"""
src/scanner/ast_scanner.py
──────────────────────────
Python AST (Abstract Syntax Tree) cryptographic API analyzer.

Part of QuantumShield PS-P2 (Qiskit Fall Fest 2026).
Enriches static detection for Python files:
  • Parses Python code into AST to inspect function calls, imports, and arguments.
  • Filters out comments, docstrings, and irrelevant string literals.
  • Statically extracts visible parameters (e.g., key_size=2048, key_size=1024,
    curve types, backend options).
  • Distinguishes confirmed observations from inferred or unknown values.
  • Handles syntax errors cleanly (with fallback or syntax error finding).
  • Accurately records source line numbers and code evidence.
"""

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .regex_scanner import Finding
from .risk_classifier import RiskClassifier, RiskLevel
from .scan_result import FileScanOutcome


# Competition-rule switch: enable only if rules require conservative AES-128
# reporting when the key size cannot be determined.
CONSERVATIVE_AES_DEFAULT = False


@dataclass
class AstFinding(Finding):
    """
    Finding produced by AST analysis with enhanced parameter awareness.
    Inherits from Finding for 100% backward compatibility with P0 consumers.
    """
    detection_method: str = "ast"
    parameters: dict[str, Any] = field(default_factory=dict)
    confidence: str = "CONFIRMED"  # "CONFIRMED" | "INFERRED" | "UNKNOWN"
    key_size: Optional[int] = None
    curve: Optional[str] = None
    assumed_default: bool = False
    details: str = ""

    def to_dict(self) -> dict:
        d = super().to_dict()
        d["parameters"] = self.parameters
        d["confidence"] = self.confidence
        d["key_size"] = self.key_size
        d["curve"] = self.curve
        d["assumed_default"] = self.assumed_default
        d["details"] = self.details
        return d


class PythonAstScanner:
    """
    Parses Python source code and inspects the AST for cryptographic API calls.
    """

    def __init__(self, classifier: Optional[RiskClassifier] = None) -> None:
        self._classifier = classifier or RiskClassifier()

    def scan_source(self, code: str, file_path: str = "<memory>") -> list[AstFinding]:
        """
        Scan Python source code string and return list of AstFindings.
        Handles syntax errors gracefully without raising exceptions.
        """
        lines = code.splitlines()

        try:
            tree = ast.parse(code, filename=file_path)
        except SyntaxError as exc:
            # Report a syntax error finding or return empty
            return [
                AstFinding(
                    file_path=file_path,
                    line_number=exc.lineno or 1,
                    language="python",
                    matched_api="<SyntaxError>",
                    algorithm="UNKNOWN",
                    risk_level=RiskLevel.UNKNOWN,
                    replacement="Fix syntax error to enable AST scanning",
                    evidence=exc.text.strip() if exc.text else f"Syntax error: {exc.msg}",
                    detection_method="ast_error",
                    confidence="UNKNOWN",
                    details=f"SyntaxError: {exc.msg}",
                )
            ]

        visitor = _CryptoAstVisitor(lines, file_path, self._classifier)
        visitor.visit(tree)
        return visitor.findings

    def scan_file(self, path: str | Path, relative_to: Optional[str | Path] = None) -> list[AstFinding]:
        """Scan a Python file on disk."""
        findings, _ = self.scan_file_with_outcome(path, relative_to=relative_to)
        return findings

    def scan_file_with_outcome(
        self, path: str | Path, relative_to: Optional[str | Path] = None
    ) -> tuple[list[AstFinding], FileScanOutcome]:
        """Scan a Python file and return its processing outcome separately."""
        p = Path(path).resolve()
        rel_path = str(p.relative_to(Path(relative_to).resolve())) if relative_to else p.name

        try:
            code = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return [
                AstFinding(
                    file_path=rel_path,
                    line_number=1,
                    language="python",
                    matched_api="<ReadError>",
                    algorithm="UNKNOWN",
                    risk_level=RiskLevel.UNKNOWN,
                    replacement="Unreadable file",
                    evidence=str(exc),
                    detection_method="ast_error",
                    confidence="UNKNOWN",
                    details=f"Read error: {exc}",
                )
            ], FileScanOutcome(rel_path, "failed", str(exc))

        findings = self.scan_source(code, file_path=rel_path)
        syntax_errors = [finding for finding in findings if finding.detection_method == "ast_error"]
        if syntax_errors:
            return findings, FileScanOutcome(rel_path, "failed", syntax_errors[0].details)
        return findings, FileScanOutcome(rel_path, "scanned")


class _CryptoAstVisitor(ast.NodeVisitor):
    """
    AST visitor that tracks module imports, aliases, and function calls.
    """

    def __init__(self, source_lines: list[str], file_path: str, classifier: RiskClassifier) -> None:
        self.source_lines = source_lines
        self.file_path = file_path
        self.classifier = classifier
        self.findings: list[AstFinding] = []

        # Track imports: local_alias -> full_qualified_name
        # e.g., "from cryptography.hazmat.primitives.asymmetric import rsa as my_rsa" -> "my_rsa": "rsa"
        self.aliases: dict[str, str] = {}
        self._key_byte_lengths: dict[str, tuple[tuple[int, int], int]] = {}

    def _visit_scoped_node(self, node: ast.AST) -> None:
        outer_key_lengths = self._key_byte_lengths
        self._key_byte_lengths = {}
        self._key_byte_lengths = self._collect_local_key_lengths(node)
        try:
            self.generic_visit(node)
        finally:
            self._key_byte_lengths = outer_key_lengths

    def _collect_local_key_lengths(
        self, node: ast.AST
    ) -> dict[str, tuple[tuple[int, int], int]]:
        assignment_counts: dict[str, int] = {}
        declared_outer_names: set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(
                child.ctx, (ast.Store, ast.Del)
            ):
                assignment_counts[child.id] = assignment_counts.get(child.id, 0) + 1
            elif isinstance(child, (ast.Global, ast.Nonlocal)):
                declared_outer_names.update(child.names)

        known_lengths: dict[str, tuple[tuple[int, int], int]] = {}
        for statement in getattr(node, "body", []):
            if isinstance(statement, ast.Assign):
                targets = statement.targets
                value = statement.value
            elif isinstance(statement, ast.AnnAssign):
                targets = [statement.target]
                value = statement.value
            else:
                continue

            key_bits, confidence = self._deduce_byte_key_length(value)
            if key_bits not in (128, 192, 256) or confidence != "CONFIRMED":
                continue
            assignment_position = (
                getattr(statement, "end_lineno", statement.lineno),
                getattr(statement, "end_col_offset", statement.col_offset),
            )
            for target in targets:
                if (
                    isinstance(target, ast.Name)
                    and assignment_counts.get(target.id) == 1
                    and target.id not in declared_outer_names
                ):
                    known_lengths[target.id] = (assignment_position, key_bits)
        return known_lengths

    def visit_Module(self, node: ast.Module) -> None:
        self._visit_scoped_node(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_scoped_node(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_scoped_node(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._visit_scoped_node(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        outer_key_lengths = self._key_byte_lengths
        self._key_byte_lengths = {}
        try:
            self.generic_visit(node)
        finally:
            self._key_byte_lengths = outer_key_lengths

    def _get_evidence(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            target_name = alias.asname or alias.name
            self.aliases[target_name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            full_name = f"{module}.{alias.name}" if module else alias.name
            target_name = alias.asname or alias.name
            self.aliases[target_name] = full_name
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Check function call
        findings_before = len(self.findings)
        self._analyze_call(node)
        if len(self.findings) > findings_before:
            function_line = getattr(node.func, "lineno", getattr(node, "lineno", 1))
            source_line = self.source_lines[function_line - 1]
            byte_column = getattr(node.func, "col_offset", node.col_offset)
            char_column = len(
                source_line.encode("utf-8")[:byte_column].decode("utf-8")
            )
            end_line = getattr(node.func, "end_lineno", function_line)
            end_column = None
            if end_line == function_line:
                end_source_line = self.source_lines[function_line - 1]
                end_byte_column = getattr(node.func, "end_col_offset", None)
                if end_byte_column is not None:
                    end_column = len(
                        end_source_line.encode("utf-8")[:end_byte_column].decode("utf-8")
                    )
            for finding in self.findings[findings_before:]:
                finding._source_column = char_column
                finding._source_end_column = end_column
        self.generic_visit(node)

    def _resolve_callable_name(self, func_node: ast.AST) -> tuple[str, str]:
        """
        Resolves callable name and its base object.
        Returns (base_name, attribute_name) or ("", full_string).
        """
        if isinstance(func_node, ast.Name):
            name = func_node.id
            resolved = self.aliases.get(name, name)
            return (resolved, "")
        elif isinstance(func_node, ast.Attribute):
            attr = func_node.attr
            if isinstance(func_node.value, ast.Name):
                base = func_node.value.id
                resolved_base = self.aliases.get(base, base)
                return (resolved_base, attr)
            elif isinstance(func_node.value, ast.Attribute):
                sub_base, sub_attr = self._resolve_callable_name(func_node.value)
                return (f"{sub_base}.{sub_attr}", attr)
        return ("", "")

    def _extract_constant_val(self, node: Optional[ast.AST]) -> Any:
        if node is None:
            return None
        if isinstance(node, ast.Constant):
            return node.value
        # For Python versions where Num/Str/Bytes were used, Constant handles 3.8+
        return None

    def _analyze_call(self, node: ast.Call) -> None:
        base, attr = self._resolve_callable_name(node.func)
        full_call = f"{base}.{attr}" if attr else base
        lineno = getattr(node, "lineno", 1)
        evidence = self._get_evidence(lineno)

        # ── 1. RSA detection ────────────────────────────────────────────────
        # cryptography: rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=...)
        if (
            (attr == "generate_private_key" and ("rsa" in base.lower() or base.endswith(".rsa")))
            or full_call.endswith("rsa.generate_private_key")
        ):
            key_size, confidence = self._extract_rsa_key_size(node)
            profile = self.classifier.get_profile("RSA")
            details = f"RSA private key generation with key size {key_size if key_size else 'UNKNOWN'} bits"
            self.findings.append(
                AstFinding(
                    file_path=self.file_path,
                    line_number=lineno,
                    language="python",
                    matched_api="rsa.generate_private_key",
                    algorithm="RSA",
                    risk_level=profile.level,
                    replacement=profile.replacement,
                    evidence=evidence,
                    detection_method="ast",
                    confidence=confidence,
                    key_size=key_size,
                    parameters={"key_size": key_size, "public_exponent": self._extract_constant_val(self._extract_kwarg_or_arg(node, "public_exponent", 0))},
                    details=details,
                )
            )
            return


        # PyCryptodome: RSA.generate(bits, ...)
        if (
            (attr == "generate" and ("RSA" in base or base.endswith(".RSA")))
            or full_call.endswith("RSA.generate")
        ):
            key_size, confidence = self._extract_pycrypto_rsa_size(node)
            profile = self.classifier.get_profile("RSA")
            details = f"PyCryptodome RSA.generate with key size {key_size if key_size else 'UNKNOWN'} bits"
            self.findings.append(
                AstFinding(
                    file_path=self.file_path,
                    line_number=lineno,
                    language="python",
                    matched_api="RSA.generate",
                    algorithm="RSA",
                    risk_level=profile.level,
                    replacement=profile.replacement,
                    evidence=evidence,
                    detection_method="ast",
                    confidence=confidence,
                    key_size=key_size,
                    parameters={"bits": key_size},
                    details=details,
                )
            )
            return

        # PyCryptodome: PKCS1_OAEP (RSA encryption / key encapsulation)
        if (
            (attr == "new" and ("PKCS1_OAEP" in base or base.endswith(".PKCS1_OAEP")))
            or full_call.endswith("PKCS1_OAEP.new")
        ):
            profile = self.classifier.get_profile("RSA", purpose="encapsulation")
            self.findings.append(
                AstFinding(
                    file_path=self.file_path,
                    line_number=lineno,
                    language="python",
                    matched_api="PKCS1_OAEP.new",
                    algorithm="RSA",
                    risk_level=profile.level,
                    replacement=profile.replacement,
                    evidence=evidence,
                    detection_method="ast",
                    confidence="CONFIRMED",
                    details="RSA-OAEP asymmetric encryption / key establishment",
                )
            )
            return

        # PyCryptodome: pkcs1_15 (RSA signatures)
        if (
            (attr == "new" and ("pkcs1_15" in base or base.endswith(".pkcs1_15")))
            or full_call.endswith("pkcs1_15.new")
        ):
            profile = self.classifier.get_profile("RSA", purpose="signature")
            self.findings.append(
                AstFinding(
                    file_path=self.file_path,
                    line_number=lineno,
                    language="python",
                    matched_api="pkcs1_15.new",
                    algorithm="RSA",
                    risk_level=profile.level,
                    replacement=profile.replacement,
                    evidence=evidence,
                    detection_method="ast",
                    confidence="CONFIRMED",
                    details="RSA PKCS#1 v1.5 digital signature scheme",
                )
            )
            return

        # PyCryptodome: RSA.import_key(pem_data)
        if (
            (attr == "import_key" and ("RSA" in base or base.endswith(".RSA")))
            or full_call.endswith("RSA.import_key")
        ):
            profile = self.classifier.get_profile("RSA")
            self.findings.append(
                AstFinding(
                    file_path=self.file_path,
                    line_number=lineno,
                    language="python",
                    matched_api="RSA.import_key",
                    algorithm="RSA",
                    risk_level=profile.level,
                    replacement=profile.replacement,
                    evidence=evidence,
                    detection_method="ast",
                    confidence="CONFIRMED",
                    key_size=None,
                    parameters={},
                    details="PyCryptodome RSA.import_key invocation (imported key size determined at runtime)",
                )
            )
            return


        # ── 2. ECC / ECDSA / ECDH ───────────────────────────────────────────
        # Key generation alone does not establish whether an EC key is used for
        # signing or key agreement.
        if (
            (
                attr == "generate_private_key"
                and (
                    base.casefold() == "ec"
                    or base.casefold().endswith(".ec")
                )
            )
            or full_call.casefold() == "ec.generate_private_key"
            or full_call.casefold().endswith(".ec.generate_private_key")
        ):
            curve, confidence = self._extract_ec_curve(node)
            profile = self.classifier.get_profile("ECC")
            details = f"EC key pair generation with curve {curve or 'UNKNOWN'}"
            self.findings.append(
                AstFinding(
                    file_path=self.file_path,
                    line_number=lineno,
                    language="python",
                    matched_api="ec.generate_private_key",
                    algorithm="ECC",
                    risk_level=profile.level,
                    replacement=profile.replacement,
                    evidence=evidence,
                    detection_method="ast",
                    confidence=confidence,
                    curve=curve,
                    parameters={"curve": curve},
                    details=details,
                )
            )
            return

        # cryptography: ec.ECDSA(algorithm)
        if attr == "ECDSA" or full_call.endswith(".ECDSA") or full_call == "ECDSA":
            profile = self.classifier.get_profile("ECDSA")
            self.findings.append(
                AstFinding(
                    file_path=self.file_path,
                    line_number=lineno,
                    language="python",
                    matched_api="ec.ECDSA",
                    algorithm="ECDSA",
                    risk_level=profile.level,
                    replacement=profile.replacement,
                    evidence=evidence,
                    detection_method="ast",
                    confidence="CONFIRMED",
                    details="Elliptic Curve Digital Signature Algorithm (ECDSA) primitive invocation",
                )
            )
            return

        # cryptography: ec.ECDH()
        if attr == "ECDH" or full_call.endswith(".ECDH") or full_call == "ECDH":
            profile = self.classifier.get_profile("ECDH")
            self.findings.append(
                AstFinding(
                    file_path=self.file_path,
                    line_number=lineno,
                    language="python",
                    matched_api="ec.ECDH",
                    algorithm="ECDH",
                    risk_level=profile.level,
                    replacement=profile.replacement,
                    evidence=evidence,
                    detection_method="ast",
                    confidence="CONFIRMED",
                    details="Elliptic Curve Diffie-Hellman (ECDH) key exchange invocation",
                )
            )
            return

        # PyCryptodome: ECC.generate(curve=...)
        if (
            (
                attr == "generate"
                and (
                    base.casefold() == "ecc"
                    or base.casefold().endswith(".ecc")
                )
            )
            or full_call.casefold() == "ecc.generate"
            or full_call.casefold().endswith(".ecc.generate")
        ):
            curve, confidence = self._extract_ecc_curve_pycryptodome(node)
            profile = self.classifier.get_profile("ECC")
            self.findings.append(
                AstFinding(
                    file_path=self.file_path,
                    line_number=lineno,
                    language="python",
                    matched_api="ECC.generate",
                    algorithm="ECC",
                    risk_level=profile.level,
                    replacement=profile.replacement,
                    evidence=evidence,
                    detection_method="ast",
                    confidence=confidence,
                    curve=curve,
                    parameters={"curve": curve},
                    details=f"PyCryptodome ECC.generate with curve {curve or 'UNKNOWN'}",
                )
            )
            return

        # ── 3. AES detection ────────────────────────────────────────────────
        # PyCryptodome: AES.new(key, mode, ...)
        if (attr == "new" and ("AES" in base or base.endswith(".AES"))) or full_call.endswith("AES.new"):
            key_size, confidence = self._extract_aes_key_size_from_new(node)
            assumed_default = False
            if key_size in (128, 192, 256):
                algo = f"AES-{key_size}"
            elif CONSERVATIVE_AES_DEFAULT:
                algo = "AES-128"
                confidence = "INFERRED"
                assumed_default = True
            else:
                algo = "AES-UNKNOWN"
                confidence = "INFERRED"

            profile = self.classifier.get_profile(algo)
            self.findings.append(
                AstFinding(
                    file_path=self.file_path,
                    line_number=lineno,
                    language="python",
                    matched_api="AES.new",
                    algorithm=algo,
                    risk_level=profile.level,
                    replacement=profile.replacement,
                    evidence=evidence,
                    detection_method="ast",
                    confidence=confidence,
                    key_size=key_size,
                    parameters={"key_bits": key_size},
                    assumed_default=assumed_default,
                    details=(
                        f"AES cipher construction with {key_size}-bit key"
                        if key_size is not None
                        else (
                            "AES cipher construction; reported as inferred AES-128 "
                            "by conservative default"
                            if assumed_default
                            else "AES cipher construction with unknown key size"
                        )
                    ),
                )
            )
            return

        # cryptography: algorithms.AES(key)
        if attr == "AES" or full_call.endswith("algorithms.AES") or full_call == "AES":
            key_size, confidence = self._extract_aes_key_size_from_cryptography(node)
            assumed_default = False
            if key_size in (128, 192, 256):
                algo = f"AES-{key_size}"
            elif CONSERVATIVE_AES_DEFAULT:
                algo = "AES-128"
                confidence = "INFERRED"
                assumed_default = True
            else:
                algo = "AES-UNKNOWN"
                confidence = "INFERRED"

            profile = self.classifier.get_profile(algo)
            self.findings.append(
                AstFinding(
                    file_path=self.file_path,
                    line_number=lineno,
                    language="python",
                    matched_api="algorithms.AES",
                    algorithm=algo,
                    risk_level=profile.level,
                    replacement=profile.replacement,
                    evidence=evidence,
                    detection_method="ast",
                    confidence=confidence,
                    key_size=key_size,
                    parameters={"key_bits": key_size},
                    assumed_default=assumed_default,
                    details=(
                        f"cryptography algorithms.AES cipher with {key_size}-bit key"
                        if key_size is not None
                        else (
                            "cryptography algorithms.AES cipher; reported as inferred "
                            "AES-128 by conservative default"
                            if assumed_default
                            else "cryptography algorithms.AES cipher with unknown key size"
                        )
                    ),
                )
            )
            return

        # ── 4. SHA-256 detection ────────────────────────────────────────────
        # hashlib.sha256() or hashlib.new('sha256')
        if (
            (attr == "sha256" and "hashlib" in base)
            or full_call.endswith("hashlib.sha256")
            or (attr == "SHA256" and ("hashes" in base or "SHA256" in base))
            or full_call.endswith("hashes.SHA256")
            or full_call.endswith("SHA256.new")
        ):
            profile = self.classifier.get_profile("SHA-256")
            self.findings.append(
                AstFinding(
                    file_path=self.file_path,
                    line_number=lineno,
                    language="python",
                    matched_api=full_call or "sha256",
                    algorithm="SHA-256",
                    risk_level=profile.level,
                    replacement=profile.replacement,
                    evidence=evidence,
                    detection_method="ast",
                    confidence="CONFIRMED",
                    parameters={"digest_bits": 256},
                    details="SHA-256 cryptographic hash function invocation",
                )
            )
            return

        # hashlib.new('sha256')
        if (attr == "new" and "hashlib" in base) or full_call.endswith("hashlib.new"):
            first_arg = self._extract_constant_val(node.args[0]) if node.args else None
            if isinstance(first_arg, str) and first_arg.lower() in ("sha256", "sha-256"):
                profile = self.classifier.get_profile("SHA-256")
                self.findings.append(
                    AstFinding(
                        file_path=self.file_path,
                        line_number=lineno,
                        language="python",
                        matched_api="hashlib.new('sha256')",
                        algorithm="SHA-256",
                        risk_level=profile.level,
                        replacement=profile.replacement,
                        evidence=evidence,
                        detection_method="ast",
                        confidence="CONFIRMED",
                        parameters={"name": first_arg},
                        details="hashlib.new with SHA-256 digest",
                    )
                )
                return

    # ── Extraction helpers ──────────────────────────────────────────────────

    def _extract_kwarg_or_arg(self, node: ast.Call, kwarg_name: str, arg_index: int) -> Optional[ast.AST]:
        for kw in node.keywords:
            if kw.arg == kwarg_name:
                return kw.value
        if len(node.args) > arg_index:
            return node.args[arg_index]
        return None

    def _extract_rsa_key_size(self, node: ast.Call) -> tuple[Optional[int], str]:
        """Extract key_size from rsa.generate_private_key(..., key_size=2048)."""
        val_node = self._extract_kwarg_or_arg(node, "key_size", 1)
        val = self._extract_constant_val(val_node)
        if isinstance(val, int):
            return val, "CONFIRMED"
        return None, "UNKNOWN"

    def _extract_pycrypto_rsa_size(self, node: ast.Call) -> tuple[Optional[int], str]:
        """Extract bits from RSA.generate(2048, ...)."""
        val_node = self._extract_kwarg_or_arg(node, "bits", 0)
        val = self._extract_constant_val(val_node)
        if isinstance(val, int):
            return val, "CONFIRMED"
        return None, "UNKNOWN"

    def _extract_ec_curve(self, node: ast.Call) -> tuple[Optional[str], str]:
        """Extract curve from ec.generate_private_key(ec.SECP256R1(), ...)."""
        curve_node = self._extract_kwarg_or_arg(node, "curve", 0)
        if curve_node is None:
            return None, "UNKNOWN"

        # e.g., ec.SECP256R1() or ec.SECP384R1()
        if isinstance(curve_node, ast.Call):
            b, a = self._resolve_callable_name(curve_node.func)
            curve_name = a or b
            return curve_name, "CONFIRMED"
        elif isinstance(curve_node, (ast.Name, ast.Attribute)):
            b, a = self._resolve_callable_name(curve_node)
            return a or b, "CONFIRMED"

        return None, "UNKNOWN"

    def _extract_ecc_curve_pycryptodome(self, node: ast.Call) -> tuple[Optional[str], str]:
        curve_node = self._extract_kwarg_or_arg(node, "curve", 0)
        val = self._extract_constant_val(curve_node)
        if isinstance(val, str):
            return val, "CONFIRMED"
        return None, "UNKNOWN"

    def _extract_aes_key_size_from_new(self, node: ast.Call) -> tuple[Optional[int], str]:
        """Inspect key length in AES.new(key, ...)."""
        key_node = self._extract_kwarg_or_arg(node, "key", 0)
        return self._deduce_byte_key_length(key_node)

    def _extract_aes_key_size_from_cryptography(self, node: ast.Call) -> tuple[Optional[int], str]:
        """Inspect key in algorithms.AES(key)."""
        key_node = self._extract_kwarg_or_arg(node, "key", 0)
        return self._deduce_byte_key_length(key_node)

    def _deduce_byte_key_length(self, node: Optional[ast.AST]) -> tuple[Optional[int], str]:
        if node is None:
            return None, "UNKNOWN"

        if isinstance(node, ast.Name):
            known_key = self._key_byte_lengths.get(node.id)
            if known_key is not None:
                assignment_position, key_bits = known_key
                use_position = (node.lineno, node.col_offset)
                if assignment_position < use_position:
                    return key_bits, "CONFIRMED"

        # Direct bytes constant: b"..."
        val = self._extract_constant_val(node)
        if isinstance(val, bytes):
            length = len(val) * 8
            if length in (128, 192, 256):
                return length, "CONFIRMED"

        # Only recognize known byte-generating APIs; arbitrary calls accepting
        # a size-like argument do not establish the returned key length.
        if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute)):
            base, attr = self._resolve_callable_name(node.func)
            callable_name = f"{base}.{attr}" if attr else base
            known_byte_generators = {
                "Crypto.Random.get_random_bytes",
                "os.urandom",
            }
            if callable_name not in known_byte_generators:
                return None, "UNKNOWN"

            arg_val = self._extract_constant_val(node.args[0]) if node.args else None
            if isinstance(arg_val, int):
                length = arg_val * 8
                if length in (128, 192, 256):
                    return length, "CONFIRMED"

        return None, "UNKNOWN"
