"""
src/scanner/regex_scanner.py
────────────────────────────
Regex-based static scanner for cryptographic API usage in Python, Java and C
source files.

PS-P2 (Crypto Inventory & Migration Planner) – Qiskit Fall Fest 2026
Detection method: Layer 1 / regex (baseline).  AST detection (Layer 2) lives
in ast_scanner.py (Phase 1 P1 task).

Each Finding carries the information required by the PS-P2 deliverable spec:
  • relative file path
  • line number (1-based)
  • language
  • matched API text (the regex match)
  • inferred algorithm name
  • risk level  (HIGH / MODERATE / LOWER)
  • recommended replacement
  • evidence (full source line, stripped)
  • detection method
"""

from __future__ import annotations

import ast
import io
import json
import re
import sys
import tokenize
from bisect import bisect_right
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator, List, Optional

from .risk_classifier import RiskClassifier, RiskLevel
from .scan_result import FileScanOutcome, ScanResult


# ──────────────────────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """One detected cryptographic API usage."""

    file_path: str          # relative to the scanned root
    line_number: int        # 1-based
    language: str           # "python" | "java" | "c"
    matched_api: str        # the text captured by the regex group
    algorithm: str          # canonical algorithm name, e.g. "RSA", "AES-128"
    risk_level: str         # "HIGH" | "MODERATE" | "LOWER"
    replacement: str        # recommended PQC replacement
    evidence: str           # full source line (stripped) for human review
    detection_method: str = "regex"
    _source_column: Optional[int] = field(default=None, repr=False, compare=False)
    _source_end_column: Optional[int] = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict:
        data = asdict(self)
        data.pop("_source_column", None)
        data.pop("_source_end_column", None)
        return data


# ──────────────────────────────────────────────────────────────────────────────
# Pattern library
# ──────────────────────────────────────────────────────────────────────────────

# Each entry: (compiled_pattern, algorithm_name)
# The first capturing group must capture the matched API text.

_PYTHON_PATTERNS: list[tuple[re.Pattern, str]] = [
    # ── RSA ──────────────────────────────────────────────────────────────────
    # cryptography library
    (re.compile(r"(rsa\.generate_private_key)", re.IGNORECASE), "RSA"),
    (re.compile(r"(asymmetric\s*import\s+rsa\b)", re.IGNORECASE), "RSA"),
    (re.compile(r"(from\s+cryptography\.[^\n]*\brsa\b)", re.IGNORECASE), "RSA"),
    (re.compile(r"\b(create_rsa_key)\s*\(", re.IGNORECASE), "RSA"),
    # PyCryptodome / PyCrypto
    (re.compile(r"(from\s+Crypto\.PublicKey\s+import\s+RSA)", re.IGNORECASE), "RSA"),
    (re.compile(r"(Crypto\.PublicKey\.RSA)", re.IGNORECASE), "RSA"),
    (re.compile(r"(RSA\.generate\s*\()", re.IGNORECASE), "RSA"),
    (re.compile(r"(RSA\.import_key\s*\()", re.IGNORECASE), "RSA"),
    # Generic RSA keyword in key-generation context
    (re.compile(r'["\']RSA["\']\s*[,\)]', re.IGNORECASE), "RSA"),

    # ── ECC / ECDSA / ECDH ──────────────────────────────────────────────────
    (re.compile(r"(ec\.generate_private_key)", re.IGNORECASE), "ECC"),
    (re.compile(r"(ECC\s*\.\s*generate)", re.IGNORECASE), "ECC"),
    (re.compile(r"(ECDSA\b)", re.IGNORECASE), "ECDSA"),
    (re.compile(r"(ECDH\b)", re.IGNORECASE), "ECDH"),
    (re.compile(r'["\']EC["\']\s*[,\)]', re.IGNORECASE), "ECC"),

    # ── AES-128 ──────────────────────────────────────────────────────────────
    # Key length 128 bits = 16 bytes
    (re.compile(r"(AES[_\-]128\b)", re.IGNORECASE), "AES-128"),
    (re.compile(r"get_random_bytes\s*\(\s*16\s*\)", re.IGNORECASE), "AES-128"),
    (re.compile(r"(AES\s*\.\s*new)\s*\(", re.IGNORECASE), "AES-UNKNOWN"),

    # ── AES-256 ──────────────────────────────────────────────────────────────
    (re.compile(r"(AES[_\-]256\b)", re.IGNORECASE), "AES-256"),
    (re.compile(r"get_random_bytes\s*\(\s*32\s*\)", re.IGNORECASE), "AES-256"),

    # ── SHA-256 ──────────────────────────────────────────────────────────────
    (re.compile(r"(hashlib\.sha256\s*\()"), "SHA-256"),
    (re.compile(
        r"(hashlib\s*\.\s*new\s*\(\s*['\"]sha256['\"])",
        re.IGNORECASE,
    ), "SHA-256"),
    (re.compile(r"(SHA256\b)"), "SHA-256"),
    (re.compile(r"(from\s+Crypto\.Hash\s+import\s+SHA256)"), "SHA-256"),
    (re.compile(r"(SHA[_\-]256\b)", re.IGNORECASE), "SHA-256"),
]

_JAVA_PATTERNS: list[tuple[re.Pattern, str]] = [
    # ── RSA ──────────────────────────────────────────────────────────────────
    (re.compile(r'KeyPairGenerator\.getInstance\s*\(\s*"(RSA)"', re.IGNORECASE), "RSA"),
    (re.compile(r'KeyFactory\.getInstance\s*\(\s*"(RSA)"', re.IGNORECASE), "RSA"),
    (re.compile(r'Cipher\.getInstance\s*\(\s*"(RSA)[/"]', re.IGNORECASE), "RSA"),
    (re.compile(r'(RSAPublicKeySpec|RSAPrivateKeySpec|RSAKeyGenParameterSpec)'), "RSA"),

    # ── ECC / ECDSA / ECDH ──────────────────────────────────────────────────
    (re.compile(r'KeyPairGenerator\.getInstance\s*\(\s*"(EC)"', re.IGNORECASE), "ECC"),
    (re.compile(r'KeyFactory\.getInstance\s*\(\s*"(EC)"', re.IGNORECASE), "ECC"),
    (re.compile(r'Signature\.getInstance\s*\(\s*"(SHA[0-9]+with(?:ECDSA|EC))"', re.IGNORECASE), "ECDSA"),
    (re.compile(r'Signature\.getInstance\s*\(\s*"(SHA[0-9]+withRSA|RSASSA-PSS)"', re.IGNORECASE), "RSA"),
    (re.compile(r'KeyAgreement\.getInstance\s*\(\s*"(ECDH)"', re.IGNORECASE), "ECDH"),
    (re.compile(r'\bnew\s+(ECGenParameterSpec|ECPublicKeySpec|ECPrivateKeySpec)\s*\('), "ECC"),

    # ── AES-128 ──────────────────────────────────────────────────────────────
    (re.compile(r'(AES[_/\-]128)', re.IGNORECASE), "AES-128"),
    (re.compile(r'keyGenerator\.init\s*\(\s*(128)\s*\)', re.IGNORECASE), "AES-128"),

    # ── AES-256 ──────────────────────────────────────────────────────────────
    (re.compile(r'(AES[_/\-]256)', re.IGNORECASE), "AES-256"),
    (re.compile(r'keyGenerator\.init\s*\(\s*(256)\s*\)', re.IGNORECASE), "AES-256"),
    (re.compile(r'keyGenerator\.init\s*\(\s*(192)\s*\)', re.IGNORECASE), "AES-192"),

    # ── AES generic ──────────────────────────────────────────────────────────
    (re.compile(r'Cipher\.getInstance\s*\(\s*"(AES)', re.IGNORECASE), "AES-UNKNOWN"),
    (re.compile(r'KeyGenerator\.getInstance\s*\(\s*"(AES)"', re.IGNORECASE), "AES-UNKNOWN"),

    # ── SHA-256 ──────────────────────────────────────────────────────────────
    (re.compile(r'MessageDigest\.getInstance\s*\(\s*"(SHA-256)"', re.IGNORECASE), "SHA-256"),
    (re.compile(r'(SHA[_\-]256)', re.IGNORECASE), "SHA-256"),
]

_C_PATTERNS: list[tuple[re.Pattern, str]] = [
    # ── RSA (OpenSSL / generic) ──────────────────────────────────────────────
    (re.compile(r"\b(RSA_generate_key(?:_ex)?)\s*\("), "RSA"),
    (re.compile(r"\b(RSA_new)\s*\("), "RSA"),
    (re.compile(r"\b(EVP_PKEY_RSA)\b"), "RSA"),
    (re.compile(r"\b(PEM_write(?:_bio)?_RSAPrivateKey|PEM_write(?:_bio)?_RSAPublicKey)\b"), "RSA"),
    (re.compile(r"\b(d2i_RSAPrivateKey|d2i_RSAPublicKey)\b"), "RSA"),

    # ── ECC / ECDSA ──────────────────────────────────────────────────────────
    (re.compile(r"\b(EC_KEY_new(?:_by_curve_name)?)\s*\("), "ECC"),
    (re.compile(r"\b(EVP_PKEY_EC)\b"), "ECC"),
    (re.compile(r"\b(ECDSA_sign|ECDSA_verify|ECDSA_SIG_new)\b"), "ECDSA"),
    (re.compile(r"\b(ECDH_compute_key)\b"), "ECDH"),
    (re.compile(r"\b(EC_GROUP_new_by_curve_name)\b"), "ECC"),
    (re.compile(r"\b(RSA_sign|RSA_verify|RSA_private_encrypt|RSA_public_decrypt)\b"), "RSA"),
    (re.compile(r"\b(RSA_public_encrypt|RSA_private_decrypt)\b"), "RSA"),

    # ── AES-128 ──────────────────────────────────────────────────────────────
    (re.compile(r"\b(EVP_aes_128_(?:cbc|ecb|gcm|ctr|cfb|ofb))\b", re.IGNORECASE), "AES-128"),
    (re.compile(r"\b(AES_128)\b", re.IGNORECASE), "AES-128"),
    (re.compile(r"\b(AES_set_encrypt_key|AES_set_decrypt_key)\s*\([^,]+,\s*128\s*,"), "AES-128"),

    # ── AES-256 ──────────────────────────────────────────────────────────────
    (re.compile(r"\b(EVP_aes_256_(?:cbc|ecb|gcm|ctr|cfb|ofb))\b", re.IGNORECASE), "AES-256"),
    (re.compile(r"\b(AES_256)\b", re.IGNORECASE), "AES-256"),
    (re.compile(r"\b(AES_set_encrypt_key|AES_set_decrypt_key)\s*\([^,]+,\s*256\s*,"), "AES-256"),

    # ── AES-192 ──────────────────────────────────────────────────────────────
    (re.compile(r"\b(EVP_aes_192_(?:cbc|ecb|gcm|ctr|cfb|ofb))\b", re.IGNORECASE), "AES-192"),
    (re.compile(r"\b(AES_192)\b", re.IGNORECASE), "AES-192"),
    (re.compile(r"\b(AES_set_encrypt_key|AES_set_decrypt_key)\s*\([^,]+,\s*192\s*,"), "AES-192"),

    # ── AES generic ──────────────────────────────────────────────────────────
    (re.compile(r"\b(AES_encrypt|AES_decrypt)\b"), "AES-UNKNOWN"),

    # ── SHA-256 ──────────────────────────────────────────────────────────────
    (re.compile(r"\b(SHA256(?:_Init|_Update|_Final)?)\b"), "SHA-256"),
    (re.compile(r"\b(EVP_sha256)\b"), "SHA-256"),
    (re.compile(r"\b(SHA256_DIGEST_LENGTH)\b"), "SHA-256"),
]

# Language → (extension set, pattern list)
_LANGUAGE_CONFIG: dict[str, tuple[frozenset[str], list[tuple[re.Pattern, str]]]] = {
    "python": (frozenset({".py", ".pyw"}), _PYTHON_PATTERNS),
    "java":   (frozenset({".java"}),        _JAVA_PATTERNS),
    "c":      (frozenset({".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"}), _C_PATTERNS),
}


def _mask_python_comments_and_strings(source: str) -> str:
    """Mask comments and non-API strings without changing source positions."""
    masked, _, _ = _mask_python_comments_and_strings_with_status(source)
    return masked


def _mask_python_comments_and_strings_with_status(
    source: str,
) -> tuple[str, str, dict[int, int]]:
    """Mask source and report parse/tokenization limitations to the scanner."""
    lines = source.splitlines(keepends=True)
    line_starts: list[int] = []
    offset = 0
    for line in lines:
        line_starts.append(offset)
        offset += len(line)

    masked = list(source)
    preserved_ranges: list[tuple[int, int]] = []
    aes_key_sizes: dict[int, int] = {}
    errors: list[str] = []

    def ast_position_offset(position: tuple[int, int]) -> int:
        row, byte_column = position
        if row < 1 or row > len(line_starts):
            return len(source)
        line = lines[row - 1]
        character_column = len(
            line.encode("utf-8")[:byte_column].decode("utf-8")
        )
        return line_starts[row - 1] + character_column

    def position_offset(position: tuple[int, int]) -> int:
        row, column = position
        if row < 1 or row > len(line_starts):
            return len(source)
        return line_starts[row - 1] + column

    def mask_range(start: int, end: int) -> None:
        for index in range(start, min(end, len(masked))):
            if masked[index] not in "\r\n":
                masked[index] = " "

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        tree = None
        errors.append(f"SyntaxError at line {exc.lineno}: {exc.msg}")

    if tree is not None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            receiver = node.func.value
            if not isinstance(receiver, ast.Name) or not node.args:
                continue

            argument = node.args[0]
            if not isinstance(argument, ast.Constant):
                continue

            if (
                receiver.id == "hashlib"
                and node.func.attr == "new"
                and isinstance(argument.value, str)
                and argument.value.lower() == "sha256"
            ):
                preserved_ranges.append((
                    ast_position_offset((argument.lineno, argument.col_offset)),
                    ast_position_offset((argument.end_lineno, argument.end_col_offset)),
                ))
            elif (
                receiver.id == "AES"
                and node.func.attr == "new"
                and isinstance(argument.value, bytes)
            ):
                key_size = len(argument.value)
                if key_size in (16, 24, 32):
                    preserved_ranges.append((
                        ast_position_offset((argument.lineno, argument.col_offset)),
                        ast_position_offset((argument.end_lineno, argument.end_col_offset)),
                    ))
                    aes_key_sizes[ast_position_offset((
                        node.func.lineno,
                        node.func.col_offset,
                    ))] = key_size

    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    while True:
        try:
            token = next(tokens)
        except StopIteration:
            break
        except (IndentationError, tokenize.TokenError) as exc:
            if isinstance(exc, tokenize.TokenError):
                position = exc.args[1]
                errors.append(f"Tokenization error: {exc.args[0]}")
            else:
                position = (exc.lineno or 1, max((exc.offset or 1) - 1, 0))
                errors.append(f"Tokenization error: {exc.msg}")
            mask_range(position_offset(position), len(source))
            break

        if token.type == tokenize.COMMENT:
            mask_range(position_offset(token.start), position_offset(token.end))
        elif token.type == tokenize.STRING:
            token_start = position_offset(token.start)
            token_end = position_offset(token.end)
            if not any(
                start <= token_start and token_end <= end
                for start, end in preserved_ranges
            ):
                mask_range(position_offset(token.start), position_offset(token.end))

    return "".join(masked), "; ".join(errors), aes_key_sizes


def _mask_c_like_comments(source: str) -> str:
    """Mask C/Java comments while preserving quoted literals and positions."""
    masked = list(source)
    length = len(source)

    def mask_range(start: int, end: int) -> None:
        for index in range(start, end):
            if masked[index] not in "\r\n":
                masked[index] = " "

    index = 0
    while index < length:
        if source.startswith("//", index):
            end = index + 2
            while end < length:
                if source[end] == "\n":
                    if end > index and source[end - 1] == "\\":
                        end += 1
                        continue
                    break
                if source[end] == "\r":
                    if end > index and source[end - 1] == "\\":
                        end += 1
                        if end < length and source[end] == "\n":
                            end += 1
                        continue
                    break
                end += 1
            mask_range(index, end)
            index = end
            continue

        if source.startswith("/*", index):
            close = source.find("*/", index + 2)
            end = length if close < 0 else close + 2
            mask_range(index, end)
            index = end
            continue

        if source.startswith('R"', index):
            delimiter_end = source.find("(", index + 2, min(index + 19, length))
            if delimiter_end >= 0:
                delimiter = source[index + 2:delimiter_end]
                close = source.find(")" + delimiter + '"', delimiter_end + 1)
                index = length if close < 0 else close + len(delimiter) + 2
                continue

        if source.startswith('"""', index):
            search_from = index + 3
            while True:
                close = source.find('"""', search_from)
                if close < 0:
                    index = length
                    break
                backslashes = 0
                cursor = close - 1
                while cursor >= index and source[cursor] == "\\":
                    backslashes += 1
                    cursor -= 1
                if backslashes % 2 == 0:
                    index = close + 3
                    break
                search_from = close + 3
            continue

        if source[index] in ("'", '"'):
            quote = source[index]
            index += 1
            while index < length:
                if source[index] == "\\":
                    index += 2
                elif source[index] == quote:
                    index += 1
                    break
                else:
                    index += 1
            continue

        index += 1

    return "".join(masked)


# Directories to skip (venvs, package installs, build outputs)
_SKIP_DIRS: frozenset[str] = frozenset({
    ".venv", "venv", "env", "ENV", ".env",
    "__pycache__", ".pytest_cache", ".mypy_cache",
    "node_modules",
    "build", "dist", "target",
    ".git", ".hg", ".svn",
    "site-packages",
})


# ──────────────────────────────────────────────────────────────────────────────
# Scanner
# ──────────────────────────────────────────────────────────────────────────────

class RegexScanner:
    """
    Walk a directory tree (or scan a single file), detect cryptographic API
    calls via regex and classify each finding with the PS-P2 risk taxonomy.

    Parameters
    ----------
    root : str | Path
        The directory or file to scan.
    skip_dirs : frozenset[str] | None
        Directory names to skip.  Defaults to ``_SKIP_DIRS``.
    """

    def __init__(
        self,
        root: str | Path,
        skip_dirs: Optional[frozenset[str]] = None,
    ) -> None:
        self._root = Path(root).resolve()
        self._skip_dirs = skip_dirs if skip_dirs is not None else _SKIP_DIRS
        self._classifier = RiskClassifier()

    # ── public API ──────────────────────────────────────────────────────────

    def scan(self) -> list[Finding]:
        """Run the scan and return all findings."""
        return self.scan_with_outcomes().findings

    def scan_with_outcomes(self) -> ScanResult:
        """Run the scan and report one processing outcome per discovered file."""
        findings: list[Finding] = []
        outcomes: list[FileScanOutcome] = []
        discovered = list(self._iter_source_files())
        for path, language in discovered:
            file_findings, outcome = self._scan_file_with_outcome(path, language)
            findings.extend(file_findings)
            outcomes.append(outcome)
        discovered_paths = tuple(self._relative(path) for path, _ in discovered)
        return ScanResult(
            findings=findings,
            outcomes=outcomes,
            discovered_files=discovered_paths,
        )

    def scan_to_json(self) -> str:
        """Scan and return a JSON string of all findings."""
        findings = self.scan()
        return json.dumps(
            [f.to_dict() for f in findings],
            indent=2,
            ensure_ascii=False,
        )

    # ── internals ────────────────────────────────────────────────────────────

    def _iter_source_files(self) -> Iterator[tuple[Path, str]]:
        """Yield (absolute_path, language) for every scannable source file."""
        target = self._root

        if target.is_file():
            lang = self._detect_language(target)
            if lang:
                yield target, lang
            return

        if not target.is_dir():
            return

        for path in target.rglob("*"):
            # Skip excluded directory subtrees
            if any(part in self._skip_dirs for part in path.parts):
                continue
            if not path.is_file():
                continue
            lang = self._detect_language(path)
            if lang:
                yield path, lang

    @staticmethod
    def _detect_language(path: Path) -> Optional[str]:
        suffix = path.suffix.lower()
        for lang, (extensions, _) in _LANGUAGE_CONFIG.items():
            if suffix in extensions:
                return lang
        return None

    def _scan_file(self, path: Path, language: str) -> list[Finding]:
        """Scan a single file and return its findings."""
        findings, _ = self._scan_file_with_outcome(path, language)
        return findings

    def _scan_file_with_outcome(
        self, path: Path, language: str
    ) -> tuple[list[Finding], FileScanOutcome]:
        """Scan one file and return findings with its explicit processing result."""
        relative_path = self._relative(path)
        try:
            source = self._read_source(path)
        except OSError as exc:
            # Unreadable file: record a warning finding so the caller knows
            return (
                [Finding(
                    file_path=relative_path,
                    line_number=0,
                    language=language,
                    matched_api="<unreadable>",
                    algorithm="UNKNOWN",
                    risk_level=RiskLevel.UNKNOWN,
                    replacement="N/A",
                    evidence=f"[ERROR] Could not read file: {exc}",
                    detection_method="regex",
                )],
                FileScanOutcome(relative_path, "failed", str(exc)),
            )

        if not source.strip():
            return [], FileScanOutcome(relative_path, "scanned")

        _, patterns = _LANGUAGE_CONFIG[language]
        findings: list[Finding] = []
        seen_spans: dict[tuple[int, str], list[tuple[int, int]]] = {}

        evidence_lines = source.splitlines()
        masking_error = ""
        aes_key_sizes: dict[int, int] = {}
        if language == "python":
            scan_source, masking_error, aes_key_sizes = (
                _mask_python_comments_and_strings_with_status(source)
            )
            scan_source = re.sub(r"\\(?=\r?\n)", " ", scan_source)
            line_starts = [0]
            line_starts.extend(
                index + 1
                for index, character in enumerate(scan_source)
                if character == "\n"
            )
            matches = sorted(
                (
                    match.start(1) if match.lastindex else match.start(),
                    pattern_index,
                    match,
                    algorithm,
                )
                for pattern_index, (pattern, algorithm) in enumerate(patterns)
                for match in pattern.finditer(scan_source)
            )
            match_entries = (
                (
                    bisect_right(line_starts, match_start),
                    match_start - line_starts[bisect_right(line_starts, match_start) - 1],
                    match,
                    algorithm,
                )
                for match_start, _, match, algorithm in matches
            )
        else:
            scan_source = _mask_c_like_comments(source)
            match_entries = (
                (
                    line_no,
                    match.start(1) if match.lastindex else match.start(),
                    match,
                    algorithm,
                )
                for line_no, line in enumerate(scan_source.splitlines(), start=1)
                for pattern, algorithm in patterns
                for match in pattern.finditer(line)
            )

        for line_no, source_column, m, algorithm in match_entries:
            matched_api = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
            if language == "python" and matched_api.replace(" ", "").casefold() == "aes.new":
                key_size = aes_key_sizes.get(m.start(1) if m.lastindex else m.start())
                if key_size in (16, 24, 32):
                    algorithm = f"AES-{key_size * 8}"
            source_end_column = (
                (m.end(1) if m.lastindex and m.lastindex >= 1 else m.end())
                - (line_starts[line_no - 1] if language == "python" else 0)
            )
            key = (line_no, algorithm)
            spans = seen_spans.setdefault(key, [])
            if any(
                source_column < previous_end and previous_start < source_end_column
                for previous_start, previous_end in spans
            ):
                continue
            spans.append((source_column, source_end_column))

            evidence = evidence_lines[line_no - 1].strip()
            code_line = scan_source.splitlines()[line_no - 1]
            statement_start = code_line.rfind(";", 0, source_column) + 1
            statement_end = code_line.find(";", source_end_column)
            if statement_end < 0:
                statement_end = len(code_line)
            code_context = code_line[statement_start:statement_end].strip()
            purpose = self._infer_purpose(algorithm, matched_api, code_context)
            risk = self._classifier.classify(algorithm, purpose=purpose)
            findings.append(Finding(
                file_path=relative_path,
                line_number=line_no,
                language=language,
                matched_api=matched_api,
                algorithm=algorithm,
                risk_level=risk.level,
                replacement=risk.replacement,
                evidence=evidence,
                detection_method="regex",
                _source_column=source_column,
                _source_end_column=source_end_column,
            ))

        if masking_error:
            return findings, FileScanOutcome(relative_path, "failed", masking_error)
        return findings, FileScanOutcome(relative_path, "scanned")

    @staticmethod
    def _infer_purpose(algorithm: str, matched_api: str, evidence: str) -> Optional[str]:
        if algorithm != "RSA":
            return None
        context = f"{matched_api} {evidence}".casefold()
        if any(token in context for token in (
            "withrsa", "rsassa-pss", "rsa_sign", "rsa_verify",
            "rsa_private_encrypt", "rsa_public_decrypt",
        )):
            return "signature"
        if any(token in context for token in (
            "cipher.getinstance", "rsa_public_encrypt", "rsa_private_decrypt",
            "pkcs1_oaep", "oaep",
        )):
            return "encryption"
        return None

    @staticmethod
    def _read_source(path: Path) -> str:
        return path.read_text(encoding="utf-8", errors="replace")

    def _relative(self, path: Path) -> str:
        """Return path relative to root (or absolute if outside root)."""
        try:
            return str(path.relative_to(self._root))
        except ValueError:
            return str(path)


# ──────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────────────────────────────────────

def _build_cli() -> None:
    """Minimal CLI (no click dependency required for basic use)."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="quantumshield-scan",
        description=(
            "QuantumShield PS-P2 – static crypto inventory scanner.\n"
            "Detects RSA/EC/AES/SHA usage and rates quantum risk."
        ),
    )
    parser.add_argument(
        "path",
        help="Directory or file to scan.",
    )
    parser.add_argument(
        "--output", "-o",
        default="-",
        help="Output file path (default: stdout).",
    )
    parser.add_argument(
        "--pretty", action="store_true",
        help="Print a human-readable table instead of JSON.",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output JSON format (default).",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "report", "markdown", "table"],
        default="json",
        help="Report format: json (list of findings, default), report (full inventory report JSON), markdown, or table.",
    )
    parser.add_argument(
        "--ast", action="store_true", default=False,
        help="Enable Python AST enrichment to reduce false positives.",
    )
    args = parser.parse_args()

    if args.ast:
        from .unified_scanner import UnifiedScanner
        scanner = UnifiedScanner(root=args.path, use_ast_for_python=True)
        scan_result = scanner.scan_with_outcomes()
    else:
        scanner = RegexScanner(root=args.path)
        scan_result = scanner.scan_with_outcomes()
    findings = scan_result.findings

    if args.pretty or args.format == "table":
        _print_table(findings)
        return

    if args.format == "markdown":
        from ..reporting.inventory_report import InventoryReportGenerator
        file_counts = scan_result.file_counts()
        gen = InventoryReportGenerator(
            findings,
            scanned_root=args.path,
            total_files_scanned=file_counts["files_scanned"],
            files_discovered=file_counts["files_discovered"],
            files_failed=file_counts["files_failed"],
            files_skipped=file_counts["files_skipped"],
        )
        output_text = gen.generate_markdown()
    elif args.format == "report":
        from ..reporting.inventory_report import InventoryReportGenerator
        file_counts = scan_result.file_counts()
        gen = InventoryReportGenerator(
            findings,
            scanned_root=args.path,
            total_files_scanned=file_counts["files_scanned"],
            files_discovered=file_counts["files_discovered"],
            files_failed=file_counts["files_failed"],
            files_skipped=file_counts["files_skipped"],
        )
        output_text = gen.generate_json()
    else:
        # Default raw JSON findings list
        output_text = json.dumps(
            [f.to_dict() for f in findings],
            indent=2,
            ensure_ascii=False,
        )



    if args.output == "-":
        # Write as UTF-8 bytes to avoid cp1252 errors on Windows terminals.
        sys.stdout.buffer.write((output_text + "\n").encode("utf-8"))
        sys.stdout.buffer.flush()
    else:
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"Results written to {args.output}", file=sys.stderr)



def _print_table(findings: list[Finding]) -> None:
    """Print a readable summary table to stdout."""
    if not findings:
        out = "No cryptographic API usage detected.\n"
        sys.stdout.buffer.write(out.encode("utf-8", errors="replace"))
        sys.stdout.buffer.flush()
        return

    # Risk order for sorting
    order = {RiskLevel.HIGH: 0, RiskLevel.MODERATE: 1, RiskLevel.LOWER: 2, RiskLevel.UNKNOWN: 3}
    findings = sorted(findings, key=lambda f: (order.get(f.risk_level, 9), f.file_path, f.line_number))

    risk_icon = {RiskLevel.HIGH: "[HIGH]", RiskLevel.MODERATE: "[MOD ]", RiskLevel.LOWER: "[LOW ]", RiskLevel.UNKNOWN: "[UNK ]"}

    lines: list[str] = []
    lines.append("")
    lines.append("-" * 90)
    lines.append(f"{'FILE':<35} {'LINE':>5}  {'LANG':<6}  {'ALGORITHM':<10}  {'RISK':<8}  REPLACEMENT")
    lines.append("-" * 90)
    for f in findings:
        icon = risk_icon.get(f.risk_level, "[UNK ]")
        lines.append(
            f"{f.file_path:<35} {f.line_number:>5}  {f.language:<6}  "
            f"{f.algorithm:<10}  {icon:<8}  {f.replacement}"
        )
    lines.append("-" * 90)
    lines.append(f"Total findings: {len(findings)}")

    by_risk: dict[str, int] = {}
    for f in findings:
        by_risk[f.risk_level] = by_risk.get(f.risk_level, 0) + 1
    for level, count in sorted(by_risk.items(), key=lambda x: order.get(x[0], 9)):
        icon = risk_icon.get(level, "[UNK ]")
        lines.append(f"  {icon} {level}: {count}")
    lines.append("")

    output = "\n".join(lines)
    sys.stdout.buffer.write((output + "\n").encode("utf-8", errors="replace"))
    sys.stdout.buffer.flush()


def main() -> None:  # named entry-point for setup.py / pyproject.toml
    _build_cli()


if __name__ == "__main__":
    main()
