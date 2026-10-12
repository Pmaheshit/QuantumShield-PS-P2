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

import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator, List, Optional

from .risk_classifier import RiskClassifier, RiskLevel


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

    def to_dict(self) -> dict:
        return asdict(self)


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
    # PyCryptodome / PyCrypto
    (re.compile(r"(from\s+Crypto\.PublicKey\s+import\s+RSA)", re.IGNORECASE), "RSA"),
    (re.compile(r"(Crypto\.PublicKey\.RSA)", re.IGNORECASE), "RSA"),
    (re.compile(r"(RSA\.generate\s*\()", re.IGNORECASE), "RSA"),
    (re.compile(r"(RSA\.import_key\s*\()", re.IGNORECASE), "RSA"),
    # Generic RSA keyword in key-generation context
    (re.compile(r'["\']RSA["\']\s*[,\)]', re.IGNORECASE), "RSA"),

    # ── ECC / ECDSA / ECDH ──────────────────────────────────────────────────
    (re.compile(r"(from\s+cryptography\.[^\n]*\bec\b)", re.IGNORECASE), "ECDSA"),
    (re.compile(r"(ec\.generate_private_key)", re.IGNORECASE), "ECDSA"),
    (re.compile(r"(ECDSA\b)", re.IGNORECASE), "ECDSA"),
    (re.compile(r"(ECDH\b)", re.IGNORECASE), "ECDH"),
    (re.compile(r"(from\s+Crypto\.PublicKey\s+import\s+ECC)", re.IGNORECASE), "ECDSA"),
    (re.compile(r'["\']EC["\']\s*[,\)]', re.IGNORECASE), "ECDSA"),

    # ── AES-128 ──────────────────────────────────────────────────────────────
    # Key length 128 bits = 16 bytes
    (re.compile(r"(AES[_\-]128\b)", re.IGNORECASE), "AES-128"),
    (re.compile(r"get_random_bytes\s*\(\s*16\s*\)", re.IGNORECASE), "AES-128"),
    (re.compile(r"AES\.new\s*\([^,]+,\s*AES\.[A-Z]+,\s*(?:key\s*=\s*)?(?:b['\"][^'\"]{16}['\"]|\w{1,20})\s*\)",
                re.IGNORECASE), "AES-128"),

    # ── AES-256 ──────────────────────────────────────────────────────────────
    (re.compile(r"(AES[_\-]256\b)", re.IGNORECASE), "AES-256"),
    (re.compile(r"get_random_bytes\s*\(\s*32\s*\)", re.IGNORECASE), "AES-256"),

    # ── Generic AES (unknown key length → classify conservatively as AES-128) ─
    (re.compile(r"\bfrom\s+Crypto\.Cipher\s+import\s+(AES)\b"), "AES-128"),
    (re.compile(r"\bfrom\s+cryptography\.hazmat\.primitives\.ciphers(?:\s*import\s*|\s+algorithms\s+import\s+)(AES)\b",
                re.IGNORECASE), "AES-128"),

    # ── SHA-256 ──────────────────────────────────────────────────────────────
    (re.compile(r"(hashlib\.sha256\s*\()"), "SHA-256"),
    (re.compile(r"(hashlib\.new\s*\(\s*['\"]sha256['\"])", re.IGNORECASE), "SHA-256"),
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
    (re.compile(r'KeyPairGenerator\.getInstance\s*\(\s*"(EC)"', re.IGNORECASE), "ECDSA"),
    (re.compile(r'KeyFactory\.getInstance\s*\(\s*"(EC)"', re.IGNORECASE), "ECDSA"),
    (re.compile(r'Signature\.getInstance\s*\(\s*"(SHA[0-9]+with(?:ECDSA|EC))"', re.IGNORECASE), "ECDSA"),
    (re.compile(r'KeyAgreement\.getInstance\s*\(\s*"(ECDH)"', re.IGNORECASE), "ECDH"),
    (re.compile(r'(ECGenParameterSpec|ECPublicKeySpec|ECPrivateKeySpec)'), "ECDSA"),

    # ── AES-128 ──────────────────────────────────────────────────────────────
    (re.compile(r'(AES[_/\-]128)', re.IGNORECASE), "AES-128"),
    (re.compile(r'keyGenerator\.init\s*\(\s*(128)\s*\)', re.IGNORECASE), "AES-128"),

    # ── AES-256 ──────────────────────────────────────────────────────────────
    (re.compile(r'(AES[_/\-]256)', re.IGNORECASE), "AES-256"),
    (re.compile(r'keyGenerator\.init\s*\(\s*(256)\s*\)', re.IGNORECASE), "AES-256"),

    # ── AES generic ──────────────────────────────────────────────────────────
    (re.compile(r'Cipher\.getInstance\s*\(\s*"(AES)', re.IGNORECASE), "AES-128"),
    (re.compile(r'KeyGenerator\.getInstance\s*\(\s*"(AES)"', re.IGNORECASE), "AES-128"),

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
    (re.compile(r"\b(EC_KEY_new(?:_by_curve_name)?)\s*\("), "ECDSA"),
    (re.compile(r"\b(EVP_PKEY_EC)\b"), "ECDSA"),
    (re.compile(r"\b(ECDSA_sign|ECDSA_verify|ECDSA_SIG_new)\b"), "ECDSA"),
    (re.compile(r"\b(EC_GROUP_new_by_curve_name)\b"), "ECDSA"),

    # ── AES-128 ──────────────────────────────────────────────────────────────
    (re.compile(r"\b(EVP_aes_128_(?:cbc|ecb|gcm|ctr|cfb|ofb))\b", re.IGNORECASE), "AES-128"),
    (re.compile(r"\b(AES_128)\b", re.IGNORECASE), "AES-128"),
    (re.compile(r"\b(AES_set_encrypt_key|AES_set_decrypt_key)\s*\([^,]+,\s*128\s*,"), "AES-128"),

    # ── AES-256 ──────────────────────────────────────────────────────────────
    (re.compile(r"\b(EVP_aes_256_(?:cbc|ecb|gcm|ctr|cfb|ofb))\b", re.IGNORECASE), "AES-256"),
    (re.compile(r"\b(AES_256)\b", re.IGNORECASE), "AES-256"),
    (re.compile(r"\b(AES_set_encrypt_key|AES_set_decrypt_key)\s*\([^,]+,\s*256\s*,"), "AES-256"),

    # ── AES generic ──────────────────────────────────────────────────────────
    (re.compile(r"\b(AES_encrypt|AES_decrypt)\b"), "AES-128"),

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
        findings: list[Finding] = []
        for path, language in self._iter_source_files():
            findings.extend(self._scan_file(path, language))
        return findings

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
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            # Unreadable file: record a warning finding so the caller knows
            rel = self._relative(path)
            return [Finding(
                file_path=rel,
                line_number=0,
                language=language,
                matched_api="<unreadable>",
                algorithm="UNKNOWN",
                risk_level=RiskLevel.UNKNOWN,
                replacement="N/A",
                evidence=f"[ERROR] Could not read file: {exc}",
                detection_method="regex",
            )]

        if not source.strip():
            return []  # empty file – nothing to report

        _, patterns = _LANGUAGE_CONFIG[language]
        findings: list[Finding] = []
        seen: set[tuple[int, str]] = set()  # deduplicate same line + algorithm

        lines = source.splitlines()
        for line_no, line in enumerate(lines, start=1):
            for pattern, algorithm in patterns:
                m = pattern.search(line)
                if not m:
                    continue
                matched_api = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                key = (line_no, algorithm)
                if key in seen:
                    continue
                seen.add(key)

                risk = self._classifier.classify(algorithm)
                findings.append(Finding(
                    file_path=self._relative(path),
                    line_number=line_no,
                    language=language,
                    matched_api=matched_api,
                    algorithm=algorithm,
                    risk_level=risk.level,
                    replacement=risk.replacement,
                    evidence=line.strip(),
                    detection_method="regex",
                ))

        return findings

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
        findings = scanner.scan()
    else:
        scanner = RegexScanner(root=args.path)
        findings = scanner.scan()

    if args.pretty or args.format == "table":
        _print_table(findings)
        return

    if args.format == "markdown":
        from ..reporting.inventory_report import InventoryReportGenerator
        total_files = len(list(scanner._iter_source_files())) if hasattr(scanner, "_iter_source_files") else len(findings)
        gen = InventoryReportGenerator(findings, scanned_root=args.path, total_files_scanned=total_files)
        output_text = gen.generate_markdown()
    elif args.format == "report":
        from ..reporting.inventory_report import InventoryReportGenerator
        total_files = len(list(scanner._iter_source_files())) if hasattr(scanner, "_iter_source_files") else len(findings)
        gen = InventoryReportGenerator(findings, scanned_root=args.path, total_files_scanned=total_files)
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
