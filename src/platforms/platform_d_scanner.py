"""
src/platforms/platform_d_scanner.py
───────────────────────────────────
Platform D implementation: Memory-Budgeted High-Risk AST Scanner.

Implements the Custom Platform D architecture for QuantumShield PS-P2:
  • Memory Budget: File-size guard rejects individual files exceeding the
    configured memory_limit_mb threshold before parsing begins.
    NOTE: This is a per-file input-size boundary, NOT a process-wide OS-enforced
    memory ceiling.  The Python interpreter RSS (including runtime and shared
    libs) will always exceed the budget figure.  What is bounded is the volume of
    source text fed into the AST parser in a single call.
  • Streaming Iterator: Scans files incrementally without buffering full
    repository ASTs.
  • Genuine Trade-off Demonstration (scan_strategy="high_risk_priority"):
    - Focuses deep AST parsing on Shor-vulnerable asymmetric algorithms
      (RSA, ECC, ECDSA, ECDH) which are the urgent PQC migration targets.
    - Symmetric-only files (AES, SHA with no asymmetric call sites) are
      processed via fast regex baseline.
    - This selective strategy is implemented by:
        1. Tokenizing a quick pre-scan so comments and ordinary strings do not
           trigger asymmetric routing.
        2. If any HIGH-risk pattern is found, parse the full AST for precision.
        3. Otherwise emit token-aware regex findings directly.
    - The benchmark reports precision, recall, and runtime for each scanner mode
      rather than assuming that the selective path preserves a fixed recall.
"""

from __future__ import annotations

import re
import os
from pathlib import Path
from typing import Iterator, List, Optional

from ..scanner.ast_scanner import AstFinding, PythonAstScanner
from ..scanner.regex_scanner import (
    Finding,
    RegexScanner,
    _SKIP_DIRS,
    _mask_python_comments_and_strings,
)
from ..scanner.risk_classifier import RiskClassifier, RiskLevel
from .platform_config import PLATFORM_D, PlatformProfile

# Quick-check patterns used by the high_risk_priority pre-scan.
# We deliberately keep this set conservative so we do NOT miss RSA/ECC calls.
_HIGH_RISK_QUICK_PATTERNS: list[re.Pattern] = [
    re.compile(r"\brsa\b", re.IGNORECASE),
    re.compile(r"\becdsa\b", re.IGNORECASE),
    re.compile(r"\becdh\b", re.IGNORECASE),
    re.compile(r"\bec\.\w", re.IGNORECASE),          # ec.generate_private_key, ec.SECP256R1 …
    re.compile(r"\bECC\.generate\b", re.IGNORECASE),
    re.compile(r"\basymmetric\b", re.IGNORECASE),     # cryptography.hazmat.primitives.asymmetric
]


def _file_text_contains_high_risk(text: str) -> bool:
    """Return True if Python code contains a HIGH-risk asymmetric pattern."""
    code = _mask_python_comments_and_strings(text)
    for pat in _HIGH_RISK_QUICK_PATTERNS:
        if pat.search(code):
            return True
    return False


class PlatformDScanner:
    """
    Modular execution engine for Custom Platform D.

    Enforces an input-file-size boundary (not a process-wide OS memory limit)
    and implements the high_risk_priority selective AST strategy.
    """

    def __init__(
        self,
        root: str | Path,
        profile: Optional[PlatformProfile] = None,
        classifier: Optional[RiskClassifier] = None,
    ) -> None:
        self.root = Path(root).resolve()
        if not self.root.exists():
            raise FileNotFoundError(f"Root path does not exist: {self.root}")

        self.profile = profile or PLATFORM_D
        self.profile.validate()

        self.classifier = classifier or RiskClassifier()
        self.regex_scanner = RegexScanner(root=self.root, skip_dirs=_SKIP_DIRS)
        self.ast_scanner = PythonAstScanner(classifier=self.classifier)

    def scan(self) -> list[Finding]:
        """
        Execute Platform D scan according to configured scan_strategy and
        the input-file-size boundary.
        """
        findings: list[Finding] = []
        max_file_bytes = (self.profile.memory_limit_mb or 64) * 1024 * 1024

        for file_path, language in self._iter_source_files():
            # ── Input-size boundary (not an OS heap limit) ──────────────────
            try:
                size = file_path.stat().st_size
                if size > max_file_bytes:
                    rel = (
                        str(file_path.relative_to(self.root))
                        if self.root.is_dir()
                        else file_path.name
                    )
                    findings.append(
                        Finding(
                            file_path=rel,
                            line_number=0,
                            language=language,
                            matched_api="<InputSizeLimitExceeded>",
                            algorithm="UNKNOWN",
                            risk_level=RiskLevel.UNKNOWN,
                            replacement=(
                                f"File exceeds Platform D input-size limit of "
                                f"{self.profile.memory_limit_mb} MB; skipped to stay within "
                                f"per-file parsing budget."
                            ),
                            evidence=f"File size {round(size / 1024, 2)} KB exceeds budget",
                            detection_method="platform_d_guard",
                        )
                    )
                    continue
            except OSError:
                continue

            # ── Scan the file according to strategy ──────────────────────────
            if language == "python":
                findings.extend(self._scan_python_file(file_path))
            else:
                # Java and C: always use regex engine (no AST available)
                findings.extend(self.regex_scanner._scan_file(file_path, language))

        return findings

    # ── Strategy dispatch ────────────────────────────────────────────────────

    def _scan_python_file(self, file_path: Path) -> list[Finding]:
        strategy = self.profile.scan_strategy

        if strategy in ("full", "ast_deep"):
            # Unconditionally parse full AST for all Python files
            return self.ast_scanner.scan_file(file_path, relative_to=self.root)

        if strategy == "regex_fast":
            # Regex only — no AST parsing overhead
            return self.regex_scanner._scan_file(file_path, "python")

        if strategy == "high_risk_priority":
            return self._scan_python_high_risk_priority(file_path)

        # Fallback: full AST
        return self.ast_scanner.scan_file(file_path, relative_to=self.root)

    def _scan_python_high_risk_priority(self, file_path: Path) -> list[Finding]:
        """
        Selective AST strategy:
        1. Read source and mask comments and non-API strings.
        2. Quick-check for HIGH-risk (asymmetric) API keywords.
        3. If found  → run full AST scan (precise, eliminates comment/string FPs).
        4. If absent → run token-aware regex scan without AST parse overhead.

        The detection_method field distinguishes which path each finding took.
        """
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        if _file_text_contains_high_risk(text):
            # Deep AST parse: eliminates comment/string FPs, extracts key sizes
            return self.ast_scanner.scan_file(file_path, relative_to=self.root)
        else:
            # Fast path: symmetric-only file — regex is sufficient
            return self.regex_scanner._scan_file(file_path, "python")

    def _iter_source_files(self) -> Iterator[tuple[Path, str]]:
        return self.regex_scanner._iter_source_files()
