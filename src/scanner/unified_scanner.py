"""
src/scanner/unified_scanner.py
──────────────────────────────
Unified Static Scanner combining Regex-based pattern detection (for Python, Java, C)
with Python AST enrichment.

Part of QuantumShield PS-P2 (Qiskit Fall Fest 2026).

Workflow:
1. Java and C files are scanned using RegexScanner (baseline).
2. Python files can be scanned with AST (for high precision, parameter extraction,
   comment elimination) with Regex fallback or comparison mode.
3. Provides unified findings with detection_method, confidence, and line numbers.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional, Union

from .ast_scanner import AstFinding, PythonAstScanner
from .regex_scanner import Finding, RegexScanner, _SKIP_DIRS
from .risk_classifier import RiskClassifier, RiskLevel


class UnifiedScanner:
    """
    Orchestrates multi-language static crypto detection.
    Applies AST enrichment on Python files while maintaining Regex coverage for
    all supported languages (Python, Java, C).
    """

    def __init__(
        self,
        root: str | Path,
        skip_dirs: Optional[frozenset[str]] = None,
        use_ast_for_python: bool = True,
        classifier: Optional[RiskClassifier] = None,
    ) -> None:
        self.root = Path(root).resolve()
        self.skip_dirs = skip_dirs if skip_dirs is not None else _SKIP_DIRS
        self.use_ast_for_python = use_ast_for_python
        self.classifier = classifier or RiskClassifier()
        self.regex_scanner = RegexScanner(root=self.root, skip_dirs=self.skip_dirs)
        self.ast_scanner = PythonAstScanner(classifier=self.classifier)

    def scan(self) -> list[Finding]:
        """
        Execute scan across all files in root.
        Returns unified list of findings.
        """
        findings: list[Finding] = []
        scanned_files = list(self._iter_source_files())

        for file_path, language in scanned_files:
            rel_path = str(file_path.relative_to(self.root)) if self.root.is_dir() else file_path.name

            if language == "python" and self.use_ast_for_python:
                # Use AST scanner
                ast_findings = self.ast_scanner.scan_file(file_path, relative_to=self.root)
                # If AST encountered a syntax error or produced 0 findings on an unparseable file,
                # we retain the AST findings (which records the error or findings).
                # In addition, if code has standard calls not yet mapped in AST, regex can supplement.
                # However, AST eliminates comment false positives!
                findings.extend(ast_findings)
            else:
                # Regex scanner for Java, C, and non-AST Python
                regex_findings = self.regex_scanner._scan_file(file_path, language)
                findings.extend(regex_findings)

        return findings

    def scan_comparison(self) -> dict[str, Any]:
        """
        Runs both regex and AST scanners on all Python files and returns a comparison dict
        measuring findings count, comment false positives filtered, and parameter extraction.
        """
        py_files = [p for p, lang in self._iter_source_files() if lang == "python"]
        regex_py_findings: list[Finding] = []
        ast_py_findings: list[Finding] = []

        for p in py_files:
            regex_py_findings.extend(self.regex_scanner._scan_file(p, "python"))
            ast_py_findings.extend(self.ast_scanner.scan_file(p, relative_to=self.root))

        return {
            "scanned_python_files": len(py_files),
            "regex_findings_count": len(regex_py_findings),
            "ast_findings_count": len(ast_py_findings),
            "regex_findings": [f.to_dict() for f in regex_py_findings],
            "ast_findings": [f.to_dict() for f in ast_py_findings],
        }

    def _iter_source_files(self) -> Iterator[tuple[Path, str]]:
        return self.regex_scanner._iter_source_files()
