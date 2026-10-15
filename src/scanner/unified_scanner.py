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

import io
import re
from pathlib import Path
import tokenize
from typing import Any, Iterator, Optional

from .ast_scanner import AstFinding, PythonAstScanner
from .regex_scanner import Finding, RegexScanner, _SKIP_DIRS
from .risk_classifier import RiskClassifier


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
            if language == "python" and self.use_ast_for_python:
                # Use AST scanner
                ast_findings = self.ast_scanner.scan_file(file_path, relative_to=self.root)
                findings.extend(ast_findings)

                regex_findings = self.regex_scanner._scan_file(file_path, language)
                code_lines = self._python_code_lines(file_path)
                if code_lines is not None:
                    for regex_finding in regex_findings:
                        if not self._matches_python_code(regex_finding, code_lines):
                            continue
                        if self._represented_by_ast(regex_finding, ast_findings):
                            continue
                        findings.append(regex_finding)
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

    @staticmethod
    def _python_code_lines(file_path: Path) -> Optional[list[str]]:
        """Return source with comments and string literals masked, or None if tokenizing fails."""
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
            lines = source.splitlines(keepends=True)
            for token in tokenize.generate_tokens(io.StringIO(source).readline):
                if token.type not in (tokenize.COMMENT, tokenize.STRING):
                    continue
                start_line, start_column = token.start
                end_line, end_column = token.end
                for line_number in range(start_line, end_line + 1):
                    line_text = lines[line_number - 1]
                    line = list(line_text)
                    start = start_column if line_number == start_line else 0
                    end = end_column if line_number == end_line else len(line_text.rstrip("\r\n"))
                    for column in range(start, min(end, len(line))):
                        if line[column] not in "\r\n":
                            line[column] = " "
                    lines[line_number - 1] = "".join(line)
            return [line.rstrip("\r\n") for line in lines]
        except (OSError, IndentationError, SyntaxError, tokenize.TokenError):
            return None

    @staticmethod
    def _matches_python_code(finding: Finding, code_lines: list[str]) -> bool:
        if not 1 <= finding.line_number <= len(code_lines):
            return False
        return finding.matched_api in code_lines[finding.line_number - 1]

    @staticmethod
    def _represented_by_ast(finding: Finding, ast_findings: list[AstFinding]) -> bool:
        api = re.sub(r"[\s(]+$", "", finding.matched_api).casefold()
        return any(
            ast_finding.line_number == finding.line_number
            and ast_finding.algorithm == finding.algorithm
            and (
                api in ast_finding.matched_api.casefold()
                or ast_finding.matched_api.casefold() in api
            )
            for ast_finding in ast_findings
        )
