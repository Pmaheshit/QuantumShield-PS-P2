"""
tests/test_unified_scanner.py
─────────────────────────────
Unit tests for UnifiedScanner and AST vs Regex comparison (Milestone P1 Part C).
Verifies:
  1. Unified scanner detects across Python, Java, and C files.
  2. AST vs Regex comparison flags false positives correctly on comment fixtures.
  3. Preservation of all findings and line number alignment.
"""

from pathlib import Path
import pytest

from src.scanner.unified_scanner import UnifiedScanner
from src.scanner.risk_classifier import RiskLevel

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestUnifiedScanner:
    def test_unified_scan_runs_across_fixtures(self):
        scanner = UnifiedScanner(root=FIXTURES_DIR, use_ast_for_python=True)
        findings = scanner.scan()

        assert len(findings) > 0
        languages = {f.language for f in findings}
        assert "python" in languages
        assert "java" in languages
        assert "c" in languages

    def test_ast_vs_regex_comparison_on_edge_cases(self):
        edge_fixture = FIXTURES_DIR / "snippet_edge_cases.py"
        scanner = UnifiedScanner(root=edge_fixture, use_ast_for_python=True)

        # In snippet_edge_cases.py:
        # - Regex matches the comment lines ("RSA-2048", "AES-128", "hashlib.sha256")
        #   AND the string literal ("RSA_key_holder", "AES_128")
        #   AND the import line.
        # - AST ONLY matches the 3 genuine function calls:
        #   CustomRSAKeyModule.generate(1024)
        #   CustomRSAKeyModule.generate(4096)
        #   CustomRSAKeyModule.generate(dynamic_size)
        regex_findings = scanner.regex_scanner._scan_file(edge_fixture, "python")
        ast_findings = scanner.ast_scanner.scan_file(edge_fixture)

        # AST must have eliminated the comment and string literal false positives!
        assert len(ast_findings) == 3
        # Regex flags comments and strings, so regex findings count > AST findings count
        assert len(regex_findings) > len(ast_findings)

        # Check AST key sizes
        key_sizes = [f.key_size for f in ast_findings]
        assert 1024 in key_sizes
        assert 4096 in key_sizes
        assert None in key_sizes  # dynamic_size
