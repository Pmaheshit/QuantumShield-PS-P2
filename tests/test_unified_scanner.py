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

    def test_regex_ignores_comments_and_strings_on_edge_cases(self):
        edge_fixture = FIXTURES_DIR / "snippet_edge_cases.py"
        scanner = UnifiedScanner(root=edge_fixture, use_ast_for_python=True)

        # In snippet_edge_cases.py:
        # - Regex ignores comments and the logging string and detects the import.
        # - AST ONLY matches the 3 genuine function calls:
        #   CustomRSAKeyModule.generate(1024)
        #   CustomRSAKeyModule.generate(4096)
        #   CustomRSAKeyModule.generate(dynamic_size)
        regex_findings = scanner.regex_scanner._scan_file(edge_fixture, "python")
        ast_findings = scanner.ast_scanner.scan_file(edge_fixture)

        assert len(ast_findings) == 3
        assert len(regex_findings) == 1
        assert "import RSA" in regex_findings[0].evidence

        # Check AST key sizes
        key_sizes = [f.key_size for f in ast_findings]
        assert 1024 in key_sizes
        assert 4096 in key_sizes
        assert None in key_sizes  # dynamic_size

    def test_ast_mode_uses_regex_for_unrecognized_rsa_api(self, tmp_path):
        source = (
            "from some_crypto_library import create_rsa_key\n"
            "private_key = create_rsa_key(2048)\n"
        )
        (tmp_path / "example.py").write_text(source, encoding="utf-8")
        scanner = UnifiedScanner(root=tmp_path, use_ast_for_python=True)

        regex_findings = scanner.regex_scanner._scan_file(tmp_path / "example.py", "python")
        findings = scanner.scan()

        assert any(f.algorithm == "RSA" and f.line_number == 2 for f in regex_findings)
        assert [
            (f.algorithm, f.line_number, f.detection_method)
            for f in findings
        ] == [("RSA", 2, "regex")]

    def test_ast_mode_filters_regex_comment_and_string_matches(self, tmp_path):
        source = (
            "# create_rsa_key(1024)\n"
            "example = 'create_rsa_key(1024)'\n"
            "private_key = create_rsa_key(2048)\n"
        )
        (tmp_path / "example.py").write_text(source, encoding="utf-8")
        scanner = UnifiedScanner(root=tmp_path, use_ast_for_python=True)

        findings = scanner.scan()

        assert [(f.algorithm, f.line_number) for f in findings] == [("RSA", 3)]

    def test_ast_mode_deduplicates_supported_api(self, tmp_path):
        source = (
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        )
        (tmp_path / "example.py").write_text(source, encoding="utf-8")
        scanner = UnifiedScanner(root=tmp_path, use_ast_for_python=True)

        findings = scanner.scan()
        call_findings = [f for f in findings if f.line_number == 2]

        assert len(call_findings) == 1
        assert call_findings[0].detection_method == "ast"
