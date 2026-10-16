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

    def test_multiline_api_call_is_retained_once(self, tmp_path):
        source = (
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "private_key = rsa.generate_private_key(\n"
            "    public_exponent=65537,\n"
            "    key_size=2048,\n"
            ")\n"
        )
        (tmp_path / "example.py").write_text(source, encoding="utf-8")
        scanner = UnifiedScanner(root=tmp_path, use_ast_for_python=True)

        findings = scanner.scan()
        call_findings = [
            finding for finding in findings
            if finding.algorithm == "RSA" and finding.line_number == 2
        ]

        assert len(call_findings) == 1
        assert call_findings[0].detection_method == "ast"

    def test_nested_supported_calls_keep_ast_occurrences_without_regex_duplicate(
        self, tmp_path
    ):
        source = (
            "import hashlib\n"
            "digest = hashlib.sha256(hashlib.sha256(data).digest()).digest()\n"
        )
        (tmp_path / "example.py").write_text(source, encoding="utf-8")
        scanner = UnifiedScanner(root=tmp_path, use_ast_for_python=True)

        findings = scanner.scan()
        hash_findings = [
            finding for finding in findings
            if finding.algorithm == "SHA-256" and finding.line_number == 2
        ]

        assert len(hash_findings) == 2
        assert all(finding.detection_method == "ast" for finding in hash_findings)

    def test_import_finding_is_retained(self, tmp_path):
        source = "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        (tmp_path / "example.py").write_text(source, encoding="utf-8")
        scanner = UnifiedScanner(root=tmp_path, use_ast_for_python=True)

        findings = scanner.scan()

        assert len(findings) == 1
        assert findings[0].line_number == 1
        assert findings[0].algorithm == "RSA"
        assert findings[0].detection_method == "regex"

    def test_comments_between_tokens_do_not_hide_call_or_add_false_positive(
        self, tmp_path
    ):
        source = (
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "key = (\n"
            "    rsa.generate_private_key  # RSA.generate(1024) is only a comment\n"
            "    (\n"
            "        public_exponent=65537,\n"
            "        key_size=2048,\n"
            "    )\n"
            ")\n"
        )
        (tmp_path / "example.py").write_text(source, encoding="utf-8")
        scanner = UnifiedScanner(root=tmp_path, use_ast_for_python=True)

        findings = scanner.scan()
        call_findings = [
            finding
            for finding in findings
            if finding.algorithm == "RSA" and finding.line_number == 3
        ]

        assert len(call_findings) == 1
        assert call_findings[0].detection_method == "ast"
        assert len(findings) == 2  # one import finding and one call finding

    @pytest.mark.parametrize(
        "source",
        [
            "# rsa.generate_private_key(2048)\n",
            'documentation = "rsa.generate_private_key(2048)"\n',
        ],
    )
    def test_api_name_only_in_comment_or_string_is_ignored(self, tmp_path, source):
        (tmp_path / "example.py").write_text(source, encoding="utf-8")
        scanner = UnifiedScanner(root=tmp_path, use_ast_for_python=True)

        assert scanner.scan() == []

    def test_tokenization_failure_keeps_best_effort_regex_finding(self, tmp_path):
        source = (
            "private_key = create_rsa_key(2048)\n"
            'documentation = """unterminated string\n'
        )
        file_path = tmp_path / "malformed.py"
        file_path.write_text(source, encoding="utf-8")
        scanner = UnifiedScanner(root=tmp_path, use_ast_for_python=True)

        masked_lines, tokenization_error = scanner._python_code_lines_with_error(
            file_path
        )
        assert masked_lines is None
        assert tokenization_error

        result = scanner.scan_with_outcomes()

        assert any(
            finding.detection_method == "ast_error"
            for finding in result.findings
        )
        assert any(
            finding.matched_api == "create_rsa_key"
            and finding.detection_method == "regex"
            for finding in result.findings
        )
        assert result.outcomes[0].status == "failed"
        assert result.outcomes[0].reason
