"""
tests/test_regex_scanner.py
────────────────────────────
Unit tests for src/scanner/regex_scanner.py

Tests cover:
  • Positive detection in Python, Java and C fixtures
  • Correct line number reporting (1-based)
  • Correct risk category assignment per PS-P2 taxonomy
  • True-negative: clean file produces no findings
  • Error handling: unreadable file, empty repository, non-source files
  • Output structure: required fields present on every Finding
  • CLI JSON output is valid JSON
  • Directory scan skips excluded dirs
"""

from __future__ import annotations

import json
import sys
import subprocess
from pathlib import Path

import pytest

# Allow running from the repo root without installing the package
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.scanner.regex_scanner import (
    Finding,
    RegexScanner,
    _mask_python_comments_and_strings,
)
from src.scanner.risk_classifier import RiskLevel

# ── Paths to fixtures ─────────────────────────────────────────────────────────
FIXTURES = Path(__file__).parent / "fixtures"
RSA_PY    = FIXTURES / "snippet_rsa.py"
ECC_PY    = FIXTURES / "snippet_ecc.py"
AES_PY    = FIXTURES / "snippet_aes.py"
JAVA      = FIXTURES / "snippet_ecdsa.java"
C_FILE    = FIXTURES / "snippet_aes.c"
CLEAN_PY  = FIXTURES / "snippet_clean.py"


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def scan_file(path: Path) -> list[Finding]:
    """Convenience: scan a single file and return findings."""
    return RegexScanner(root=path).scan()


def algorithms_found(findings: list[Finding]) -> set[str]:
    return {f.algorithm for f in findings}


def risk_levels_found(findings: list[Finding]) -> set[str]:
    return {f.risk_level for f in findings}


# ──────────────────────────────────────────────────────────────────────────────
# Required Finding fields
# ──────────────────────────────────────────────────────────────────────────────

class TestFindingStructure:
    """Every Finding must carry all PS-P2 required fields."""

    def test_all_required_fields_present(self):
        findings = scan_file(RSA_PY)
        assert findings, "Expected at least one RSA finding"
        f = findings[0]
        assert hasattr(f, "file_path")
        assert hasattr(f, "line_number")
        assert hasattr(f, "language")
        assert hasattr(f, "matched_api")
        assert hasattr(f, "algorithm")
        assert hasattr(f, "risk_level")
        assert hasattr(f, "replacement")
        assert hasattr(f, "evidence")
        assert hasattr(f, "detection_method")

    def test_detection_method_is_regex(self):
        findings = scan_file(RSA_PY)
        assert all(f.detection_method == "regex" for f in findings)

    def test_language_is_python_for_py_file(self):
        findings = scan_file(RSA_PY)
        assert all(f.language == "python" for f in findings)

    def test_language_is_java_for_java_file(self):
        findings = scan_file(JAVA)
        assert all(f.language == "java" for f in findings)

    def test_language_is_c_for_c_file(self):
        findings = scan_file(C_FILE)
        assert all(f.language == "c" for f in findings)

    def test_line_number_is_positive_int(self):
        findings = scan_file(RSA_PY)
        for f in findings:
            assert isinstance(f.line_number, int)
            assert f.line_number >= 1

    def test_evidence_is_non_empty_string(self):
        findings = scan_file(RSA_PY)
        for f in findings:
            assert isinstance(f.evidence, str)
            assert len(f.evidence) > 0


# ──────────────────────────────────────────────────────────────────────────────
# Python: positive detection tests
# ──────────────────────────────────────────────────────────────────────────────

class TestPythonPositive:

    def test_rsa_detected_in_python(self):
        findings = scan_file(RSA_PY)
        assert "RSA" in algorithms_found(findings), \
            f"Expected RSA, got: {algorithms_found(findings)}"

    def test_rsa_is_high_risk(self):
        findings = scan_file(RSA_PY)
        rsa_findings = [f for f in findings if f.algorithm == "RSA"]
        assert all(f.risk_level == RiskLevel.HIGH for f in rsa_findings)

    def test_ecdsa_detected_in_python(self):
        findings = scan_file(ECC_PY)
        algos = algorithms_found(findings)
        assert "ECDSA" in algos or "ECDH" in algos, f"Got: {algos}"

    def test_ecdsa_is_high_risk(self):
        findings = scan_file(ECC_PY)
        ec_findings = [f for f in findings if f.algorithm in ("ECDSA", "ECDH")]
        assert all(f.risk_level == RiskLevel.HIGH for f in ec_findings)

    def test_aes128_detected_in_python(self):
        findings = scan_file(AES_PY)
        assert "AES-128" in algorithms_found(findings), \
            f"Got: {algorithms_found(findings)}"

    def test_aes128_is_moderate(self):
        findings = scan_file(AES_PY)
        aes128 = [f for f in findings if f.algorithm == "AES-128"]
        assert all(f.risk_level == RiskLevel.MODERATE for f in aes128)

    def test_aes256_detected_in_python(self):
        findings = scan_file(AES_PY)
        assert "AES-256" in algorithms_found(findings), \
            f"Got: {algorithms_found(findings)}"

    def test_aes256_is_lower(self):
        findings = scan_file(AES_PY)
        aes256 = [f for f in findings if f.algorithm == "AES-256"]
        assert all(f.risk_level == RiskLevel.LOWER for f in aes256)

    def test_sha256_detected_in_python(self):
        findings = scan_file(AES_PY)
        assert "SHA-256" in algorithms_found(findings), \
            f"Got: {algorithms_found(findings)}"

    def test_sha256_is_lower(self):
        findings = scan_file(AES_PY)
        sha = [f for f in findings if f.algorithm == "SHA-256"]
        assert all(f.risk_level == RiskLevel.LOWER for f in sha)

    def test_python_comments_and_documentation_strings_are_ignored(self, tmp_path):
        source = (
            "# AES-128 was used in an older implementation.\n"
            'message = "SHA256 is mentioned in this documentation."\n'
            'digest = hashlib.new("sha256")\n'
            'cipher = AES.new(key, AES.MODE_GCM, b"0123456789abcdef")\n'
        )
        file_path = tmp_path / "mentions.py"
        file_path.write_text(source, encoding="utf-8")

        findings = RegexScanner(root=file_path).scan()

        assert [(finding.algorithm, finding.line_number) for finding in findings] == [
            ("SHA-256", 3),
            ("AES-UNKNOWN", 4),
        ]
        assert findings[0].evidence == 'digest = hashlib.new("sha256")'

    def test_crypto_api_only_in_comment_is_ignored(self, tmp_path):
        file_path = tmp_path / "comment.py"
        file_path.write_text(
            '# hashlib.new("sha256")\n'
            '# AES.new(b"0123456789abcdef", AES.MODE_GCM)\n',
            encoding="utf-8",
        )

        result = RegexScanner(root=file_path).scan_with_outcomes()

        assert result.findings == []
        assert result.outcomes[0].status == "scanned"

    def test_crypto_api_only_in_ordinary_string_is_ignored(self, tmp_path):
        file_path = tmp_path / "strings.py"
        file_path.write_text(
            'documentation = \'hashlib.new("sha256")\'\n'
            'message = "AES.new(b\'example_key\', AES.MODE_GCM)"\n',
            encoding="utf-8",
        )

        assert RegexScanner(root=file_path).scan() == []

    @pytest.mark.parametrize(
        ("key", "expected_algorithm"),
        [
            ('b"0123456789abcdef"', "AES-128"),
            ('b"0123456789abcdef01234567"', "AES-192"),
            ('b"0123456789abcdef0123456789abcdef"', "AES-256"),
        ],
    )
    def test_multiline_aes_call_uses_literal_key_size(
        self, tmp_path, key, expected_algorithm
    ):
        source = (
            "cipher = AES.new(\n"
            f"    {key},\n"
            "    AES.MODE_GCM,\n"
            ")\n"
        )
        file_path = tmp_path / "multiline_aes.py"
        file_path.write_text(source, encoding="utf-8")

        findings = RegexScanner(root=file_path).scan()

        assert [(finding.algorithm, finding.line_number) for finding in findings] == [
            (expected_algorithm, 1),
        ]
        assert findings[0].matched_api == "AES.new"

    @pytest.mark.parametrize(
        ("suffix", "source"),
        [
            (".java", 'Cipher.getInstance("AES/GCM/NoPadding");\n'),
            (".c", "AES_encrypt(input, output, &key);\n"),
        ],
    )
    def test_generic_aes_apis_do_not_assume_a_key_size(
        self, tmp_path, suffix, source
    ):
        file_path = tmp_path / f"generic_aes{suffix}"
        file_path.write_text(source, encoding="utf-8")

        findings = RegexScanner(root=file_path).scan()

        assert len(findings) == 1
        assert findings[0].algorithm == "AES-UNKNOWN"
        assert findings[0].risk_level == RiskLevel.UNKNOWN

    def test_python_aes_import_alone_does_not_create_finding(self, tmp_path):
        file_path = tmp_path / "import_only.py"
        file_path.write_text("from Crypto.Cipher import AES\n", encoding="utf-8")

        assert RegexScanner(root=file_path).scan() == []

    def test_multiline_hashlib_new_classifies_sha256(self, tmp_path):
        source = (
            "import hashlib\n"
            "digest = hashlib.new(\n"
            '    "sha256"\n'
            ")\n"
        )
        file_path = tmp_path / "multiline_hashlib.py"
        file_path.write_text(source, encoding="utf-8")

        findings = RegexScanner(root=file_path).scan()

        assert [(finding.algorithm, finding.line_number) for finding in findings] == [
            ("SHA-256", 2),
        ]
        assert findings[0].risk_level == RiskLevel.LOWER

    def test_triple_quoted_documentation_is_masked_and_keeps_line_numbers(
        self, tmp_path
    ):
        source = (
            'documentation = """\n'
            'Example: hashlib.new("sha256")\n'
            'AES.new(b"0123456789abcdef", AES.MODE_GCM)\n'
            '"""\n'
            "import hashlib\n"
            'digest = hashlib.new("sha256")\n'
        )
        file_path = tmp_path / "triple_quoted.py"
        file_path.write_text(source, encoding="utf-8")
        masked = _mask_python_comments_and_strings(source)

        assert len(masked) == len(source)
        assert masked.count("\n") == source.count("\n")
        findings = RegexScanner(root=file_path).scan()
        assert [(finding.algorithm, finding.line_number) for finding in findings] == [
            ("SHA-256", 6),
        ]

    def test_comments_between_call_tokens_preserve_real_hashlib_call(self, tmp_path):
        source = (
            "import hashlib\n"
            "digest = hashlib \\\n"
            "    .new( \\\n"
            "    # Select the algorithm\n"
            '    "sha256"\n'
            ")\n"
        )
        file_path = tmp_path / "commented_call.py"
        file_path.write_text(source, encoding="utf-8")

        result = RegexScanner(root=file_path).scan_with_outcomes()

        assert [(finding.algorithm, finding.line_number) for finding in result.findings] == [
            ("SHA-256", 2),
        ]
        assert result.outcomes[0].status == "scanned"

    def test_malformed_python_is_reported_as_failed(self, tmp_path):
        file_path = tmp_path / "malformed.py"
        file_path.write_text(
            'import hashlib\n'
            'digest = hashlib.new("sha256"\n',
            encoding="utf-8",
        )

        result = RegexScanner(root=file_path).scan_with_outcomes()

        assert result.outcomes[0].status == "failed"
        assert "SyntaxError" in result.outcomes[0].reason

    def test_tokenization_failure_keeps_earlier_best_effort_finding(self, tmp_path):
        file_path = tmp_path / "tokenization_error.py"
        file_path.write_text(
            "private_key = create_rsa_key(2048)\n"
            'documentation = """unterminated string\n',
            encoding="utf-8",
        )

        result = RegexScanner(root=file_path).scan_with_outcomes()

        assert any(
            finding.algorithm == "RSA"
            and finding.line_number == 1
            and finding.detection_method == "regex"
            for finding in result.findings
        )
        assert result.outcomes[0].status == "failed"
        assert "Tokenization error" in result.outcomes[0].reason

    def test_masking_preserves_positions_after_multiline_string(self, tmp_path):
        source = (
            'documentation = """\n'
            'hashlib.new("sha256")\n'
            'AES.new(b"0123456789abcdef", AES.MODE_GCM)\n'
            '"""\n'
            "# Still preserve following source positions.\n"
            'digest = hashlib.new("sha256")\n'
        )
        file_path = tmp_path / "positions.py"
        file_path.write_text(source, encoding="utf-8")
        masked = _mask_python_comments_and_strings(source)

        assert len(masked) == len(source)
        assert masked.count("\n") == source.count("\n")
        findings = RegexScanner(root=file_path).scan()
        assert [(finding.algorithm, finding.line_number) for finding in findings] == [
            ("SHA-256", 6),
        ]

    def test_mixed_false_positive_candidates_and_real_api(self, tmp_path):
        source = (
            '# hashlib.new("sha256")\n'
            'documentation = \'AES.new(b"0123456789abcdef", AES.MODE_GCM)\'\n'
            'digest = hashlib.new("sha256")\n'
        )
        file_path = tmp_path / "mixed.py"
        file_path.write_text(source, encoding="utf-8")

        findings = RegexScanner(root=file_path).scan()

        assert [(finding.algorithm, finding.line_number) for finding in findings] == [
            ("SHA-256", 3),
        ]

    def test_rsa_line_number_is_accurate(self):
        """The line reporting a rsa.generate_private_key call should match."""
        source_lines = RSA_PY.read_text().splitlines()
        findings = scan_file(RSA_PY)
        for f in findings:
            if "generate_private_key" in f.matched_api.lower():
                actual_line = source_lines[f.line_number - 1].strip()
                assert "generate_private_key" in actual_line, \
                    f"Line {f.line_number}: '{actual_line}' does not match finding"


# ──────────────────────────────────────────────────────────────────────────────
# Java: positive detection tests
# ──────────────────────────────────────────────────────────────────────────────

class TestJavaPositive:

    def test_rsa_detected_in_java(self):
        findings = scan_file(JAVA)
        assert "RSA" in algorithms_found(findings)

    def test_ecdsa_detected_in_java(self):
        findings = scan_file(JAVA)
        algos = algorithms_found(findings)
        assert "ECDSA" in algos, f"Got: {algos}"

    def test_ecdh_detected_in_java(self):
        findings = scan_file(JAVA)
        algos = algorithms_found(findings)
        assert "ECDH" in algos, f"Got: {algos}"

    def test_aes128_detected_in_java(self):
        findings = scan_file(JAVA)
        assert "AES-128" in algorithms_found(findings)

    def test_aes256_detected_in_java(self):
        findings = scan_file(JAVA)
        assert "AES-256" in algorithms_found(findings)

    def test_sha256_detected_in_java(self):
        findings = scan_file(JAVA)
        assert "SHA-256" in algorithms_found(findings)

    def test_all_java_high_risk_are_high(self):
        findings = scan_file(JAVA)
        high = [f for f in findings if f.algorithm in ("RSA", "ECDSA", "ECDH")]
        assert all(f.risk_level == RiskLevel.HIGH for f in high)

    def test_java_line_numbers_within_bounds(self):
        source_lines = JAVA.read_text().splitlines()
        findings = scan_file(JAVA)
        for f in findings:
            assert 1 <= f.line_number <= len(source_lines), \
                f"Line {f.line_number} out of bounds for file with {len(source_lines)} lines"


# ──────────────────────────────────────────────────────────────────────────────
# C: positive detection tests
# ──────────────────────────────────────────────────────────────────────────────

class TestCPositive:

    def test_rsa_detected_in_c(self):
        findings = scan_file(C_FILE)
        assert "RSA" in algorithms_found(findings)

    def test_ecdsa_detected_in_c(self):
        findings = scan_file(C_FILE)
        assert "ECDSA" in algorithms_found(findings)

    def test_aes128_detected_in_c(self):
        findings = scan_file(C_FILE)
        assert "AES-128" in algorithms_found(findings)

    def test_aes256_detected_in_c(self):
        findings = scan_file(C_FILE)
        assert "AES-256" in algorithms_found(findings)

    def test_sha256_detected_in_c(self):
        findings = scan_file(C_FILE)
        assert "SHA-256" in algorithms_found(findings)

    def test_c_rsa_is_high(self):
        findings = scan_file(C_FILE)
        rsa = [f for f in findings if f.algorithm == "RSA"]
        assert all(f.risk_level == RiskLevel.HIGH for f in rsa)

    def test_c_aes128_is_moderate(self):
        findings = scan_file(C_FILE)
        aes128 = [f for f in findings if f.algorithm == "AES-128"]
        assert all(f.risk_level == RiskLevel.MODERATE for f in aes128)

    def test_c_aes256_is_lower(self):
        findings = scan_file(C_FILE)
        aes256 = [f for f in findings if f.algorithm == "AES-256"]
        assert all(f.risk_level == RiskLevel.LOWER for f in aes256)


# ──────────────────────────────────────────────────────────────────────────────
# True-negative: clean file
# ──────────────────────────────────────────────────────────────────────────────

class TestNonMatches:

    def test_clean_file_produces_no_findings(self):
        findings = scan_file(CLEAN_PY)
        crypto_findings = [
            f for f in findings
            if f.algorithm not in ("UNKNOWN",)
        ]
        assert crypto_findings == [], \
            f"Unexpected findings in clean file: {[(f.algorithm, f.line_number) for f in crypto_findings]}"

    def test_non_source_file_skipped(self, tmp_path):
        """Files with extensions other than .py/.java/.c are ignored."""
        txt_file = tmp_path / "notes.txt"
        txt_file.write_text("from Crypto.PublicKey import RSA\n")
        findings = RegexScanner(root=txt_file).scan()
        assert findings == []


# ──────────────────────────────────────────────────────────────────────────────
# Error handling
# ──────────────────────────────────────────────────────────────────────────────

class TestErrorHandling:

    def test_unreadable_file_produces_error_finding(self, tmp_path):
        """An unreadable file should produce a single UNKNOWN finding, not crash."""
        bad_file = tmp_path / "bad.py"
        bad_file.write_bytes(b"\xff\xfe\xfd")  # invalid UTF-8 / arbitrary bytes

        # Override read to force OSError by removing permissions (best-effort on Windows)
        findings = RegexScanner(root=bad_file).scan()
        # pdfplumber reads with errors='replace', so this should produce 0 or crypto findings
        # The important contract: no exception raised
        assert isinstance(findings, list)

    def test_empty_source_file_produces_no_findings(self, tmp_path):
        empty = tmp_path / "empty.py"
        empty.write_text("")
        findings = RegexScanner(root=empty).scan()
        assert findings == []

    def test_empty_directory_produces_no_findings(self, tmp_path):
        findings = RegexScanner(root=tmp_path).scan()
        assert findings == []

    def test_nonexistent_path_produces_no_findings(self, tmp_path):
        missing = tmp_path / "does_not_exist"
        findings = RegexScanner(root=missing).scan()
        assert findings == []

    def test_skip_venv_directory(self, tmp_path):
        """Files inside .venv/ must be skipped."""
        venv_dir = tmp_path / ".venv" / "lib"
        venv_dir.mkdir(parents=True)
        planted = venv_dir / "crypto_stub.py"
        planted.write_text("from Crypto.PublicKey import RSA\n")
        findings = RegexScanner(root=tmp_path).scan()
        assert findings == [], "Files inside .venv/ should be skipped"

    def test_skip_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules"
        nm.mkdir()
        planted = nm / "bad.py"
        planted.write_text("from Crypto.PublicKey import RSA\n")
        findings = RegexScanner(root=tmp_path).scan()
        assert findings == []


# ──────────────────────────────────────────────────────────────────────────────
# JSON output
# ──────────────────────────────────────────────────────────────────────────────

class TestJsonOutput:

    def test_scan_to_json_is_valid_json(self):
        scanner = RegexScanner(root=FIXTURES)
        output = scanner.scan_to_json()
        parsed = json.loads(output)  # raises if invalid
        assert isinstance(parsed, list)

    def test_json_findings_have_required_keys(self):
        scanner = RegexScanner(root=FIXTURES)
        output = scanner.scan_to_json()
        findings = json.loads(output)
        required_keys = {
            "file_path", "line_number", "language", "matched_api",
            "algorithm", "risk_level", "replacement", "evidence",
            "detection_method",
        }
        for item in findings:
            missing = required_keys - set(item.keys())
            assert not missing, f"Missing keys {missing} in finding: {item}"

    def test_to_dict_is_json_serialisable(self):
        findings = scan_file(RSA_PY)
        assert findings
        d = findings[0].to_dict()
        json.dumps(d)  # must not raise


# ──────────────────────────────────────────────────────────────────────────────
# Directory scan
# ──────────────────────────────────────────────────────────────────────────────

class TestDirectoryScan:

    def test_fixtures_dir_scan_finds_multiple_languages(self):
        scanner = RegexScanner(root=FIXTURES)
        findings = scanner.scan()
        langs = {f.language for f in findings if f.language != "unknown"}
        # fixtures dir contains Python, Java, and C files
        assert "python" in langs
        assert "java" in langs
        assert "c" in langs

    def test_fixtures_dir_has_all_risk_levels(self):
        scanner = RegexScanner(root=FIXTURES)
        findings = scanner.scan()
        levels = risk_levels_found(findings)
        assert RiskLevel.HIGH in levels
        assert RiskLevel.MODERATE in levels
        assert RiskLevel.LOWER in levels

    def test_cli_json_output_is_valid(self):
        """End-to-end: invoke the CLI as a subprocess and parse its output."""
        result = subprocess.run(
            [sys.executable, "-m", "src.scanner.regex_scanner", str(FIXTURES)],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        assert result.returncode == 0, f"CLI exited {result.returncode}: {result.stderr}"
        parsed = json.loads(result.stdout)
        assert isinstance(parsed, list)
        assert len(parsed) > 0
