"""
tests/test_ast_scanner.py
─────────────────────────
Unit tests for Python AST scanner (Milestone P1 Part A).
Verifies:
  1. AST detects real crypto calls (RSA, ECDSA, AES, SHA-256).
  2. AST ignores comments and string literals (reduces false positives).
  3. AST extracts statically visible parameters (key sizes, curves).
  4. AST marks unknown/runtime values with confidence="UNKNOWN".
  5. AST handles aliased imports.
  6. AST handles syntax errors gracefully without crashing.
  7. Correct line numbers and file paths are preserved.
"""

from pathlib import Path
import pytest

from src.scanner.ast_scanner import PythonAstScanner, AstFinding
from src.scanner.risk_classifier import RiskLevel

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def ast_scanner() -> PythonAstScanner:
    return PythonAstScanner()


class TestAstPrecisionAndFalsePositives:
    def test_comments_do_not_produce_ast_findings(self, ast_scanner: PythonAstScanner):
        code = '''
# RSA.generate(2048) in comment
# AES-128 is obsolete
# from Crypto.Cipher import AES
x = 10 + 20
'''
        findings = ast_scanner.scan_source(code)
        assert len(findings) == 0

    def test_strings_do_not_produce_ast_findings(self, ast_scanner: PythonAstScanner):
        code = '''
msg = "Connecting to RSA endpoint with AES-128 session"
log = f"SHA256 checksum: {msg}"
'''
        findings = ast_scanner.scan_source(code)
        assert len(findings) == 0

    def test_clean_file_produces_no_ast_findings(self, ast_scanner: PythonAstScanner):
        clean_file = FIXTURES_DIR / "snippet_clean.py"
        findings = ast_scanner.scan_file(clean_file)
        assert len(findings) == 0


class TestAstParameterExtraction:
    def test_rsa_key_size_2048_extracted(self, ast_scanner: PythonAstScanner):
        code = '''
from Crypto.PublicKey import RSA
key = RSA.generate(2048)
'''
        findings = ast_scanner.scan_source(code)
        assert len(findings) == 1
        f = findings[0]
        assert f.algorithm == "RSA"
        assert f.key_size == 2048
        assert f.confidence == "CONFIRMED"
        assert f.risk_level == RiskLevel.HIGH

    def test_rsa_key_size_1024_and_4096(self, ast_scanner: PythonAstScanner):
        code = '''
from Crypto.PublicKey import RSA
k1 = RSA.generate(1024)
k2 = RSA.generate(4096)
'''
        findings = ast_scanner.scan_source(code)
        assert len(findings) == 2
        sizes = [f.key_size for f in findings]
        assert sizes == [1024, 4096]
        assert all(f.confidence == "CONFIRMED" for f in findings)

    def test_cryptography_rsa_key_size_extracted(self, ast_scanner: PythonAstScanner):
        code = '''
from cryptography.hazmat.primitives.asymmetric import rsa
priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
'''
        findings = ast_scanner.scan_source(code)
        assert len(findings) == 1
        assert findings[0].key_size == 3072
        assert findings[0].confidence == "CONFIRMED"

    def test_runtime_parameter_reported_as_unknown(self, ast_scanner: PythonAstScanner):
        code = '''
from Crypto.PublicKey import RSA
def make_key(dyn_size):
    return RSA.generate(dyn_size)
'''
        findings = ast_scanner.scan_source(code)
        assert len(findings) == 1
        assert findings[0].key_size is None
        assert findings[0].confidence == "UNKNOWN"

    def test_ecc_curve_extracted(self, ast_scanner: PythonAstScanner):
        code = '''
from cryptography.hazmat.primitives.asymmetric import ec
key = ec.generate_private_key(ec.SECP384R1())
'''
        findings = ast_scanner.scan_source(code)
        assert len(findings) == 1
        assert findings[0].algorithm == "ECC"
        assert findings[0].risk_level == RiskLevel.HIGH
        assert findings[0].curve == "SECP384R1"
        assert findings[0].confidence == "CONFIRMED"

    def test_ec_key_generation_does_not_assume_signing_or_key_agreement(
        self, ast_scanner: PythonAstScanner
    ):
        code = """
from cryptography.hazmat.primitives.asymmetric import ec
private_key = ec.generate_private_key(ec.SECP256R1())
"""
        findings = ast_scanner.scan_source(code)

        assert len(findings) == 1
        assert findings[0].algorithm == "ECC"
        assert findings[0].risk_level == RiskLevel.HIGH
        assert findings[0].matched_api == "ec.generate_private_key"

    def test_pycryptodome_ecc_generation_is_generic_ecc(
        self, ast_scanner: PythonAstScanner
    ):
        findings = ast_scanner.scan_source(
            'from Crypto.PublicKey import ECC\nkey = ECC.generate(curve="P-256")\n'
        )

        assert len(findings) == 1
        assert findings[0].algorithm == "ECC"
        assert findings[0].risk_level == RiskLevel.HIGH
        assert findings[0].matched_api == "ECC.generate"

    def test_explicit_ecdsa_and_ecdh_operations_keep_specific_labels(
        self, ast_scanner: PythonAstScanner
    ):
        findings = ast_scanner.scan_source(
            "from cryptography.hazmat.primitives.asymmetric import ec\n"
            "signature = private_key.sign(message, ec.ECDSA(hash_algorithm))\n"
            "shared_key = private_key.exchange(ec.ECDH(), peer_public_key)\n"
        )

        assert [(finding.algorithm, finding.risk_level) for finding in findings] == [
            ("ECDSA", RiskLevel.HIGH),
            ("ECDH", RiskLevel.HIGH),
        ]

    def test_aes_bytes_key_size_deduced(self, ast_scanner: PythonAstScanner):
        code = '''
from Crypto.Cipher import AES
cipher = AES.new(b"0123456789abcdef", AES.MODE_CBC)
'''
        findings = ast_scanner.scan_source(code)
        assert len(findings) == 1
        assert findings[0].algorithm == "AES-128"
        assert findings[0].key_size == 128
        assert findings[0].confidence == "CONFIRMED"

    def test_aes_256_bytes_key_size_deduced(self, ast_scanner: PythonAstScanner):
        code = '''
from Crypto.Cipher import AES
cipher = AES.new(b"0123456789abcdef0123456789abcdef", AES.MODE_GCM)
'''
        findings = ast_scanner.scan_source(code)
        assert len(findings) == 1
        assert findings[0].algorithm == "AES-256"
        assert findings[0].key_size == 256
        assert findings[0].confidence == "CONFIRMED"

    @pytest.mark.parametrize(
        ("key", "expected_algorithm", "expected_size"),
        [
            ('b"0123456789abcdef"', "AES-128", 128),
            ('b"0123456789abcdef01234567"', "AES-192", 192),
            ('b"0123456789abcdef0123456789abcdef"', "AES-256", 256),
        ],
    )
    def test_aes_key_size_variants_are_reported_exactly(
        self, ast_scanner: PythonAstScanner, key: str, expected_algorithm: str,
        expected_size: int,
    ):
        findings = ast_scanner.scan_source(
            f"from Crypto.Cipher import AES\ncipher = AES.new({key}, AES.MODE_GCM)\n"
        )

        assert len(findings) == 1
        assert findings[0].algorithm == expected_algorithm
        assert findings[0].key_size == expected_size
        assert findings[0].confidence == "CONFIRMED"
        assert findings[0].assumed_default is False

    def test_unknown_aes_key_is_not_assigned_a_variant_by_default(
        self, ast_scanner: PythonAstScanner
    ):
        findings = ast_scanner.scan_source(
            "from Crypto.Cipher import AES\ncipher = AES.new(key_from_kms, AES.MODE_GCM)\n"
        )

        assert len(findings) == 1
        assert findings[0].algorithm == "AES-UNKNOWN"
        assert findings[0].key_size is None
        assert findings[0].confidence == "INFERRED"
        assert findings[0].risk_level == RiskLevel.UNKNOWN
        assert findings[0].assumed_default is False
        assert findings[0].to_dict()["assumed_default"] is False

    def test_conservative_aes_default_is_disabled(self):
        import src.scanner.ast_scanner as ast_scanner_module

        assert ast_scanner_module.CONSERVATIVE_AES_DEFAULT is False

    @pytest.mark.parametrize(
        "key_expression",
        [
            "key_from_kms",
            "load_key()",
            "settings.encryption_key",
        ],
    )
    def test_dynamic_aes_key_sources_remain_unresolved(
        self, ast_scanner: PythonAstScanner, key_expression: str
    ):
        findings = ast_scanner.scan_source(
            f"from Crypto.Cipher import AES\ncipher = AES.new({key_expression}, AES.MODE_GCM)\n"
        )

        assert len(findings) == 1
        assert findings[0].algorithm == "AES-UNKNOWN"
        assert findings[0].key_size is None
        assert findings[0].risk_level == RiskLevel.UNKNOWN

    @pytest.mark.parametrize(
        "key_expression",
        [
            'make_key(16)',
            'key_factory(size=16)',
            '"0123456789abcdef"',
        ],
    )
    def test_unverified_key_expressions_do_not_confirm_aes_size(
        self, ast_scanner: PythonAstScanner, key_expression: str
    ):
        findings = ast_scanner.scan_source(
            f"from Crypto.Cipher import AES\ncipher = AES.new({key_expression}, AES.MODE_GCM)\n"
        )

        assert len(findings) == 1
        assert findings[0].algorithm == "AES-UNKNOWN"
        assert findings[0].key_size is None
        assert findings[0].risk_level == RiskLevel.UNKNOWN

    @pytest.mark.parametrize(
        ("imports", "key_expression", "expected_size"),
        [
            ("import os\n", "os.urandom(24)", 192),
            ("from Crypto.Random import get_random_bytes\n", "get_random_bytes(32)", 256),
        ],
    )
    def test_known_random_byte_apis_confirm_requested_key_size(
        self, ast_scanner: PythonAstScanner, imports, key_expression, expected_size
    ):
        findings = ast_scanner.scan_source(
            f"{imports}from Crypto.Cipher import AES\n"
            f"cipher = AES.new({key_expression}, AES.MODE_GCM)\n"
        )

        assert len(findings) == 1
        assert findings[0].algorithm == f"AES-{expected_size}"
        assert findings[0].key_size == expected_size
        assert findings[0].confidence == "CONFIRMED"

    def test_conservative_aes_default_is_explicitly_marked(
        self, ast_scanner: PythonAstScanner, monkeypatch
    ):
        import src.scanner.ast_scanner as ast_scanner_module

        monkeypatch.setattr(ast_scanner_module, "CONSERVATIVE_AES_DEFAULT", True)
        findings = ast_scanner.scan_source(
            "from Crypto.Cipher import AES\ncipher = AES.new(key_from_kms, AES.MODE_GCM)\n"
        )

        assert len(findings) == 1
        assert findings[0].algorithm == "AES-128"
        assert findings[0].confidence == "INFERRED"
        assert findings[0].assumed_default is True
        assert findings[0].to_dict()["assumed_default"] is True

    def test_cryptography_unknown_aes_key_is_unresolved(
        self, ast_scanner: PythonAstScanner
    ):
        findings = ast_scanner.scan_source(
            "from cryptography.hazmat.primitives.ciphers import algorithms\n"
            "cipher = algorithms.AES(key_from_kms)\n"
        )

        assert len(findings) == 1
        assert findings[0].algorithm == "AES-UNKNOWN"
        assert findings[0].key_size is None
        assert findings[0].confidence == "INFERRED"
        assert findings[0].risk_level == RiskLevel.UNKNOWN


class TestAstAliasingAndImports:
    def test_aliased_import_resolved(self, ast_scanner: PythonAstScanner):
        code = '''
from Crypto.PublicKey import RSA as MyCustomKeyGen
key = MyCustomKeyGen.generate(2048)
'''
        findings = ast_scanner.scan_source(code)
        assert len(findings) == 1
        assert findings[0].algorithm == "RSA"
        assert findings[0].key_size == 2048

    def test_aliased_module_import_resolved(self, ast_scanner: PythonAstScanner):
        code = '''
import hashlib as hl
digest = hl.sha256(b"test").hexdigest()
'''
        findings = ast_scanner.scan_source(code)
        assert len(findings) == 1
        assert findings[0].algorithm == "SHA-256"


class TestAstRobustnessAndSyntaxErrors:
    def test_syntax_error_handled_gracefully(self, ast_scanner: PythonAstScanner):
        bad_code = "def invalid_syntax(x :::: return"
        findings = ast_scanner.scan_source(bad_code, file_path="bad.py")
        assert len(findings) == 1
        assert findings[0].detection_method == "ast_error"
        assert findings[0].risk_level == RiskLevel.UNKNOWN
        assert "SyntaxError" in findings[0].details

    def test_line_numbers_accurate(self, ast_scanner: PythonAstScanner):
        code = '''# line 1
# line 2
from Crypto.PublicKey import RSA  # line 3
# line 4
key = RSA.generate(2048)  # line 5
'''
        findings = ast_scanner.scan_source(code)
        assert len(findings) == 1
        assert findings[0].line_number == 5
        assert "RSA.generate(2048)" in findings[0].evidence
