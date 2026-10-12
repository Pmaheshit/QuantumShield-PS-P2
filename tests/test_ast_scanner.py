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
        assert findings[0].algorithm == "ECDSA"
        assert findings[0].curve == "SECP384R1"
        assert findings[0].confidence == "CONFIRMED"

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
