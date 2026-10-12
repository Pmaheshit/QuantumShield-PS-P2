"""
tests/test_risk_classifier.py
─────────────────────────────
Unit tests for src/scanner/risk_classifier.py

Tests cover:
  • Correct risk level for each PS-P2 taxonomy entry
  • Correct replacement recommendation for each level
  • Case-insensitive lookup
  • Alias resolution
  • Unknown algorithm handling (returns UNKNOWN, not exception)
"""

import pytest
from src.scanner.risk_classifier import RiskClassifier, RiskLevel


@pytest.fixture()
def clf():
    return RiskClassifier()


# ──────────────────────────────────────────────────────────────────────────────
# HIGH-risk algorithms (Shor's algorithm threat)
# ──────────────────────────────────────────────────────────────────────────────

class TestHighRisk:
    def test_rsa_is_high(self, clf):
        p = clf.classify("RSA")
        assert p.level == RiskLevel.HIGH

    def test_rsa_lowercase_is_high(self, clf):
        p = clf.classify("rsa")
        assert p.level == RiskLevel.HIGH

    def test_ecdsa_is_high(self, clf):
        p = clf.classify("ECDSA")
        assert p.level == RiskLevel.HIGH

    def test_ecdh_is_high(self, clf):
        p = clf.classify("ECDH")
        assert p.level == RiskLevel.HIGH

    def test_ecc_is_high(self, clf):
        p = clf.classify("ECC")
        assert p.level == RiskLevel.HIGH

    def test_rsa_replacement_mentions_ml_kem(self, clf):
        p = clf.classify("RSA")
        assert "ML-KEM" in p.replacement or "ML-DSA" in p.replacement

    def test_ecdsa_replacement_mentions_ml_dsa(self, clf):
        p = clf.classify("ECDSA")
        assert "ML-DSA" in p.replacement

    def test_ecdh_replacement_mentions_ml_kem(self, clf):
        p = clf.classify("ECDH")
        assert "ML-KEM" in p.replacement

    def test_purpose_specific_rsa_signature(self, clf):
        p = clf.classify("RSA", purpose="signature")
        assert "ML-DSA" in p.replacement
        assert "ML-KEM" not in p.replacement

    def test_purpose_specific_rsa_encapsulation(self, clf):
        p = clf.classify("RSA", purpose="encapsulation")
        assert "ML-KEM" in p.replacement
        assert "ML-DSA" not in p.replacement



# ──────────────────────────────────────────────────────────────────────────────
# MODERATE-risk algorithms (Grover's algorithm threat)
# ──────────────────────────────────────────────────────────────────────────────

class TestModerateRisk:
    def test_aes128_is_moderate(self, clf):
        p = clf.classify("AES-128")
        assert p.level == RiskLevel.MODERATE

    def test_aes128_alias_underscore(self, clf):
        p = clf.classify("AES_128")
        assert p.level == RiskLevel.MODERATE

    def test_aes128_alias_no_separator(self, clf):
        p = clf.classify("AES128")
        assert p.level == RiskLevel.MODERATE

    def test_aes128_replacement_is_aes256(self, clf):
        p = clf.classify("AES-128")
        assert "AES-256" in p.replacement


# ──────────────────────────────────────────────────────────────────────────────
# LOWER-risk algorithms
# ──────────────────────────────────────────────────────────────────────────────

class TestLowerRisk:
    def test_aes256_is_lower(self, clf):
        p = clf.classify("AES-256")
        assert p.level == RiskLevel.LOWER

    def test_sha256_is_lower(self, clf):
        p = clf.classify("SHA-256")
        assert p.level == RiskLevel.LOWER

    def test_sha256_alias(self, clf):
        p = clf.classify("SHA256")
        assert p.level == RiskLevel.LOWER

    def test_sha256_alias_underscore(self, clf):
        p = clf.classify("SHA_256")
        assert p.level == RiskLevel.LOWER

    def test_aes256_no_replacement_change_needed(self, clf):
        p = clf.classify("AES-256")
        # replacement should say no change required
        assert "No change" in p.replacement or "no change" in p.replacement.lower()

    def test_sha256_no_replacement_change_needed(self, clf):
        p = clf.classify("SHA-256")
        assert "No change" in p.replacement or "no change" in p.replacement.lower()


# ──────────────────────────────────────────────────────────────────────────────
# Unknown / unrecognised algorithms
# ──────────────────────────────────────────────────────────────────────────────

class TestUnknown:
    def test_unknown_algo_returns_unknown_level(self, clf):
        p = clf.classify("BLOWFISH")
        assert p.level == RiskLevel.UNKNOWN

    def test_unknown_algo_no_exception(self, clf):
        """Unknown algorithm must never raise."""
        p = clf.classify("SOME_FUTURE_ALGO_XYZ")
        assert p is not None
        assert p.level == RiskLevel.UNKNOWN

    def test_empty_string_no_exception(self, clf):
        p = clf.classify("")
        assert p is not None

    def test_all_profiles_non_empty(self, clf):
        profiles = clf.all_profiles()
        assert len(profiles) >= 7   # RSA, ECDSA, ECDH, ECC, AES-128, AES-256, SHA-256
