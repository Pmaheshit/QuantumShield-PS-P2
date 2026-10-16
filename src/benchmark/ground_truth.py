"""
src/benchmark/ground_truth.py
─────────────────────────────
Ground-truth label repository for QuantumShield PS-P2 benchmark validation.

Contains exact expected cryptographic findings for mock test fixtures.
Labels are explicitly defined per fixture file with:
  • file_path
  • line_number
  • algorithm
  • risk_level
  • is_comment_or_docstring (for false-positive auditing)
  • is_genuine_api_call

Note: In accordance with the PS-P2 competition rules, the organizers' official
multi-language repository ground truth is withheld until final judging.
These labels represent our transparent, fully auditable mock test ground truth.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Dict, List, Set, Tuple


@dataclass(frozen=True)
class ExpectedFinding:
    file_name: str
    line_number: int
    algorithm: str
    risk_level: str
    is_genuine_call: bool
    purpose: str = "generic"  # "signature", "key_exchange", "cipher", "hash", "comment", "string"
    fixture_sha256: str | None = None


# Ground truth labels for each Python fixture
MOCK_FIXTURE_GROUND_TRUTH: dict[str, list[ExpectedFinding]] = {
    # ── snippet_clean.py: 0 genuine calls, 0 crypto comments
    "snippet_clean.py": [],

    # ── snippet_edge_cases.py:
    # Contains comments on lines 5, 7, 15
    # Contains string literal on line 21
    # Contains import on line 27
    # Contains exactly 3 genuine RSA generation calls on lines 32, 37, 42
    "snippet_edge_cases.py": [
        ExpectedFinding("snippet_edge_cases.py", 32, "RSA", "HIGH", is_genuine_call=True, purpose="key_exchange"),
        ExpectedFinding("snippet_edge_cases.py", 37, "RSA", "HIGH", is_genuine_call=True, purpose="key_exchange"),
        ExpectedFinding("snippet_edge_cases.py", 42, "RSA", "HIGH", is_genuine_call=True, purpose="key_exchange"),
    ],

    # ── snippet_rsa.py:
    # Line 13: rsa.generate_private_key (genuine)
    # Line 26: hashes.SHA256 (genuine)
    # Line 29: hashes.SHA256 (genuine)
    # Line 39: _RSA.generate(2048) (genuine)
    # Line 41: PKCS1_OAEP.new (genuine)
    # Line 48: _RSA.import_key (genuine)
    "snippet_rsa.py": [
        ExpectedFinding("snippet_rsa.py", 13, "RSA", "HIGH", is_genuine_call=True, purpose="key_exchange"),
        ExpectedFinding("snippet_rsa.py", 26, "SHA-256", "LOWER", is_genuine_call=True, purpose="hash"),
        ExpectedFinding("snippet_rsa.py", 29, "SHA-256", "LOWER", is_genuine_call=True, purpose="hash"),
        ExpectedFinding("snippet_rsa.py", 39, "RSA", "HIGH", is_genuine_call=True, purpose="key_exchange"),
        ExpectedFinding("snippet_rsa.py", 41, "RSA", "HIGH", is_genuine_call=True, purpose="encapsulation"),
        ExpectedFinding("snippet_rsa.py", 48, "RSA", "HIGH", is_genuine_call=True, purpose="key_exchange"),
    ],

    # ── snippet_ecc.py:
    # Line 12: ec.generate_private_key(ec.SECP256R1()) (generic EC key generation)
    # Line 18: ec.ECDSA (genuine signature)
    # Line 18: hashes.SHA256 (genuine hash)
    # Line 23: ec.ECDH (genuine key agreement)
    # Line 32: ECC.generate (generic EC key generation)
    "snippet_ecc.py": [
        ExpectedFinding("snippet_ecc.py", 12, "ECC", "HIGH", is_genuine_call=True),
        ExpectedFinding("snippet_ecc.py", 18, "ECDSA", "HIGH", is_genuine_call=True, purpose="signature"),
        ExpectedFinding("snippet_ecc.py", 18, "SHA-256", "LOWER", is_genuine_call=True, purpose="hash"),
        ExpectedFinding("snippet_ecc.py", 23, "ECDH", "HIGH", is_genuine_call=True, purpose="key_exchange"),
        ExpectedFinding("snippet_ecc.py", 32, "ECC", "HIGH", is_genuine_call=True),
    ],

    # ── snippet_aes.py:
    # Line 15: AES.new (AES-128)
    # Line 32: AES.new (AES-256)
    # Line 43: hashlib.sha256
    # Line 48: hashlib.new("sha256")
    "snippet_aes.py": [
        ExpectedFinding("snippet_aes.py", 15, "AES-128", "MODERATE", is_genuine_call=True, purpose="cipher"),
        ExpectedFinding("snippet_aes.py", 32, "AES-256", "LOWER", is_genuine_call=True, purpose="cipher"),
        ExpectedFinding("snippet_aes.py", 43, "SHA-256", "LOWER", is_genuine_call=True, purpose="hash"),
        ExpectedFinding("snippet_aes.py", 48, "SHA-256", "LOWER", is_genuine_call=True, purpose="hash"),
    ],
}

# Stable content identities prevent an unrelated same-named file from inheriting
# labels for the controlled mock fixture. Update a digest when that fixture changes.
_FIXTURE_SHA256 = {
    "snippet_edge_cases.py": "93aafca910238bb181b180644b45717ed86da21f5eb4bfe58a56d22aaeb6bc8f",
    "snippet_rsa.py": "b28a104bf676095afb4b042326daf954739d3cc3507b821a2ac9aa41fe4dd8b8",
    "snippet_ecc.py": "202c086f25d13440776ef416739b29646bb3da132e3fce5e246d6832e0ea4653",
    "snippet_aes.py": "ec7f39d0c6547ed97ffa3847593cda6743a623bcae52586507ec8ae99465b46e",
}

for _fixture_name, _findings in tuple(MOCK_FIXTURE_GROUND_TRUTH.items()):
    if _findings and _fixture_name in _FIXTURE_SHA256:
        MOCK_FIXTURE_GROUND_TRUTH[_fixture_name] = [
            replace(finding, fixture_sha256=_FIXTURE_SHA256[_fixture_name])
            for finding in _findings
        ]


def get_ground_truth(file_name: str) -> list[ExpectedFinding]:
    """Retrieve ground truth findings for a specific fixture filename."""
    return MOCK_FIXTURE_GROUND_TRUTH.get(file_name, [])


def get_all_ground_truth() -> dict[str, list[ExpectedFinding]]:
    """Retrieve all ground truth mappings."""
    return MOCK_FIXTURE_GROUND_TRUTH
