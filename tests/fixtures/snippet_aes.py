"""
tests/fixtures/snippet_aes.py
Mock Python source file with AES-128 and AES-256 usage patterns.
"""

import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# ── AES-128 (MODERATE risk) ───────────────────────────────────────────────────
def encrypt_aes128(plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypt with AES-128-GCM."""
    key = get_random_bytes(16)          # 16 bytes = 128 bits
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return key, ciphertext, tag


def encrypt_aes128_explicit() -> bytes:
    """Explicit AES-128 label."""
    key = b"mysecretkey12345"  # AES-128 key (16 bytes)
    # Using AES_128 constant as a label in a config dict
    config = {"algorithm": "AES-128", "key_size": 128}
    return key


# ── AES-256 (LOWER risk) ──────────────────────────────────────────────────────
def encrypt_aes256(plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypt with AES-256-GCM."""
    key = get_random_bytes(32)          # 32 bytes = 256 bits
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return key, ciphertext, tag


AES_256_KEY_SIZE = 256  # used in config below


# ── SHA-256 (LOWER risk) ──────────────────────────────────────────────────────
def hash_sha256(data: bytes) -> str:
    """Hash data with SHA-256."""
    digest = hashlib.sha256(data).hexdigest()
    return digest


def hash_sha256_alt(data: bytes) -> bytes:
    h = hashlib.new("sha256")
    h.update(data)
    return h.digest()
