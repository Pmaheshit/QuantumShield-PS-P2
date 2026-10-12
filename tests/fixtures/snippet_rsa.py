"""
tests/fixtures/snippet_rsa.py
Mock Python source file with RSA usage patterns.
Used as a positive-detection fixture for PS-P2 scanner tests.
"""

# ── cryptography library (modern Python PQC-migration target) ─────────────────
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

def generate_rsa_keypair(key_size: int = 2048):
    """Generate an RSA keypair using the cryptography library."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def sign_with_rsa(private_key, message: bytes) -> bytes:
    """Sign a message with RSA-PSS."""
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


# ── PyCryptodome (legacy) ─────────────────────────────────────────────────────
from Crypto.PublicKey import RSA as _RSA
from Crypto.Cipher import PKCS1_OAEP

def pycryptodome_rsa_example():
    key = _RSA.generate(2048)
    public_key = key.publickey()
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(b"hello quantum world")
    return ciphertext


# ── RSA import check ─────────────────────────────────────────────────────────
def load_rsa_key(pem_data: bytes):
    return _RSA.import_key(pem_data)
