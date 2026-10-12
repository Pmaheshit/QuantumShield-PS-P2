"""
tests/fixtures/snippet_ecc.py
Mock Python source file with ECC/ECDSA/ECDH usage patterns.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


def generate_ec_keypair():
    """Generate an elliptic-curve keypair (P-256)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def ecdsa_sign(private_key, message: bytes) -> bytes:
    """Sign with ECDSA."""
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


def ecdh_exchange(private_key, peer_public_key) -> bytes:
    """Perform ECDH key agreement."""
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_key


# PyCryptodome ECC path
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

def pycryptodome_ecc_example():
    key = ECC.generate(curve="P-256")
    signer = DSS.new(key, "fips-186-3")
    return signer
