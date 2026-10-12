"""
tests/fixtures/snippet_edge_cases.py
───────────────────────────────────
Test fixture with edge cases for Python AST vs Regex evaluation:
1. Comment false positives (lines that mention RSA/AES/SHA-256 only in comments)
2. String literal false positives (strings mentioning algorithms in non-crypto logging)
3. Aliased imports (e.g. `from Crypto.PublicKey import RSA as LegacyAsymKey`)
4. Key sizes: 1024-bit, 2048-bit, 4096-bit
5. Ambiguous calls with unknown parameters computed at runtime
"""

import os

# COMMENT FALSE POSITIVE 1:
# We used to use RSA-2048 and AES-128 here, but now this is plain arithmetic.
# Note: hashlib.sha256 was replaced by blake2b in version 2.0.


def regular_computation(x: int, y: int) -> int:
    # STRING LITERAL FALSE POSITIVE:
    log_msg = "Checking status for user RSA_key_holder_99 with AES_128 flag"
    print(log_msg)
    return x * y + 42


# ── Aliased Import ───────────────────────────────────────────────────────────
from Crypto.PublicKey import RSA as CustomRSAKeyModule  # alias


def generate_with_alias():
    # Statically visible 1024-bit key size
    return CustomRSAKeyModule.generate(1024)


def generate_modern_rsa():
    # Statically visible 4096-bit key size
    return CustomRSAKeyModule.generate(4096)


def generate_runtime_param(dynamic_size: int):
    # Ambiguous / runtime key size
    return CustomRSAKeyModule.generate(dynamic_size)
