"""
src/scanner/risk_classifier.py
───────────────────────────────
Maps a detected algorithm name to a quantum-risk level and a recommended
post-quantum replacement, following the exact taxonomy specified in PS-P2:

  RSA / Elliptic-Curve  →  HIGH     (broken by Shor's algorithm)
  AES-128               →  MODERATE (key space halved by Grover's algorithm)
  AES-256 / SHA-256     →  LOWER    (Grover's impact marginal at this size)

Reference: Problem_Statment_Details.pdf, Page 14–15 (PS-P2 baseline task).
"""

from __future__ import annotations

from dataclasses import dataclass


# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

class RiskLevel:
    """String constants for risk levels.  Using a class avoids an Enum
    so the values serialise cleanly to JSON without extra converters."""

    HIGH     = "HIGH"
    MODERATE = "MODERATE"
    LOWER    = "LOWER"
    UNKNOWN  = "UNKNOWN"


@dataclass(frozen=True)
class RiskProfile:
    """Immutable risk assessment for one algorithm."""
    algorithm:   str
    level:       str   # one of RiskLevel.*
    reason:      str   # plain-English quantum threat rationale
    replacement: str   # recommended PQC primitive


# ──────────────────────────────────────────────────────────────────────────────
# Taxonomy (verbatim from PS-P2 spec)
# ──────────────────────────────────────────────────────────────────────────────

_PROFILES: dict[str, RiskProfile] = {
    # ── HIGH-risk (Shor's algorithm) ──────────────────────────────────────────
    "RSA": RiskProfile(
        algorithm="RSA",
        level=RiskLevel.HIGH,
        reason="Shor's algorithm factors RSA moduli in polynomial time on a CRQC.",
        replacement="ML-KEM (key encapsulation) or ML-DSA (signatures)",
    ),
    "ECDSA": RiskProfile(
        algorithm="ECDSA",
        level=RiskLevel.HIGH,
        reason="Shor's algorithm solves the elliptic-curve discrete-log problem.",
        replacement="ML-DSA (FIPS 204) for signatures",
    ),
    "ECDH": RiskProfile(
        algorithm="ECDH",
        level=RiskLevel.HIGH,
        reason="Shor's algorithm solves the elliptic-curve discrete-log problem.",
        replacement="ML-KEM (FIPS 203) for key exchange",
    ),
    "ECC": RiskProfile(
        algorithm="ECC",
        level=RiskLevel.HIGH,
        reason="Shor's algorithm solves the elliptic-curve discrete-log problem.",
        replacement="ML-KEM (FIPS 203) or ML-DSA (FIPS 204)",
    ),

    # ── MODERATE-risk (Grover's algorithm) ───────────────────────────────────
    "AES-128": RiskProfile(
        algorithm="AES-128",
        level=RiskLevel.MODERATE,
        reason=(
            "Grover's algorithm provides a quadratic speedup, effectively reducing "
            "128-bit security to ~64-bit – below the 128-bit post-quantum security target."
        ),
        replacement="Upgrade to AES-256",
    ),

    # ── LOWER-risk (Grover's impact marginal) ────────────────────────────────
    "AES-256": RiskProfile(
        algorithm="AES-256",
        level=RiskLevel.LOWER,
        reason=(
            "Grover's quadratic speedup reduces 256-bit security to ~128-bit, "
            "which still meets post-quantum security targets."
        ),
        replacement="No change required; AES-256 is quantum-safe at current security levels",
    ),
    "SHA-256": RiskProfile(
        algorithm="SHA-256",
        level=RiskLevel.LOWER,
        reason=(
            "Grover's algorithm reduces collision-resistance to ~128-bit, "
            "which is acceptable for most use cases."
        ),
        replacement="No change required; SHA-256 remains acceptable post-quantum",
    ),
    "SHA-384": RiskProfile(
        algorithm="SHA-384",
        level=RiskLevel.LOWER,
        reason="Grover's speedup still leaves >128-bit security.",
        replacement="No change required",
    ),
    "SHA-512": RiskProfile(
        algorithm="SHA-512",
        level=RiskLevel.LOWER,
        reason="Grover's speedup still leaves >128-bit security.",
        replacement="No change required",
    ),
}

# Aliases: normalised algorithm name → canonical key into _PROFILES
_ALIASES: dict[str, str] = {
    # RSA variants
    "rsa":                 "RSA",
    # ECDSA / EC variants
    "ecdsa":               "ECDSA",
    "ecdh":                "ECDH",
    "ec":                  "ECDSA",
    "ecc":                 "ECC",
    "elliptic-curve":      "ECC",
    "elliptic curve":      "ECC",
    # AES
    "aes-128":             "AES-128",
    "aes128":              "AES-128",
    "aes_128":             "AES-128",
    "aes-256":             "AES-256",
    "aes256":              "AES-256",
    "aes_256":             "AES-256",
    # SHA
    "sha-256":             "SHA-256",
    "sha256":              "SHA-256",
    "sha_256":             "SHA-256",
    "sha-384":             "SHA-384",
    "sha384":              "SHA-384",
    "sha-512":             "SHA-512",
    "sha512":              "SHA-512",
}

# Default profile for unrecognised algorithms
_UNKNOWN_PROFILE = RiskProfile(
    algorithm="UNKNOWN",
    level=RiskLevel.UNKNOWN,
    reason="Algorithm not in PS-P2 taxonomy; manual review required.",
    replacement="Manual review required",
)


# ──────────────────────────────────────────────────────────────────────────────
# Classifier
# ──────────────────────────────────────────────────────────────────────────────

class RiskClassifier:
    """Classifies a detected algorithm name into a PS-P2 risk profile."""

    def classify(self, algorithm: str, purpose: Optional[str] = None) -> RiskProfile:
        """
        Return the :class:`RiskProfile` for *algorithm*.

        Lookup is case-insensitive.  Unknown algorithms return
        ``RiskLevel.UNKNOWN`` rather than raising.

        Parameters
        ----------
        algorithm : str
            The cryptographic algorithm name.
        purpose : str | None
            Optional usage context: "encapsulation" / "key_exchange" / "encryption"
            vs "signature" / "signing". When specified for RSA/ECC, generates a
            purpose-specific recommendation (ML-KEM vs ML-DSA).
        """
        key = algorithm.strip()
        # 1. Direct lookup (case-insensitive)
        profile = _PROFILES.get(key) or _PROFILES.get(key.upper())
        if not profile:
            # 2. Alias lookup
            canonical = _ALIASES.get(key.lower())
            if canonical:
                profile = _PROFILES.get(canonical)

        if not profile:
            return _UNKNOWN_PROFILE

        # Refine recommendation based on purpose when applicable
        if purpose:
            p_lower = purpose.lower()
            if profile.algorithm in ("RSA", "ECC"):
                if any(k in p_lower for k in ("sign", "signature", "verify")):
                    return RiskProfile(
                        algorithm=profile.algorithm,
                        level=profile.level,
                        reason=profile.reason,
                        replacement="ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for digital signatures",
                    )
                elif any(k in p_lower for k in ("encaps", "kem", "exchange", "encrypt", "cipher", "oaep")):
                    return RiskProfile(
                        algorithm=profile.algorithm,
                        level=profile.level,
                        reason=profile.reason,
                        replacement="ML-KEM (FIPS 203) for key establishment / encapsulation",
                    )

        return profile

    def all_profiles(self) -> list[RiskProfile]:
        """Return all defined risk profiles (useful for documentation)."""
        return list(_PROFILES.values())

    def get_profile(self, algorithm: str, purpose: Optional[str] = None) -> RiskProfile:
        """Alias for classify()."""
        return self.classify(algorithm, purpose=purpose)


