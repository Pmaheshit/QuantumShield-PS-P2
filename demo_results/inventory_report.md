# QuantumShield — Cryptographic Inventory & Migration Report

**Generated:** `2026-10-16T16:40:49.285252+00:00`<br>
**Target Directory:** `C:\Users\DINESHBABU\QuantumShield-PS-P2\my_demo_app`<br>
**Files Discovered:** 1<br>
**Files Scanned:** 1<br>
**Files Failed:** 0<br>
**Files Skipped:** 0<br>
**Total Cryptographic Findings:** 3

## 1. Executive Summary

| Risk Level | Count | Threat Rationale | Migration Priority |
| :--- | :---: | :--- | :--- |
| 🔴 **HIGH** | 2 | RSA/ECC operations may be exposed to Shor's algorithm; API matches do not establish system-level exposure. | Prioritize operation review |
| 🟡 **MODERATE** | 0 | Key space halved by Grover's Algorithm (AES-128) | Medium (Upgrade to AES-256) |
| 🟢 **LOWER** | 1 | Quantum-resistant symmetric baseline (AES-256, SHA-256) | Low / Retain current baseline |
| ⚪ **UNKNOWN** | 0 | Unresolved algorithm or key size, or unparseable source element | Requires manual review |

## 2. Findings Breakdown

### By Language

| Language | Detected Findings |
| :--- | :---: |
| `python` | 3 |

### By Algorithm

| Algorithm | Risk Level | Findings Count | Recommended Replacement |
| :--- | :--- | :---: | :--- |
| **RSA** | `HIGH` | 2 | ML-KEM (key encapsulation) or ML-DSA (signatures) |
| **SHA-256** | `LOWER` | 1 | No change required; SHA-256 remains acceptable post-quantum |

## 3. Inventory Details

| # | Location | Language | Algorithm | Risk | Detection | Confidence | Replacement / Action |
| -: | :--- | :---: | :--- | :---: | :---: | :---: | :--- |
| 1 | `crypto_example.py:6` | `python` | **RSA** | `HIGH` | `ast` | `CONFIRMED` | ML-KEM (key encapsulation) or ML-DSA (signatures) |
| 2 | `crypto_example.py:13` | `python` | **SHA-256** | `LOWER` | `ast` | `CONFIRMED` | No change required; SHA-256 remains acceptable post-quantum |
| 3 | `crypto_example.py:3` | `python` | **RSA** | `HIGH` | `regex` | `INFERRED` | ML-KEM (key encapsulation) or ML-DSA (signatures) |

### Evidence & Code Context

#### Finding #1: RSA in `crypto_example.py:6`
- **Matched API:** `rsa.generate_private_key`
- **Detection Method:** `ast` (Confidence: `CONFIRMED`)
- **Static Key Size:** 2048 bits
- **Analysis Note:** RSA private key generation with key size 2048 bits
- **Evidence Snippet:**
```
private_key = rsa.generate_private_key(
```
- **Migration Recommendation:** ML-KEM (key encapsulation) or ML-DSA (signatures)

#### Finding #2: SHA-256 in `crypto_example.py:13`
- **Matched API:** `hashlib.sha256`
- **Detection Method:** `ast` (Confidence: `CONFIRMED`)
- **Analysis Note:** SHA-256 cryptographic hash function invocation
- **Evidence Snippet:**
```
digest = hashlib.sha256(message).hexdigest()
```
- **Migration Recommendation:** No change required; SHA-256 remains acceptable post-quantum

#### Finding #3: RSA in `crypto_example.py:3`
- **Matched API:** `from cryptography.hazmat.primitives.asymmetric import rsa`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
from cryptography.hazmat.primitives.asymmetric import rsa
```
- **Migration Recommendation:** ML-KEM (key encapsulation) or ML-DSA (signatures)

## 4. Scanner Limitations & Operational Assumptions

- Static analysis only: unresolved runtime values, dynamic class loaders, or network-retrieved keys cannot be resolved; AES inference is limited to explicit sizes, known generators, and unambiguous single local assignments.
- Java and C comments are masked; string literals are preserved for algorithm parameters, so unrelated identifiers in strings may still match.
- AST scanning applies strictly to valid Python syntax; unparseable Python files report syntax error findings.
- AES findings with unresolved key lengths remain AES-UNKNOWN (UNKNOWN risk) by default; an explicitly enabled conservative AES-128 assumption is marked as assumed.
