# QuantumShield — Cryptographic Inventory & Migration Report

**Generated:** `2026-10-16T16:36:40.397799+00:00`<br>
**Target Directory:** `C:\Users\DINESHBABU\QuantumShield-PS-P2\tests\fixtures`<br>
**Files Discovered:** 7<br>
**Files Scanned:** 7<br>
**Files Failed:** 0<br>
**Files Skipped:** 0<br>
**Total Cryptographic Findings:** 47

## 1. Executive Summary

| Risk Level | Count | Threat Rationale | Migration Priority |
| :--- | :---: | :--- | :--- |
| 🔴 **HIGH** | 25 | RSA/ECC operations may be exposed to Shor's algorithm; API matches do not establish system-level exposure. | Prioritize operation review |
| 🟡 **MODERATE** | 4 | Key space halved by Grover's Algorithm (AES-128) | Medium (Upgrade to AES-256) |
| 🟢 **LOWER** | 15 | Quantum-resistant symmetric baseline (AES-256, SHA-256) | Low / Retain current baseline |
| ⚪ **UNKNOWN** | 3 | Unresolved algorithm or key size, or unparseable source element | Requires manual review |

## 2. Findings Breakdown

### By Language

| Language | Detected Findings |
| :--- | :---: |
| `c` | 12 |
| `java` | 12 |
| `python` | 23 |

### By Algorithm

| Algorithm | Risk Level | Findings Count | Recommended Replacement |
| :--- | :--- | :---: | :--- |
| **AES-128** | `MODERATE` | 4 | Upgrade to AES-256 |
| **AES-256** | `LOWER` | 4 | No change required; AES-256 is quantum-safe at current security levels |
| **AES-UNKNOWN** | `UNKNOWN` | 3 | Determine the AES key size before assigning a risk level |
| **ECC** | `HIGH` | 5 | Choose ML-KEM (FIPS 203) for key establishment or ML-DSA (FIPS 204) for signatures based on the actual use |
| **ECDH** | `HIGH` | 2 | ML-KEM (FIPS 203) for key exchange |
| **ECDSA** | `HIGH` | 3 | ML-DSA (FIPS 204) for signatures |
| **RSA** | `HIGH` | 15 | ML-KEM (key encapsulation) or ML-DSA (signatures) |
| **SHA-256** | `LOWER` | 11 | No change required; SHA-256 remains acceptable post-quantum |

## 3. Inventory Details

| # | Location | Language | Algorithm | Risk | Detection | Confidence | Replacement / Action |
| -: | :--- | :---: | :--- | :---: | :---: | :---: | :--- |
| 1 | `snippet_aes.c:18` | `c` | **RSA** | `HIGH` | `regex` | `INFERRED` | ML-KEM (key encapsulation) or ML-DSA (signatures) |
| 2 | `snippet_aes.c:21` | `c` | **RSA** | `HIGH` | `regex` | `INFERRED` | ML-KEM (key encapsulation) or ML-DSA (signatures) |
| 3 | `snippet_aes.c:29` | `c` | **RSA** | `HIGH` | `regex` | `INFERRED` | ML-KEM (key encapsulation) or ML-DSA (signatures) |
| 4 | `snippet_aes.c:38` | `c` | **ECC** | `HIGH` | `regex` | `INFERRED` | Choose ML-KEM (FIPS 203) for key establishment or ML-DSA (FIPS 204) for signatures based on the actual use |
| 5 | `snippet_aes.c:45` | `c` | **ECDSA** | `HIGH` | `regex` | `INFERRED` | ML-DSA (FIPS 204) for signatures |
| 6 | `snippet_aes.c:56` | `c` | **AES-128** | `MODERATE` | `regex` | `INFERRED` | Upgrade to AES-256 |
| 7 | `snippet_aes.c:74` | `c` | **AES-256** | `LOWER` | `regex` | `INFERRED` | No change required; AES-256 is quantum-safe at current security levels |
| 8 | `snippet_aes.c:90` | `c` | **SHA-256** | `LOWER` | `regex` | `INFERRED` | No change required; SHA-256 remains acceptable post-quantum |
| 9 | `snippet_aes.c:91` | `c` | **SHA-256** | `LOWER` | `regex` | `INFERRED` | No change required; SHA-256 remains acceptable post-quantum |
| 10 | `snippet_aes.c:92` | `c` | **SHA-256** | `LOWER` | `regex` | `INFERRED` | No change required; SHA-256 remains acceptable post-quantum |
| 11 | `snippet_aes.c:95` | `c` | **SHA-256** | `LOWER` | `regex` | `INFERRED` | No change required; SHA-256 remains acceptable post-quantum |
| 12 | `snippet_aes.c:97` | `c` | **SHA-256** | `LOWER` | `regex` | `INFERRED` | No change required; SHA-256 remains acceptable post-quantum |
| 13 | `snippet_aes.py:15` | `python` | **AES-128** | `MODERATE` | `ast` | `CONFIRMED` | Upgrade to AES-256 |
| 14 | `snippet_aes.py:32` | `python` | **AES-256** | `LOWER` | `ast` | `CONFIRMED` | No change required; AES-256 is quantum-safe at current security levels |
| 15 | `snippet_aes.py:43` | `python` | **SHA-256** | `LOWER` | `ast` | `CONFIRMED` | No change required; SHA-256 remains acceptable post-quantum |
| 16 | `snippet_aes.py:48` | `python` | **SHA-256** | `LOWER` | `ast` | `CONFIRMED` | No change required; SHA-256 remains acceptable post-quantum |
| 17 | `snippet_aes.py:14` | `python` | **AES-128** | `MODERATE` | `regex` | `INFERRED` | Upgrade to AES-256 |
| 18 | `snippet_aes.py:31` | `python` | **AES-256** | `LOWER` | `regex` | `INFERRED` | No change required; AES-256 is quantum-safe at current security levels |
| 19 | `snippet_ecc.py:12` | `python` | **ECC** | `HIGH` | `ast` | `CONFIRMED` | Choose ML-KEM (FIPS 203) for key establishment or ML-DSA (FIPS 204) for signatures based on the actual use |
| 20 | `snippet_ecc.py:18` | `python` | **ECDSA** | `HIGH` | `ast` | `CONFIRMED` | ML-DSA (FIPS 204) for signatures |
| 21 | `snippet_ecc.py:18` | `python` | **SHA-256** | `LOWER` | `ast` | `CONFIRMED` | No change required; SHA-256 remains acceptable post-quantum |
| 22 | `snippet_ecc.py:23` | `python` | **ECDH** | `HIGH` | `ast` | `CONFIRMED` | ML-KEM (FIPS 203) for key exchange |
| 23 | `snippet_ecc.py:32` | `python` | **ECC** | `HIGH` | `ast` | `CONFIRMED` | Choose ML-KEM (FIPS 203) for key establishment or ML-DSA (FIPS 204) for signatures based on the actual use |
| 24 | `snippet_ecdsa.java:15` | `java` | **RSA** | `HIGH` | `regex` | `INFERRED` | ML-KEM (key encapsulation) or ML-DSA (signatures) |
| 25 | `snippet_ecdsa.java:22` | `java` | **RSA** | `HIGH` | `regex` | `INFERRED` | ML-KEM (FIPS 203) for key establishment / encapsulation |
| 26 | `snippet_ecdsa.java:29` | `java` | **ECC** | `HIGH` | `regex` | `INFERRED` | Choose ML-KEM (FIPS 203) for key establishment or ML-DSA (FIPS 204) for signatures based on the actual use |
| 27 | `snippet_ecdsa.java:30` | `java` | **ECC** | `HIGH` | `regex` | `INFERRED` | Choose ML-KEM (FIPS 203) for key establishment or ML-DSA (FIPS 204) for signatures based on the actual use |
| 28 | `snippet_ecdsa.java:37` | `java` | **ECDSA** | `HIGH` | `regex` | `INFERRED` | ML-DSA (FIPS 204) for signatures |
| 29 | `snippet_ecdsa.java:46` | `java` | **ECDH** | `HIGH` | `regex` | `INFERRED` | ML-KEM (FIPS 203) for key exchange |
| 30 | `snippet_ecdsa.java:54` | `java` | **AES-UNKNOWN** | `UNKNOWN` | `regex` | `INFERRED` | Determine the AES key size before assigning a risk level |
| 31 | `snippet_ecdsa.java:55` | `java` | **AES-128** | `MODERATE` | `regex` | `INFERRED` | Upgrade to AES-256 |
| 32 | `snippet_ecdsa.java:61` | `java` | **AES-UNKNOWN** | `UNKNOWN` | `regex` | `INFERRED` | Determine the AES key size before assigning a risk level |
| 33 | `snippet_ecdsa.java:69` | `java` | **AES-UNKNOWN** | `UNKNOWN` | `regex` | `INFERRED` | Determine the AES key size before assigning a risk level |
| 34 | `snippet_ecdsa.java:70` | `java` | **AES-256** | `LOWER` | `regex` | `INFERRED` | No change required; AES-256 is quantum-safe at current security levels |
| 35 | `snippet_ecdsa.java:77` | `java` | **SHA-256** | `LOWER` | `regex` | `INFERRED` | No change required; SHA-256 remains acceptable post-quantum |
| 36 | `snippet_edge_cases.py:32` | `python` | **RSA** | `HIGH` | `ast` | `CONFIRMED` | ML-KEM (key encapsulation) or ML-DSA (signatures) |
| 37 | `snippet_edge_cases.py:37` | `python` | **RSA** | `HIGH` | `ast` | `CONFIRMED` | ML-KEM (key encapsulation) or ML-DSA (signatures) |
| 38 | `snippet_edge_cases.py:42` | `python` | **RSA** | `HIGH` | `ast` | `UNKNOWN` | ML-KEM (key encapsulation) or ML-DSA (signatures) |
| 39 | `snippet_edge_cases.py:27` | `python` | **RSA** | `HIGH` | `regex` | `INFERRED` | ML-KEM (key encapsulation) or ML-DSA (signatures) |
| 40 | `snippet_rsa.py:13` | `python` | **RSA** | `HIGH` | `ast` | `UNKNOWN` | ML-KEM (key encapsulation) or ML-DSA (signatures) |
| 41 | `snippet_rsa.py:26` | `python` | **SHA-256** | `LOWER` | `ast` | `CONFIRMED` | No change required; SHA-256 remains acceptable post-quantum |
| 42 | `snippet_rsa.py:29` | `python` | **SHA-256** | `LOWER` | `ast` | `CONFIRMED` | No change required; SHA-256 remains acceptable post-quantum |
| 43 | `snippet_rsa.py:39` | `python` | **RSA** | `HIGH` | `ast` | `CONFIRMED` | ML-KEM (key encapsulation) or ML-DSA (signatures) |
| 44 | `snippet_rsa.py:41` | `python` | **RSA** | `HIGH` | `ast` | `CONFIRMED` | ML-KEM (FIPS 203) for key establishment / encapsulation |
| 45 | `snippet_rsa.py:48` | `python` | **RSA** | `HIGH` | `ast` | `CONFIRMED` | ML-KEM (key encapsulation) or ML-DSA (signatures) |
| 46 | `snippet_rsa.py:8` | `python` | **RSA** | `HIGH` | `regex` | `INFERRED` | ML-KEM (key encapsulation) or ML-DSA (signatures) |
| 47 | `snippet_rsa.py:35` | `python` | **RSA** | `HIGH` | `regex` | `INFERRED` | ML-KEM (key encapsulation) or ML-DSA (signatures) |

### Evidence & Code Context

#### Finding #1: RSA in `snippet_aes.c:18`
- **Matched API:** `RSA_new`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
RSA *rsa = RSA_new();
```
- **Migration Recommendation:** ML-KEM (key encapsulation) or ML-DSA (signatures)

#### Finding #2: RSA in `snippet_aes.c:21`
- **Matched API:** `RSA_generate_key_ex`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
RSA_generate_key_ex(rsa, 2048, e, NULL);
```
- **Migration Recommendation:** ML-KEM (key encapsulation) or ML-DSA (signatures)

#### Finding #3: RSA in `snippet_aes.c:29`
- **Matched API:** `EVP_PKEY_RSA`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA) {
```
- **Migration Recommendation:** ML-KEM (key encapsulation) or ML-DSA (signatures)

#### Finding #4: ECC in `snippet_aes.c:38`
- **Matched API:** `EC_KEY_new_by_curve_name`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
```
- **Migration Recommendation:** Choose ML-KEM (FIPS 203) for key establishment or ML-DSA (FIPS 204) for signatures based on the actual use

#### Finding #5: ECDSA in `snippet_aes.c:45`
- **Matched API:** `ECDSA_sign`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
return ECDSA_sign(0, digest, dlen, sig, siglen, key);
```
- **Migration Recommendation:** ML-DSA (FIPS 204) for signatures

#### Finding #6: AES-128 in `snippet_aes.c:56`
- **Matched API:** `EVP_aes_128_cbc`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
```
- **Migration Recommendation:** Upgrade to AES-256

#### Finding #7: AES-256 in `snippet_aes.c:74`
- **Matched API:** `EVP_aes_256_gcm`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
```
- **Migration Recommendation:** No change required; AES-256 is quantum-safe at current security levels

#### Finding #8: SHA-256 in `snippet_aes.c:90`
- **Matched API:** `SHA256_Init`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
SHA256_Init(&ctx);
```
- **Migration Recommendation:** No change required; SHA-256 remains acceptable post-quantum

#### Finding #9: SHA-256 in `snippet_aes.c:91`
- **Matched API:** `SHA256_Update`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
SHA256_Update(&ctx, data, len);
```
- **Migration Recommendation:** No change required; SHA-256 remains acceptable post-quantum

#### Finding #10: SHA-256 in `snippet_aes.c:92`
- **Matched API:** `SHA256_Final`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
SHA256_Final(out_digest, &ctx);
```
- **Migration Recommendation:** No change required; SHA-256 remains acceptable post-quantum

#### Finding #11: SHA-256 in `snippet_aes.c:95`
- **Matched API:** `EVP_sha256`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
EVP_DigestInit_ex(mctx, EVP_sha256(), NULL);
```
- **Migration Recommendation:** No change required; SHA-256 remains acceptable post-quantum

#### Finding #12: SHA-256 in `snippet_aes.c:97`
- **Matched API:** `SHA256_DIGEST_LENGTH`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
unsigned int dlen = SHA256_DIGEST_LENGTH;
```
- **Migration Recommendation:** No change required; SHA-256 remains acceptable post-quantum

#### Finding #13: AES-128 in `snippet_aes.py:15`
- **Matched API:** `AES.new`
- **Detection Method:** `ast` (Confidence: `CONFIRMED`)
- **Static Key Size:** 128 bits
- **Analysis Note:** AES cipher construction with 128-bit key
- **Evidence Snippet:**
```
cipher = AES.new(key, AES.MODE_GCM)
```
- **Migration Recommendation:** Upgrade to AES-256

#### Finding #14: AES-256 in `snippet_aes.py:32`
- **Matched API:** `AES.new`
- **Detection Method:** `ast` (Confidence: `CONFIRMED`)
- **Static Key Size:** 256 bits
- **Analysis Note:** AES cipher construction with 256-bit key
- **Evidence Snippet:**
```
cipher = AES.new(key, AES.MODE_GCM)
```
- **Migration Recommendation:** No change required; AES-256 is quantum-safe at current security levels

#### Finding #15: SHA-256 in `snippet_aes.py:43`
- **Matched API:** `hashlib.sha256`
- **Detection Method:** `ast` (Confidence: `CONFIRMED`)
- **Analysis Note:** SHA-256 cryptographic hash function invocation
- **Evidence Snippet:**
```
digest = hashlib.sha256(data).hexdigest()
```
- **Migration Recommendation:** No change required; SHA-256 remains acceptable post-quantum

#### Finding #16: SHA-256 in `snippet_aes.py:48`
- **Matched API:** `hashlib.new('sha256')`
- **Detection Method:** `ast` (Confidence: `CONFIRMED`)
- **Analysis Note:** hashlib.new with SHA-256 digest
- **Evidence Snippet:**
```
h = hashlib.new("sha256")
```
- **Migration Recommendation:** No change required; SHA-256 remains acceptable post-quantum

#### Finding #17: AES-128 in `snippet_aes.py:14`
- **Matched API:** `get_random_bytes(16)`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
key = get_random_bytes(16)          # 16 bytes = 128 bits
```
- **Migration Recommendation:** Upgrade to AES-256

#### Finding #18: AES-256 in `snippet_aes.py:31`
- **Matched API:** `get_random_bytes(32)`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
key = get_random_bytes(32)          # 32 bytes = 256 bits
```
- **Migration Recommendation:** No change required; AES-256 is quantum-safe at current security levels

#### Finding #19: ECC in `snippet_ecc.py:12`
- **Matched API:** `ec.generate_private_key`
- **Detection Method:** `ast` (Confidence: `CONFIRMED`)
- **Elliptic Curve:** `SECP256R1`
- **Analysis Note:** EC key pair generation with curve SECP256R1
- **Evidence Snippet:**
```
private_key = ec.generate_private_key(ec.SECP256R1())
```
- **Migration Recommendation:** Choose ML-KEM (FIPS 203) for key establishment or ML-DSA (FIPS 204) for signatures based on the actual use

#### Finding #20: ECDSA in `snippet_ecc.py:18`
- **Matched API:** `ec.ECDSA`
- **Detection Method:** `ast` (Confidence: `CONFIRMED`)
- **Analysis Note:** Elliptic Curve Digital Signature Algorithm (ECDSA) primitive invocation
- **Evidence Snippet:**
```
return private_key.sign(message, ec.ECDSA(hashes.SHA256()))
```
- **Migration Recommendation:** ML-DSA (FIPS 204) for signatures

#### Finding #21: SHA-256 in `snippet_ecc.py:18`
- **Matched API:** `cryptography.hazmat.primitives.hashes.SHA256`
- **Detection Method:** `ast` (Confidence: `CONFIRMED`)
- **Analysis Note:** SHA-256 cryptographic hash function invocation
- **Evidence Snippet:**
```
return private_key.sign(message, ec.ECDSA(hashes.SHA256()))
```
- **Migration Recommendation:** No change required; SHA-256 remains acceptable post-quantum

#### Finding #22: ECDH in `snippet_ecc.py:23`
- **Matched API:** `ec.ECDH`
- **Detection Method:** `ast` (Confidence: `CONFIRMED`)
- **Analysis Note:** Elliptic Curve Diffie-Hellman (ECDH) key exchange invocation
- **Evidence Snippet:**
```
shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
```
- **Migration Recommendation:** ML-KEM (FIPS 203) for key exchange

#### Finding #23: ECC in `snippet_ecc.py:32`
- **Matched API:** `ECC.generate`
- **Detection Method:** `ast` (Confidence: `CONFIRMED`)
- **Elliptic Curve:** `P-256`
- **Analysis Note:** PyCryptodome ECC.generate with curve P-256
- **Evidence Snippet:**
```
key = ECC.generate(curve="P-256")
```
- **Migration Recommendation:** Choose ML-KEM (FIPS 203) for key establishment or ML-DSA (FIPS 204) for signatures based on the actual use

#### Finding #24: RSA in `snippet_ecdsa.java:15`
- **Matched API:** `RSA`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
```
- **Migration Recommendation:** ML-KEM (key encapsulation) or ML-DSA (signatures)

#### Finding #25: RSA in `snippet_ecdsa.java:22`
- **Matched API:** `RSA`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
```
- **Migration Recommendation:** ML-KEM (FIPS 203) for key establishment / encapsulation

#### Finding #26: ECC in `snippet_ecdsa.java:29`
- **Matched API:** `EC`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
```
- **Migration Recommendation:** Choose ML-KEM (FIPS 203) for key establishment or ML-DSA (FIPS 204) for signatures based on the actual use

#### Finding #27: ECC in `snippet_ecdsa.java:30`
- **Matched API:** `ECGenParameterSpec`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
```
- **Migration Recommendation:** Choose ML-KEM (FIPS 203) for key establishment or ML-DSA (FIPS 204) for signatures based on the actual use

#### Finding #28: ECDSA in `snippet_ecdsa.java:37`
- **Matched API:** `SHA256withECDSA`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
Signature sig = Signature.getInstance("SHA256withECDSA");
```
- **Migration Recommendation:** ML-DSA (FIPS 204) for signatures

#### Finding #29: ECDH in `snippet_ecdsa.java:46`
- **Matched API:** `ECDH`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
KeyAgreement ka = KeyAgreement.getInstance("ECDH");
```
- **Migration Recommendation:** ML-KEM (FIPS 203) for key exchange

#### Finding #30: AES-UNKNOWN in `snippet_ecdsa.java:54`
- **Matched API:** `AES`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
```
- **Migration Recommendation:** Determine the AES key size before assigning a risk level

#### Finding #31: AES-128 in `snippet_ecdsa.java:55`
- **Matched API:** `128`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
keyGenerator.init(128);          // 128-bit key
```
- **Migration Recommendation:** Upgrade to AES-256

#### Finding #32: AES-UNKNOWN in `snippet_ecdsa.java:61`
- **Matched API:** `AES`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
```
- **Migration Recommendation:** Determine the AES key size before assigning a risk level

#### Finding #33: AES-UNKNOWN in `snippet_ecdsa.java:69`
- **Matched API:** `AES`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
```
- **Migration Recommendation:** Determine the AES key size before assigning a risk level

#### Finding #34: AES-256 in `snippet_ecdsa.java:70`
- **Matched API:** `256`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
keyGenerator.init(256);          // 256-bit key
```
- **Migration Recommendation:** No change required; AES-256 is quantum-safe at current security levels

#### Finding #35: SHA-256 in `snippet_ecdsa.java:77`
- **Matched API:** `SHA-256`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
MessageDigest md = MessageDigest.getInstance("SHA-256");
```
- **Migration Recommendation:** No change required; SHA-256 remains acceptable post-quantum

#### Finding #36: RSA in `snippet_edge_cases.py:32`
- **Matched API:** `RSA.generate`
- **Detection Method:** `ast` (Confidence: `CONFIRMED`)
- **Static Key Size:** 1024 bits
- **Analysis Note:** PyCryptodome RSA.generate with key size 1024 bits
- **Evidence Snippet:**
```
return CustomRSAKeyModule.generate(1024)
```
- **Migration Recommendation:** ML-KEM (key encapsulation) or ML-DSA (signatures)

#### Finding #37: RSA in `snippet_edge_cases.py:37`
- **Matched API:** `RSA.generate`
- **Detection Method:** `ast` (Confidence: `CONFIRMED`)
- **Static Key Size:** 4096 bits
- **Analysis Note:** PyCryptodome RSA.generate with key size 4096 bits
- **Evidence Snippet:**
```
return CustomRSAKeyModule.generate(4096)
```
- **Migration Recommendation:** ML-KEM (key encapsulation) or ML-DSA (signatures)

#### Finding #38: RSA in `snippet_edge_cases.py:42`
- **Matched API:** `RSA.generate`
- **Detection Method:** `ast` (Confidence: `UNKNOWN`)
- **Analysis Note:** PyCryptodome RSA.generate with key size UNKNOWN bits
- **Evidence Snippet:**
```
return CustomRSAKeyModule.generate(dynamic_size)
```
- **Migration Recommendation:** ML-KEM (key encapsulation) or ML-DSA (signatures)

#### Finding #39: RSA in `snippet_edge_cases.py:27`
- **Matched API:** `from Crypto.PublicKey import RSA`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
from Crypto.PublicKey import RSA as CustomRSAKeyModule  # alias
```
- **Migration Recommendation:** ML-KEM (key encapsulation) or ML-DSA (signatures)

#### Finding #40: RSA in `snippet_rsa.py:13`
- **Matched API:** `rsa.generate_private_key`
- **Detection Method:** `ast` (Confidence: `UNKNOWN`)
- **Analysis Note:** RSA private key generation with key size UNKNOWN bits
- **Evidence Snippet:**
```
private_key = rsa.generate_private_key(
```
- **Migration Recommendation:** ML-KEM (key encapsulation) or ML-DSA (signatures)

#### Finding #41: SHA-256 in `snippet_rsa.py:26`
- **Matched API:** `cryptography.hazmat.primitives.hashes.SHA256`
- **Detection Method:** `ast` (Confidence: `CONFIRMED`)
- **Analysis Note:** SHA-256 cryptographic hash function invocation
- **Evidence Snippet:**
```
mgf=padding.MGF1(hashes.SHA256()),
```
- **Migration Recommendation:** No change required; SHA-256 remains acceptable post-quantum

#### Finding #42: SHA-256 in `snippet_rsa.py:29`
- **Matched API:** `cryptography.hazmat.primitives.hashes.SHA256`
- **Detection Method:** `ast` (Confidence: `CONFIRMED`)
- **Analysis Note:** SHA-256 cryptographic hash function invocation
- **Evidence Snippet:**
```
hashes.SHA256(),
```
- **Migration Recommendation:** No change required; SHA-256 remains acceptable post-quantum

#### Finding #43: RSA in `snippet_rsa.py:39`
- **Matched API:** `RSA.generate`
- **Detection Method:** `ast` (Confidence: `CONFIRMED`)
- **Static Key Size:** 2048 bits
- **Analysis Note:** PyCryptodome RSA.generate with key size 2048 bits
- **Evidence Snippet:**
```
key = _RSA.generate(2048)
```
- **Migration Recommendation:** ML-KEM (key encapsulation) or ML-DSA (signatures)

#### Finding #44: RSA in `snippet_rsa.py:41`
- **Matched API:** `PKCS1_OAEP.new`
- **Detection Method:** `ast` (Confidence: `CONFIRMED`)
- **Analysis Note:** RSA-OAEP asymmetric encryption / key establishment
- **Evidence Snippet:**
```
cipher = PKCS1_OAEP.new(public_key)
```
- **Migration Recommendation:** ML-KEM (FIPS 203) for key establishment / encapsulation

#### Finding #45: RSA in `snippet_rsa.py:48`
- **Matched API:** `RSA.import_key`
- **Detection Method:** `ast` (Confidence: `CONFIRMED`)
- **Analysis Note:** PyCryptodome RSA.import_key invocation (imported key size determined at runtime)
- **Evidence Snippet:**
```
return _RSA.import_key(pem_data)
```
- **Migration Recommendation:** ML-KEM (key encapsulation) or ML-DSA (signatures)

#### Finding #46: RSA in `snippet_rsa.py:8`
- **Matched API:** `from cryptography.hazmat.primitives.asymmetric import rsa`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
from cryptography.hazmat.primitives.asymmetric import rsa, padding
```
- **Migration Recommendation:** ML-KEM (key encapsulation) or ML-DSA (signatures)

#### Finding #47: RSA in `snippet_rsa.py:35`
- **Matched API:** `from Crypto.PublicKey import RSA`
- **Detection Method:** `regex` (Confidence: `INFERRED`)
- **Evidence Snippet:**
```
from Crypto.PublicKey import RSA as _RSA
```
- **Migration Recommendation:** ML-KEM (key encapsulation) or ML-DSA (signatures)

## 4. Scanner Limitations & Operational Assumptions

- Static analysis only: unresolved runtime values, dynamic class loaders, or network-retrieved keys cannot be resolved; AES inference is limited to explicit sizes, known generators, and unambiguous single local assignments.
- Java and C comments are masked; string literals are preserved for algorithm parameters, so unrelated identifiers in strings may still match.
- AST scanning applies strictly to valid Python syntax; unparseable Python files report syntax error findings.
- AES findings with unresolved key lengths remain AES-UNKNOWN (UNKNOWN risk) by default; an explicitly enabled conservative AES-128 assumption is marked as assumed.
