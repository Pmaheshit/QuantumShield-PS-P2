/*
 * tests/fixtures/snippet_aes.c
 * Mock C source file with OpenSSL cryptographic API usage patterns.
 * Covers RSA, ECDSA, AES-128, AES-256, SHA-256.
 * Used as a positive-detection fixture for PS-P2 scanner tests.
 */

#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

/* ── RSA (HIGH risk) ──────────────────────────────────────────────────────── */

RSA *generate_rsa_key(void) {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    return rsa;
}

EVP_PKEY *wrap_rsa_in_evp(RSA *rsa) {
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
    /* EVP_PKEY_RSA type constant used for type checks */
    if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA) {
        return pkey;
    }
    return NULL;
}

/* ── ECDSA (HIGH risk) ────────────────────────────────────────────────────── */

EC_KEY *generate_ec_key(void) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(key);
    return key;
}

int sign_with_ecdsa(EC_KEY *key, const unsigned char *digest, int dlen,
                    unsigned char *sig, unsigned int *siglen) {
    return ECDSA_sign(0, digest, dlen, sig, siglen, key);
}

/* ── AES-128 (MODERATE risk) ─────────────────────────────────────────────── */

int encrypt_aes128_cbc(const unsigned char *plaintext, int plen,
                       const unsigned char *key,   /* 16-byte / 128-bit */
                       const unsigned char *iv,
                       unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, clen;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plen);
    clen = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    clen += len;
    EVP_CIPHER_CTX_free(ctx);
    return clen;
}

/* ── AES-256 (LOWER risk) ────────────────────────────────────────────────── */

int encrypt_aes256_gcm(const unsigned char *plaintext, int plen,
                       const unsigned char *key,   /* 32-byte / 256-bit */
                       const unsigned char *iv,
                       unsigned char *ciphertext,
                       unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, clen;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plen);
    clen = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    clen += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    return clen;
}

/* ── SHA-256 (LOWER risk) ────────────────────────────────────────────────── */

void compute_sha256(const unsigned char *data, size_t len,
                    unsigned char *out_digest) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(out_digest, &ctx);
    /* alternative EVP path */
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mctx, data, len);
    unsigned int dlen = SHA256_DIGEST_LENGTH;
    EVP_DigestFinal_ex(mctx, out_digest, &dlen);
    EVP_MD_CTX_free(mctx);
}
