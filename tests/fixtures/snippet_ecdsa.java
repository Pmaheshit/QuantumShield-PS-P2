/*
 * tests/fixtures/snippet_ecdsa.java
 * Mock Java source file with RSA and ECDSA usage patterns.
 * Used as a positive-detection fixture for PS-P2 scanner tests.
 */

import java.security.*;
import java.security.spec.*;
import javax.crypto.*;

class CryptoExamples {

    // ── RSA (HIGH risk) ────────────────────────────────────────────────────
    public static KeyPair generateRsaKeypair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public static byte[] encryptWithRsa(PublicKey pubKey, byte[] plaintext)
            throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return cipher.doFinal(plaintext);
    }

    // ── ECDSA (HIGH risk) ──────────────────────────────────────────────────
    public static KeyPair generateEcKeypair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        kpg.initialize(ecSpec);
        return kpg.generateKeyPair();
    }

    public static byte[] signWithEcdsa(PrivateKey privKey, byte[] data)
            throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(privKey);
        sig.update(data);
        return sig.sign();
    }

    // ── ECDH (HIGH risk) ───────────────────────────────────────────────────
    public static byte[] ecdhKeyAgreement(PrivateKey myPriv, PublicKey peerPub)
            throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(myPriv);
        ka.doPhase(peerPub, true);
        return ka.generateSecret();
    }

    // ── AES-128 (MODERATE risk) ────────────────────────────────────────────
    public static SecretKey generateAes128Key() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);          // 128-bit key
        return keyGenerator.generateKey();
    }

    public static byte[] encryptAes128(SecretKey key, byte[] plaintext)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        // AES-128 in use
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    // ── AES-256 (LOWER risk) ───────────────────────────────────────────────
    public static SecretKey generateAes256Key() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);          // 256-bit key
        return keyGenerator.generateKey();
    }

    // ── SHA-256 (LOWER risk) ───────────────────────────────────────────────
    public static byte[] hashSha256(byte[] data)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }
}
