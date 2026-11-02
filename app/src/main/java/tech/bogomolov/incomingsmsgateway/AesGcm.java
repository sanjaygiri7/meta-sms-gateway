package tech.bogomolov.incomingsmsgateway;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * AES-256-GCM with a fresh random IV per encryption. Pure Java, JVM-testable.
 *
 * <p>Wire format: 12-byte IV || ciphertext+tag. The key itself lives in the
 * Android Keystore (see {@link SecureStore}); this class never stores a key.
 */
public final class AesGcm {

    static final int IV_BYTES = 12;
    static final int TAG_BITS = 128;

    private AesGcm() {
    }

    public static byte[] encrypt(SecretKey key, byte[] plaintext) {
        try {
            byte[] iv = new byte[IV_BYTES];
            new SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintext);
            byte[] out = new byte[IV_BYTES + ciphertext.length];
            System.arraycopy(iv, 0, out, 0, IV_BYTES);
            System.arraycopy(ciphertext, 0, out, IV_BYTES, ciphertext.length);
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM encryption failed", e);
        }
    }

    public static byte[] decrypt(SecretKey key, byte[] combined) {
        try {
            if (combined == null || combined.length <= IV_BYTES) {
                throw new IllegalStateException("ciphertext too short");
            }
            byte[] iv = new byte[IV_BYTES];
            System.arraycopy(combined, 0, iv, 0, IV_BYTES);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            return cipher.doFinal(combined, IV_BYTES, combined.length - IV_BYTES);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM decryption failed", e);
        }
    }
}
