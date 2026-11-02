package tech.bogomolov.incomingsmsgateway;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/** AES-GCM round-trip, IV uniqueness and tamper resistance. */
public class AesGcmTest {

    private static SecretKey key() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        return kg.generateKey();
    }

    @Test
    public void roundTrip() throws Exception {
        SecretKey key = key();
        byte[] plain = "116018 is your Meta confirmation code.".getBytes(StandardCharsets.UTF_8);
        byte[] combined = AesGcm.encrypt(key, plain);
        assertArrayEquals(plain, AesGcm.decrypt(key, combined));
    }

    @Test
    public void ivIsFreshEveryTime() throws Exception {
        SecretKey key = key();
        byte[] plain = "same".getBytes(StandardCharsets.UTF_8);
        byte[] a = AesGcm.encrypt(key, plain);
        byte[] b = AesGcm.encrypt(key, plain);
        assertFalse(Arrays.equals(a, b));
        assertFalse(Arrays.equals(
                Arrays.copyOfRange(a, 0, 12), Arrays.copyOfRange(b, 0, 12)));
    }

    @Test
    public void ciphertextDoesNotContainPlaintext() throws Exception {
        SecretKey key = key();
        byte[] combined = AesGcm.encrypt(key,
                "116018 is your Meta confirmation code.".getBytes(StandardCharsets.UTF_8));
        String encoded = java.util.Base64.getEncoder().encodeToString(combined);
        assertFalse(encoded.contains("116018"));
        assertFalse(encoded.contains("Meta"));
    }

    @Test
    public void tamperedCiphertextFails() throws Exception {
        SecretKey key = key();
        byte[] combined = AesGcm.encrypt(key, "hello".getBytes(StandardCharsets.UTF_8));
        combined[combined.length - 1] ^= 0x01;
        try {
            AesGcm.decrypt(key, combined);
            fail("tampered ciphertext must fail authentication");
        } catch (IllegalStateException expected) {
            assertTrue(expected.getMessage().contains("decryption"));
        }
    }

    @Test
    public void wrongKeyFails() throws Exception {
        byte[] combined = AesGcm.encrypt(key(), "hello".getBytes(StandardCharsets.UTF_8));
        try {
            AesGcm.decrypt(key(), combined);
            fail("wrong key must fail");
        } catch (IllegalStateException expected) {
            // Expected.
        }
    }
}
