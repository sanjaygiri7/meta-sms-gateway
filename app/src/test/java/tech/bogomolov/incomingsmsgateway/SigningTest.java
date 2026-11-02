package tech.bogomolov.incomingsmsgateway;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

/**
 * Signing contract. The Worker test suite uses the same vectors, computed
 * independently in TypeScript, so a drift between Android and Worker signing
 * fails a test on at least one side.
 */
public class SigningTest {

    // 32-byte test secret, base64: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
    private static final byte[] SECRET = new byte[32];

    static {
        for (int i = 0; i < 32; i++) {
            SECRET[i] = (byte) i;
        }
    }

    @Test
    public void sha256HexMatchesKnownVector() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                Signing.sha256Hex("abc"));
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                Signing.sha256Hex(new byte[0]));
    }

    @Test
    public void crossPlatformFixedVectorMatchesWorker() {
        // Fixed vector verified against the TypeScript Worker implementation.
        String body = "{\"version\":1,\"eventId\":\"e1\",\"sender\":\"META\","
                + "\"body\":\"116018 is your Meta confirmation code.\","
                + "\"receivedAt\":\"2026-01-01T00:00:00Z\"}";
        byte[] raw = body.getBytes(StandardCharsets.UTF_8);
        assertEquals("36f987206814c401638481de4e3ec2e9d0f395b16d83d19376fa1f0e11d559c8",
                Signing.sha256Hex(raw));
        assertEquals("f914d836081f7d8821a0169c253485877f0da94bdd90be9c13457fd2f5247f04",
                Signing.sign(SECRET, "1700000000", "0123456789abcdef0123456789abcdef", raw));
    }

    @Test
    public void hmacMatchesRfc4231Case2() {
        // RFC 4231 Test Case 2, HMAC-SHA-256, key "Jefe".
        byte[] key = "Jefe".getBytes(StandardCharsets.UTF_8);
        assertEquals("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                Signing.hmacSha256Hex(key, "what do ya want for nothing?"));
    }

    @Test
    public void canonicalStringHasFiveLinesNoTrailingNewline() {
        String canonical = Signing.canonicalString("1700000000", "abc123", "deadbeef");
        assertEquals("POST\n/sms/meta\n1700000000\nabc123\ndeadbeef", canonical);
        assertFalse(canonical.endsWith("\n"));
        assertEquals(5, canonical.split("\n", -1).length);
    }

    @Test
    public void signUsesSha256OfExactBodyBytes() {
        byte[] body = "{\"version\":1}".getBytes(StandardCharsets.UTF_8);
        String expected = Signing.hmacSha256Hex(SECRET,
                Signing.canonicalString("1700000000", "nonce1", Signing.sha256Hex(body)));
        assertEquals(expected, Signing.sign(SECRET, "1700000000", "nonce1", body));
    }

    @Test
    public void signatureIsSensitiveToBodyTimestampNonceAndSecret() {
        byte[] body = "body".getBytes(StandardCharsets.UTF_8);
        String base = Signing.sign(SECRET, "100", "n1", body);
        assertNotEquals(base, Signing.sign(SECRET, "101", "n1", body));
        assertNotEquals(base, Signing.sign(SECRET, "100", "n2", body));
        assertNotEquals(base, Signing.sign(SECRET, "100", "n1", "body2".getBytes(StandardCharsets.UTF_8)));
        byte[] other = SECRET.clone();
        other[0] = (byte) 0xFF;
        assertNotEquals(base, Signing.sign(other, "100", "n1", body));
        assertEquals(64, base.length());
        assertEquals(base.toLowerCase(), base);
    }

    @Test
    public void freshNoncesAreUnique() {
        assertNotEquals(Signing.freshNonce(), Signing.freshNonce());
        assertEquals(32, Signing.freshNonce().length());
    }

    @Test
    public void timestampFreshnessIs120Seconds() {
        assertTrue(Signing.isTimestampFresh(1000, 1000, 120));
        assertTrue(Signing.isTimestampFresh(1000, 1120, 120));
        assertTrue(Signing.isTimestampFresh(1000, 880, 120));
        assertFalse(Signing.isTimestampFresh(1000, 1121, 120));
        assertFalse(Signing.isTimestampFresh(1000, 879, 120));
    }
}
