package tech.bogomolov.incomingsmsgateway;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HMAC-SHA256 signing, identical on Android and in the Cloudflare Worker.
 *
 * <p>Canonical signing string, five lines joined by "\n", no trailing newline:
 * <pre>
 * POST
 * /sms/meta
 * TIMESTAMP
 * NONCE
 * SHA256_HEX_OF_EXACT_RAW_JSON_BODY
 * </pre>
 * The signature is HMAC-SHA256 over that string with the shared 32-byte secret,
 * sent as lowercase hex in {@code X-Signature}. The secret is raw bytes, never
 * a string that is logged or committed. The Worker accepts the same secret
 * provisioned as 64-char hex, 32-byte base64, or (fallback) UTF-8 text.
 */
public final class Signing {

    private Signing() {
    }

    public static String sha256Hex(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return toHex(digest.digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static String sha256Hex(String text) {
        return sha256Hex(text.getBytes(StandardCharsets.UTF_8));
    }

    public static String canonicalString(String timestamp, String nonce, String bodySha256Hex) {
        return "POST\n/sms/meta\n" + timestamp + "\n" + nonce + "\n" + bodySha256Hex;
    }

    public static String hmacSha256Hex(byte[] secret, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return toHex(mac.doFinal(data));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }

    public static String hmacSha256Hex(byte[] secret, String data) {
        return hmacSha256Hex(secret, data.getBytes(StandardCharsets.UTF_8));
    }

    /** Signature for one attempt: fresh timestamp and nonce are supplied by the caller. */
    public static String sign(byte[] secret, String timestamp, String nonce, byte[] rawBody) {
        String canonical = canonicalString(timestamp, nonce, sha256Hex(rawBody));
        return hmacSha256Hex(secret, canonical);
    }

    public static String toHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    public static byte[] fromHex(String hex) {
        if (hex == null || (hex.length() % 2) != 0) {
            throw new IllegalArgumentException("bad hex");
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    /** Cryptographically random nonce: 16 random bytes as 32 lowercase hex chars. */
    public static String freshNonce() {
        byte[] nonce = new byte[16];
        new SecureRandom().nextBytes(nonce);
        return toHex(nonce);
    }

    /** Timestamp freshness check shared with the Worker contract: 120 seconds. */
    public static boolean isTimestampFresh(long timestampSeconds, long nowSeconds, long toleranceSeconds) {
        long diff = nowSeconds - timestampSeconds;
        return diff >= -toleranceSeconds && diff <= toleranceSeconds;
    }
}
