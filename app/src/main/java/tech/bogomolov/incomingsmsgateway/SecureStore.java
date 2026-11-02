package tech.bogomolov.incomingsmsgateway;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.json.JSONArray;
import org.json.JSONException;

/**
 * Keystore-backed encrypted storage for everything sensitive.
 *
 * <p>The AES-256-GCM key lives only in the Android Keystore under
 * {@code meta_sms_gateway_key}. It is never stored in source, in ordinary
 * preferences, or in a backup. All values below are stored as one encrypted
 * blob each in a private SharedPreferences file: the 32-byte HMAC secret, the
 * Worker URL, the allowlist, and the device ID. No plaintext secret ever
 * reaches SharedPreferences, WorkManager input, logs or a backup file.
 *
 * <p>No user authentication is required for the key: SMS arrives while the
 * phone is locked, and the background receiver and worker must be able to
 * decrypt without the user present. Device unlock / Keystore hardware backing
 * is the protection boundary, together with {@code allowBackup=false}.
 *
 * <p>Observed sender IDs (local-only setup help, sender only, never a body)
 * are deliberately kept in a separate plaintext file, only while the
 * allowlist is empty, and are cleared once a sender is approved.
 */
public final class SecureStore {

    static final String PREFS = "meta_secure";
    static final String OBSERVED_PREFS = "meta_observed";
    private static final String KEY_ALIAS = "meta_sms_gateway_key";

    private static final String K_HMAC_SECRET = "hmac_secret";
    private static final String K_WORKER_URL = "worker_url";
    private static final String K_ALLOWLIST = "allowlist";
    private static final String K_DEVICE_ID = "device_id";
    private static final String K_ACCEPTED_COUNT = "accepted_count";

    private SecureStore() {
    }

    // ---- Keystore key ----

    static SecretKey getOrCreateKey() {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (ks.containsAlias(KEY_ALIAS)) {
                try {
                    SecretKey key = (SecretKey) ks.getKey(KEY_ALIAS, null);
                    if (key != null) {
                        return key;
                    }
                } catch (Exception keyFailed) {
                    // KeyPermanentlyInvalidatedException (a KeyStoreException
                    // subclass at runtime) means the key was invalidated, e.g.
                    // by a lock-screen change. The old ciphertexts are
                    // unrecoverable; drop the alias and generate a fresh key
                    // instead of crashing every caller. Any other failure is
                    // rethrown to the outer handler below.
                    if (keyFailed instanceof KeyPermanentlyInvalidatedException) {
                        try {
                            ks.deleteEntry(KEY_ALIAS);
                        } catch (KeyStoreException ignored) {
                            // Fall through and attempt generation anyway.
                        }
                    } else {
                        throw keyFailed;
                    }
                }
            }
            KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setRandomizedEncryptionRequired(true)
                    .setUserAuthenticationRequired(false)
                    .build();
            kg.init(spec);
            return kg.generateKey();
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException
                | NoSuchProviderException | UnrecoverableKeyException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Keystore key unavailable", e);
        } catch (RuntimeException e) {
            // KeyGenerator/Provider failures (e.g. hardware keystore errors)
            // are unchecked; wrap them so callers see one failure type.
            throw new IllegalStateException("Keystore key unavailable", e);
        }
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private static void putEncrypted(Context context, String key, byte[] plaintext) {
        byte[] combined = AesGcm.encrypt(getOrCreateKey(), plaintext);
        String encoded = Base64.encodeToString(combined, Base64.NO_WRAP);
        Arrays.fill(combined, (byte) 0);
        prefs(context).edit().putString(key, encoded).apply();
    }

    private static byte[] getDecrypted(Context context, String key) {
        String encoded = prefs(context).getString(key, null);
        if (encoded == null) {
            return null;
        }
        byte[] combined;
        try {
            combined = Base64.decode(encoded, Base64.DEFAULT);
        } catch (IllegalArgumentException corrupt) {
            // Corrupt stored blob: treat as absent (fail closed) instead of
            // crashing every caller that reads configuration.
            return null;
        }
        try {
            return AesGcm.decrypt(getOrCreateKey(), combined);
        } catch (IllegalStateException decryptionFailed) {
            // Wrong/invalidated key or tampered blob: treat as absent.
            return null;
        } finally {
            Arrays.fill(combined, (byte) 0);
        }
    }

    private static void putEncryptedString(Context context, String key, String value) {
        if (value == null) {
            prefs(context).edit().remove(key).apply();
            return;
        }
        putEncrypted(context, key, value.getBytes(StandardCharsets.UTF_8));
    }

    private static String getDecryptedString(Context context, String key) {
        byte[] plain = getDecrypted(context, key);
        if (plain == null) {
            return null;
        }
        try {
            return new String(plain, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    // ---- Device ID ----

    public static String getDeviceId(Context context) {
        String existing = getDecryptedString(context, K_DEVICE_ID);
        if (existing != null && !existing.isEmpty()) {
            return existing;
        }
        String id = UUID.randomUUID().toString();
        putEncryptedString(context, K_DEVICE_ID, id);
        return id;
    }

    // ---- HMAC secret: 32 random bytes, stored encrypted, shown only on explicit tap ----

    public static byte[] getOrCreateHmacSecret(Context context) {
        byte[] existing = getDecrypted(context, K_HMAC_SECRET);
        if (existing != null && existing.length == 32) {
            return existing;
        }
        if (existing != null) {
            Arrays.fill(existing, (byte) 0);
        }
        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);
        putEncrypted(context, K_HMAC_SECRET, secret);
        byte[] copy = Arrays.copyOf(secret, secret.length);
        Arrays.fill(secret, (byte) 0);
        return copy;
    }

    /** Base64 of the raw 32-byte secret, for provisioning the Worker. Never log this. */
    public static String getHmacSecretBase64(Context context) {
        byte[] secret = getOrCreateHmacSecret(context);
        try {
            return Base64.encodeToString(secret, Base64.NO_WRAP);
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    public static void regenerateHmacSecret(Context context) {
        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);
        try {
            putEncrypted(context, K_HMAC_SECRET, secret);
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    public static boolean hasHmacSecret(Context context) {
        return prefs(context).contains(K_HMAC_SECRET);
    }

    // ---- Worker URL and allowlist (both encrypted at rest) ----

    public static String getWorkerUrl(Context context) {
        return getDecryptedString(context, K_WORKER_URL);
    }

    public static void setWorkerUrl(Context context, String url) {
        putEncryptedString(context, K_WORKER_URL, url == null ? null : url.trim());
    }

    public static Set<String> getAllowlist(Context context) {
        String json = getDecryptedString(context, K_ALLOWLIST);
        Set<String> out = new LinkedHashSet<>();
        if (json == null || json.isEmpty()) {
            return out;
        }
        try {
            JSONArray arr = new JSONArray(json);
            for (int i = 0; i < arr.length(); i++) {
                out.add(arr.optString(i));
            }
        } catch (JSONException ignored) {
            // Corrupt stored allowlist fails closed: return empty.
            return new LinkedHashSet<>();
        }
        return MetaFilter.dedupeAllowlist(out);
    }

    public static void setAllowlist(Context context, Set<String> allowlist) {
        Set<String> clean = MetaFilter.dedupeAllowlist(allowlist);
        JSONArray arr = new JSONArray();
        for (String s : clean) {
            arr.put(s);
        }
        putEncryptedString(context, K_ALLOWLIST, arr.toString());
    }

    public static boolean isConfigured(Context context) {
        String url = getWorkerUrl(context);
        return url != null && !url.isEmpty() && !getAllowlist(context).isEmpty();
    }

    // ---- Accepted-event counter (count only, never a body or sender) ----

    public static int getAcceptedCount(Context context) {
        String v = getDecryptedString(context, K_ACCEPTED_COUNT);
        if (v == null) {
            return 0;
        }
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    public static void incrementAcceptedCount(Context context) {
        putEncryptedString(context, K_ACCEPTED_COUNT, String.valueOf(getAcceptedCount(context) + 1));
    }

    // ---- Observed senders: local-only, sender only, only while allowlist is empty ----

    public static void recordObservedSender(Context context, String sender) {
        if (sender == null || sender.trim().isEmpty()) {
            return;
        }
        if (!getAllowlist(context).isEmpty()) {
            return;
        }
        SharedPreferences pref = context.getSharedPreferences(OBSERVED_PREFS, Context.MODE_PRIVATE);
        Set<String> existing = new LinkedHashSet<>(pref.getStringSet("senders", new LinkedHashSet<>()));
        if (existing.add(sender.trim())) {
            // Keep only the newest 20, in insertion order.
            while (existing.size() > 20) {
                existing.remove(existing.iterator().next());
            }
            pref.edit().putStringSet("senders", existing).apply();
        }
    }

    public static List<String> getObservedSenders(Context context) {
        SharedPreferences pref = context.getSharedPreferences(OBSERVED_PREFS, Context.MODE_PRIVATE);
        return new ArrayList<>(pref.getStringSet("senders", new LinkedHashSet<>()));
    }

    public static void clearObservedSenders(Context context) {
        context.getSharedPreferences(OBSERVED_PREFS, Context.MODE_PRIVATE).edit().clear().apply();
    }

    // ---- Payload encryption for WorkManager (only ciphertext in WorkManager Data) ----

    /** Encrypts a raw JSON payload; the returned Base64 holds IV||ciphertext+tag. */
    public static String encryptPayload(Context context, byte[] payload) {
        byte[] combined = AesGcm.encrypt(getOrCreateKey(), payload);
        try {
            return Base64.encodeToString(combined, Base64.NO_WRAP);
        } finally {
            Arrays.fill(combined, (byte) 0);
        }
    }

    public static byte[] decryptPayload(Context context, String base64Ciphertext) {
        byte[] combined = Base64.decode(base64Ciphertext, Base64.DEFAULT);
        try {
            return AesGcm.decrypt(getOrCreateKey(), combined);
        } finally {
            Arrays.fill(combined, (byte) 0);
        }
    }
}
