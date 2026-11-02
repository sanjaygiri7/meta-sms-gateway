package tech.bogomolov.incomingsmsgateway;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Locale;

import javax.net.ssl.HttpsURLConnection;

/**
 * The only HTTP client in the app. Exactly one destination, HTTPS only, POST only,
 * no redirects, default TLS certificate/hostname verification.
 *
 * <p>No custom TrustManager, no permissive hostname verifier, no custom socket
 * factory. The "Ignore SSL" option from the original app is gone entirely.
 */
public final class MetaHttpClient {

    public enum Outcome {
        SUCCESS, PERMANENT, RETRY
    }

    private MetaHttpClient() {
    }

    /**
     * Validates that {@code urlString} is exactly the configured endpoint:
     * https, same host (case-insensitive), same effective port, path exactly
     * "/sms/meta", no query, no fragment, no userinfo. Any deviation is refused
     * without making a request.
     */
    public static boolean isAllowedEndpoint(String urlString, String configuredUrl) {
        if (urlString == null || configuredUrl == null) {
            return false;
        }
        try {
            URL url = new URL(urlString);
            URL configured = new URL(configuredUrl);
            if (!"https".equalsIgnoreCase(url.getProtocol())) {
                return false;
            }
            if (!"https".equalsIgnoreCase(configured.getProtocol())) {
                return false;
            }
            if (url.getUserInfo() != null) {
                return false;
            }
            if (!url.getHost().equalsIgnoreCase(configured.getHost())) {
                return false;
            }
            if (effectivePort(url) != effectivePort(configured)) {
                return false;
            }
            if (!"/sms/meta".equals(url.getPath())) {
                return false;
            }
            if (!"/sms/meta".equals(configured.getPath())) {
                return false;
            }
            if (url.getQuery() != null || url.getRef() != null) {
                return false;
            }
            return true;
        } catch (MalformedURLException e) {
            return false;
        }
    }

    private static int effectivePort(URL url) {
        int port = url.getPort();
        if (port != -1) {
            return port;
        }
        return "https".equalsIgnoreCase(url.getProtocol()) ? 443 : 80;
    }

    /** Validates the configured URL itself: https and path exactly /sms/meta. */
    public static boolean isValidConfiguredUrl(String urlString) {
        if (urlString == null) {
            return false;
        }
        try {
            URL url = new URL(urlString.trim());
            return "https".equalsIgnoreCase(url.getProtocol())
                    && url.getHost() != null && !url.getHost().isEmpty()
                    && url.getUserInfo() == null
                    && "/sms/meta".equals(url.getPath())
                    && url.getQuery() == null && url.getRef() == null;
        } catch (MalformedURLException e) {
            return false;
        }
    }

    /** Maps a status code to the retry policy. 3xx is permanent: never follow, never retry elsewhere. */
    public static Outcome classify(int responseCode) {
        if (responseCode >= 200 && responseCode < 300) {
            return Outcome.SUCCESS;
        }
        if (responseCode == 301 || responseCode == 302 || responseCode == 303
                || responseCode == 307 || responseCode == 308) {
            return Outcome.PERMANENT;
        }
        if (responseCode == 400 || responseCode == 401 || responseCode == 404
                || responseCode == 405 || responseCode == 409 || responseCode == 413) {
            return Outcome.PERMANENT;
        }
        if (responseCode >= 400 && responseCode < 500) {
            return Outcome.PERMANENT;
        }
        if (responseCode >= 500 && responseCode < 600) {
            return Outcome.RETRY;
        }
        return Outcome.RETRY;
    }

    /**
     * Sends one POST. Returns the HTTP status code, or -1 when no response was
     * received (network failure). Redirects are never followed: the connection
     * is configured with {@code setInstanceFollowRedirects(false)} and a 3xx
     * code is returned to the caller for permanent handling.
     */
    public static int post(String urlString, byte[] rawBody, String deviceId,
                           String timestamp, String nonce, String signatureHex) throws IOException {
        URL url = new URL(urlString);
        if (!"https".equalsIgnoreCase(url.getProtocol())) {
            throw new IOException("refusing non-HTTPS destination");
        }
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        try {
            connection.setInstanceFollowRedirects(false);
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setConnectTimeout(15000);
            connection.setReadTimeout(15000);
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            connection.setRequestProperty("X-Device-Id", deviceId);
            connection.setRequestProperty("X-Timestamp", timestamp);
            connection.setRequestProperty("X-Nonce", nonce);
            connection.setRequestProperty("X-Signature", signatureHex);
            connection.setFixedLengthStreamingMode(rawBody.length);
            // Default TLS verification: HttpsURLConnection uses the platform
            // TrustManager and hostname verifier. Nothing custom is installed.
            if (connection instanceof HttpsURLConnection) {
                ((HttpsURLConnection) connection).setHostnameVerifier(
                        HttpsURLConnection.getDefaultHostnameVerifier());
            }
            try (OutputStream out = connection.getOutputStream()) {
                out.write(rawBody);
                out.flush();
            }
            int code = connection.getResponseCode();
            // Drain, without logging, the response body so the connection can close.
            InputStream stream = code >= 200 && code < 300
                    ? connection.getInputStream() : connection.getErrorStream();
            if (stream != null) {
                byte[] buf = new byte[1024];
                while (stream.read(buf) != -1) {
                    // Discard. The OTP is never returned in a POST response.
                }
                stream.close();
            }
            return code;
        } finally {
            connection.disconnect();
        }
    }

    public static String describeHost(String urlString) {
        try {
            return new URL(urlString).getHost().toLowerCase(Locale.ROOT);
        } catch (MalformedURLException e) {
            return "";
        }
    }
}
