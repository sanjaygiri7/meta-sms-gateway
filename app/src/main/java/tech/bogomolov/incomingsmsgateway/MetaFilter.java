package tech.bogomolov.incomingsmsgateway;

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Strict Meta-only filter. Pure Java, no Android APIs, so it is JVM-unit-testable.
 *
 * <p>Both conditions must hold:
 * <ol>
 *   <li>The sender ID is explicitly allowlisted, by exact equality after trimming
 *       leading/trailing whitespace, compared case-insensitively for alphanumeric
 *       sender IDs. No partial, wildcard, suffix or fuzzy matching.</li>
 *   <li>The body matches the approved Meta confirmation-code template exactly.</li>
 * </ol>
 * Anything else is rejected locally and must never be uploaded, logged or stored.
 * The allowlist starts empty and fails closed: an empty allowlist forwards nothing.
 */
public final class MetaFilter {

    /** ^\s*([0-9]{6})\s+is your Meta confirmation code\.?\s*$ , case-insensitive. */
    public static final Pattern META_CODE_PATTERN =
            Pattern.compile("^\\s*([0-9]{6})\\s+is your Meta confirmation code\\.?\\s*$",
                    Pattern.CASE_INSENSITIVE);

    private MetaFilter() {
    }

    /** Normalised form used for allowlist comparison: trim only, lower-cased. */
    public static String normaliseSender(String sender) {
        if (sender == null) {
            return "";
        }
        return sender.trim().toLowerCase(Locale.ROOT);
    }

    /** True only when {@code sender} is exactly one of {@code allowlist} entries. */
    public static boolean isSenderAllowlisted(Set<String> allowlist, String sender) {
        if (allowlist == null || allowlist.isEmpty() || sender == null) {
            return false;
        }
        String wanted = normaliseSender(sender);
        if (wanted.isEmpty()) {
            return false;
        }
        for (String entry : allowlist) {
            if (entry != null && wanted.equals(normaliseSender(entry))) {
                return true;
            }
        }
        return false;
    }

    /** Extracts the six ASCII digits, or null when the body does not match exactly. */
    public static String extractCode(String body) {
        if (body == null) {
            return null;
        }
        Matcher m = META_CODE_PATTERN.matcher(body);
        if (!m.matches()) {
            return null;
        }
        return m.group(1);
    }

    /** True only when both the sender and the body conditions hold. */
    public static boolean accepts(Set<String> allowlist, String sender, String body) {
        return isSenderAllowlisted(allowlist, sender) && extractCode(body) != null;
    }

    /** Deduplicates allowlist entries case-insensitively, preserving first casing. */
    public static Set<String> dedupeAllowlist(Iterable<String> entries) {
        Set<String> out = new java.util.LinkedHashSet<>();
        Set<String> seen = new HashSet<>();
        if (entries == null) {
            return out;
        }
        for (String entry : entries) {
            if (entry == null) {
                continue;
            }
            String trimmed = entry.trim();
            if (trimmed.isEmpty() || "*".equals(trimmed)) {
                continue;
            }
            String key = normaliseSender(trimmed);
            if (seen.add(key)) {
                out.add(trimmed);
            }
        }
        return out;
    }
}
