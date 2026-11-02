package tech.bogomolov.incomingsmsgateway;

/** Minimal JSON string escaping, so payload building needs no org.json on the JVM. */
public final class JsonEscape {

    private JsonEscape() {
    }

    public static String escape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    out.append("\\\"");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                case '\b':
                    out.append("\\b");
                    break;
                case '\f':
                    out.append("\\f");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                    break;
            }
        }
        return out.toString();
    }

    /**
     * The exact payload the Worker verifies. No phone number, device identifiers,
     * location, contacts or SIM data. {@code receivedAt} is ISO-8601 UTC.
     */
    public static String buildPayload(String eventId, String sender, String body, String receivedAt) {
        return "{\"version\":1,\"eventId\":\"" + escape(eventId)
                + "\",\"sender\":\"" + escape(sender)
                + "\",\"body\":\"" + escape(body)
                + "\",\"receivedAt\":\"" + escape(receivedAt) + "\"}";
    }
}
