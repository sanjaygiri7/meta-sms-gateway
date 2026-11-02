package tech.bogomolov.incomingsmsgateway;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** Endpoint validation and response classification. No network is used here. */
public class MetaHttpClientTest {

    private static final String CONFIGURED = "https://meta-sms.example.workers.dev/sms/meta";

    @Test
    public void exactEndpointIsAllowed() {
        assertTrue(MetaHttpClient.isAllowedEndpoint(CONFIGURED, CONFIGURED));
        assertTrue(MetaHttpClient.isValidConfiguredUrl(CONFIGURED));
        assertTrue(MetaHttpClient.isValidConfiguredUrl("https://meta-sms.example.workers.dev:443/sms/meta"));
    }

    @Test
    public void httpIsRejected() {
        assertFalse(MetaHttpClient.isAllowedEndpoint(
                "http://meta-sms.example.workers.dev/sms/meta", CONFIGURED));
        assertFalse(MetaHttpClient.isValidConfiguredUrl(
                "http://meta-sms.example.workers.dev/sms/meta"));
    }

    @Test
    public void differentHostPathQueryOrUserinfoIsRejected() {
        assertFalse(MetaHttpClient.isAllowedEndpoint(
                "https://evil.example.workers.dev/sms/meta", CONFIGURED));
        assertFalse(MetaHttpClient.isAllowedEndpoint(
                "https://meta-sms.example.workers.dev/other", CONFIGURED));
        assertFalse(MetaHttpClient.isAllowedEndpoint(
                "https://meta-sms.example.workers.dev/sms/meta?x=1", CONFIGURED));
        assertFalse(MetaHttpClient.isAllowedEndpoint(
                "https://meta-sms.example.workers.dev/sms/meta#frag", CONFIGURED));
        assertFalse(MetaHttpClient.isAllowedEndpoint(
                "https://user@meta-sms.example.workers.dev/sms/meta", CONFIGURED));
        assertFalse(MetaHttpClient.isValidConfiguredUrl(
                "https://meta-sms.example.workers.dev/sms/meta/"));
        assertFalse(MetaHttpClient.isValidConfiguredUrl("not a url"));
        assertFalse(MetaHttpClient.isValidConfiguredUrl(null));
    }

    @Test
    public void redirectsArePermanentNeverRetryElsewhere() {
        for (int code : new int[]{301, 302, 303, 307, 308}) {
            assertEquals(MetaHttpClient.Outcome.PERMANENT, MetaHttpClient.classify(code));
        }
    }

    @Test
    public void successAndDuplicateAreSuccess() {
        assertEquals(MetaHttpClient.Outcome.SUCCESS, MetaHttpClient.classify(200));
        assertEquals(MetaHttpClient.Outcome.SUCCESS, MetaHttpClient.classify(204));
    }

    @Test
    public void permanentClientErrorsDoNotRetry() {
        for (int code : new int[]{400, 401, 404, 405, 409, 413, 418, 422}) {
            assertEquals("code " + code, MetaHttpClient.Outcome.PERMANENT, MetaHttpClient.classify(code));
        }
    }

    @Test
    public void serverErrorsRetry() {
        assertEquals(MetaHttpClient.Outcome.RETRY, MetaHttpClient.classify(500));
        assertEquals(MetaHttpClient.Outcome.RETRY, MetaHttpClient.classify(502));
        assertEquals(MetaHttpClient.Outcome.RETRY, MetaHttpClient.classify(503));
    }

    @Test
    public void payloadContainsOnlyRequiredFields() {
        String payload = JsonEscape.buildPayload(
                "event-1", "META", "116018 is your Meta confirmation code.", "2026-01-01T00:00:00Z");
        assertEquals("{\"version\":1,\"eventId\":\"event-1\",\"sender\":\"META\","
                + "\"body\":\"116018 is your Meta confirmation code.\",\"receivedAt\":\"2026-01-01T00:00:00Z\"}",
                payload);
        assertFalse(payload.contains("phone"));
        assertFalse(payload.contains("imei"));
    }

    @Test
    public void jsonEscapingHandlesQuotesAndControlChars() {
        String payload = JsonEscape.buildPayload("e", "S\"X", "a\"b\\c\nd", "t");
        assertTrue(payload.contains("S\\\"X"));
        assertTrue(payload.contains("a\\\"b\\\\c\\nd"));
    }
}
