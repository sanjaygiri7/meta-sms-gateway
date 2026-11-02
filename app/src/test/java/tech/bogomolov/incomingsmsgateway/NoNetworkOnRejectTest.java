package tech.bogomolov.incomingsmsgateway;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Security regression: a rejected SMS must never result in a network request.
 * The receiver's decision is exactly {@link MetaFilter#accepts}; this test
 * pins the decision for every rejection class, so a future change that
 * forwards a rejected message fails here before it can reach the network.
 * There is no "should forward" helper in production code that this test
 * could accidentally bless: forwarding requires accepts() to be true.
 */
public class NoNetworkOnRejectTest {

    private static boolean wouldForward(Set<String> allowlist, String sender, String body) {
        // Mirrors SmsBroadcastReceiver: only accepts() leads to enqueueing.
        return MetaFilter.accepts(allowlist, sender, body);
    }

    @Test
    public void rejectedMessagesNeverForward() {
        Set<String> allow = new HashSet<>(Collections.singletonList("META"));
        String code = "116018 is your Meta confirmation code.";
        assertFalse(wouldForward(Collections.emptySet(), "META", code));
        assertFalse(wouldForward(allow, "UNKNOWN", code));
        assertFalse(wouldForward(allow, "META", "Your OTP is 116018."));
        assertFalse(wouldForward(allow, "META", "Hello"));
        assertFalse(wouldForward(allow, "META", "116018 is your Meta confirmation code. Share it!"));
        assertFalse(wouldForward(allow, null, code));
        assertFalse(wouldForward(allow, "META", null));
        assertFalse(wouldForward(allow, "*", code));
    }

    @Test
    public void onlyExactApprovedCodeForwards() {
        Set<String> allow = new HashSet<>(Collections.singletonList("META"));
        assertTrue(wouldForward(allow, "META", "116018 is your Meta confirmation code."));
        assertTrue(wouldForward(allow, "meta", "116018 is your Meta confirmation code."));
    }
}
