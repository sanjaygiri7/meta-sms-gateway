package tech.bogomolov.incomingsmsgateway;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/** Filter contract from the specification, with fake messages only. */
public class MetaFilterTest {

    private static Set<String> allow(String... senders) {
        return new HashSet<>(Arrays.asList(senders));
    }

    @Test
    public void approvedSenderExactCodeAccepts() {
        assertTrue(MetaFilter.accepts(allow("META"), "META", "116018 is your Meta confirmation code."));
        assertTrue(MetaFilter.accepts(allow("META"), "META", "116018 is your Meta confirmation code"));
        assertEquals("116018", MetaFilter.extractCode("116018 is your Meta confirmation code."));
    }

    @Test
    public void unknownSenderExactCodeRejects() {
        assertFalse(MetaFilter.accepts(allow("META"), "OTHER", "116018 is your Meta confirmation code."));
        assertFalse(MetaFilter.accepts(allow("META"), "METAA", "116018 is your Meta confirmation code."));
        assertFalse(MetaFilter.accepts(allow("META"), "META1", "116018 is your Meta confirmation code."));
    }

    @Test
    public void approvedSenderUnrelatedOtpRejects() {
        assertFalse(MetaFilter.accepts(allow("META"), "META", "116018 is your code."));
        assertFalse(MetaFilter.accepts(allow("META"), "META", "Your OTP is 116018."));
        assertFalse(MetaFilter.accepts(allow("META"), "META", "116018 is your Meta confirmation code. Do not share it with anyone."));
        assertFalse(MetaFilter.accepts(allow("META"), "META", "Hello, this is Meta."));
        assertNull(MetaFilter.extractCode("Meta"));
    }

    @Test
    public void approvedSenderOrdinarySmsRejects() {
        assertFalse(MetaFilter.accepts(allow("META"), "META", "Hello world"));
        assertFalse(MetaFilter.accepts(allow("META"), "META", ""));
        assertNull(MetaFilter.extractCode("Hello world"));
    }

    @Test
    public void unknownSenderContainingMetaRejects() {
        assertFalse(MetaFilter.accepts(allow("META"), "NOTMETA", "116018 is your Meta confirmation code."));
        assertFalse(MetaFilter.accepts(Collections.emptySet(), "META", "116018 is your Meta confirmation code."));
    }

    @Test
    public void emptyAllowlistForwardsNothing() {
        assertFalse(MetaFilter.accepts(Collections.emptySet(), "META", "116018 is your Meta confirmation code."));
        assertFalse(MetaFilter.accepts(null, "META", "116018 is your Meta confirmation code."));
        assertFalse(MetaFilter.isSenderAllowlisted(Collections.emptySet(), "META"));
    }

    @Test
    public void senderMatchIsExactCaseInsensitiveTrimmedOnly() {
        assertTrue(MetaFilter.isSenderAllowlisted(allow("Meta"), "META"));
        assertTrue(MetaFilter.isSenderAllowlisted(allow("META"), "  meta  "));
        assertFalse(MetaFilter.isSenderAllowlisted(allow("META"), "X-META"));
        assertFalse(MetaFilter.isSenderAllowlisted(allow("META"), "META-X"));
        assertFalse(MetaFilter.isSenderAllowlisted(allow("META"), "MET"));
        assertFalse(MetaFilter.isSenderAllowlisted(allow("*"), "anything"));
    }

    @Test
    public void bodyMatchIsCaseInsensitiveAndSixAsciiDigitsOnly() {
        assertEquals("000001", MetaFilter.extractCode("000001 IS YOUR META CONFIRMATION CODE."));
        assertEquals("123456", MetaFilter.extractCode("  123456 is your Meta confirmation code.  "));
        assertNull(MetaFilter.extractCode("12345 is your Meta confirmation code."));
        assertNull(MetaFilter.extractCode("1234567 is your Meta confirmation code."));
        assertNull(MetaFilter.extractCode("12345a is your Meta confirmation code."));
        assertEquals("123456", MetaFilter.extractCode("123456 is your meta confirmation code"));
        // The template without the trailing period is accepted; extra text is not.
        assertEquals("123456", MetaFilter.extractCode("123456 is your Meta confirmation code"));
        assertNull(MetaFilter.extractCode("123456 is your Meta confirmation code.."));
        assertNull(MetaFilter.extractCode("x123456 is your Meta confirmation code."));
    }

    @Test
    public void dedupeIsCaseInsensitiveAndRejectsWildcard() {
        Set<String> out = MetaFilter.dedupeAllowlist(Arrays.asList("META", " meta ", "*", "", "  ", "Other"));
        assertEquals(2, out.size());
        assertTrue(out.contains("META"));
        assertTrue(out.contains("Other"));
    }
}
