package dev.aos.launcher.capabilities

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MessagingTest {
    private fun args(cap: Capability, raw: Map<String, Any?>) = (validate(cap, raw) as Validation.Valid).args
    private val agent = CallContext(Source.AGENT, nowMs = 1)
    private val tainted = agent.copy(tainted = true, taintSources = listOf("notifications from Shell"))

    @Test fun recipientsNormalise() {
        assertEquals(Recipients.normalize("+44 7700 900123"), Recipients.normalize("07700-900123"))
        assertEquals("dana@example.com", Recipients.normalize(" Dana@Example.COM "))
        assertTrue(Recipients.isEmail("dana@example.com"))
        assertFalse(Recipients.isEmail("dana at example"))
        assertTrue(Recipients.isPhone("+44 7700 900123"))
        assertFalse(Recipients.isPhone("12345"))
        assertFalse(Recipients.isPhone("call me maybe"))
    }

    @Test fun badRecipientsAreRejectedBeforeThePolicy() {
        assertTrue(validate(ComposeEmail, mapOf("to" to "not-an-email", "body" to "x")) is Validation.Invalid)
        assertTrue(validate(ComposeMessage, mapOf("to" to "Dana", "text" to "x")) is Validation.Invalid)
    }

    @Test fun draftsToContactsRunInANormalTask() {
        val p = Policy(PolicyConfig(knownRecipients = setOf("a@b.co", Recipients.normalize("07700900123"))))
        assertEquals(Verdict.AUTO, p.decide(ComposeEmail, args(ComposeEmail, mapOf("to" to "a@b.co", "body" to "hi")), agent).verdict)
        assertEquals(Verdict.AUTO, p.decide(ComposeMessage, args(ComposeMessage, mapOf("to" to "07700900123", "text" to "hi")), agent).verdict)
        // Anyone else asks first, even in a normal task.
        assertEquals(Verdict.ASK, p.decide(ComposeEmail, args(ComposeEmail, mapOf("to" to "x@y.co", "body" to "hi")), agent).verdict)
    }

    @Test fun inATaintedTaskOnlyContactsAndOnlyAfterAsking() {
        val p = Policy(PolicyConfig(knownRecipients = setOf("dana@example.com", Recipients.normalize("+447700900123"))))
        val stranger = p.decide(ComposeEmail, args(ComposeEmail, mapOf("to" to "helpdesk@evil.example", "body" to "your calendar")), tainted)
        assertEquals(Verdict.DENY, stranger.verdict)
        assertTrue(stranger.rule, stranger.rule.contains("isn't in your contacts") && stranger.rule.contains("notifications from Shell"))
        val dana = p.decide(ComposeEmail, args(ComposeEmail, mapOf("to" to "Dana@Example.com", "body" to "hi")), tainted)
        assertEquals(Verdict.ASK, dana.verdict)
        assertTrue(dana.rule, dana.rule.contains("one of your contacts"))
        // Same number written differently is still the contact.
        assertEquals(Verdict.ASK, p.decide(ComposeMessage, args(ComposeMessage, mapOf("to" to "07700 900123", "text" to "hi")), tainted).verdict)
    }

    @Test fun websitesStillUseTheSitesList() {
        val p = Policy(PolicyConfig(allowedDomains = setOf("wikipedia.org"), knownRecipients = setOf("wikipedia.org")))
        // A contact entry can't whitelist a website, and vice versa.
        assertEquals(Verdict.ASK, p.decide(OpenUrl, args(OpenUrl, mapOf("url" to "en.wikipedia.org")), tainted).verdict)
        val p2 = Policy(PolicyConfig(knownRecipients = setOf("evil.example")))
        assertEquals(Verdict.DENY, p2.decide(OpenUrl, args(OpenUrl, mapOf("url" to "evil.example")), tainted).verdict)
    }
}
