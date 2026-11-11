package dev.agentdodont.app.capabilities

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

    @Test fun addressesInTypedText() {
        fun found(t: String) = TypedAddresses.find(t).map { it.value }
        assertEquals(listOf("helpdesk@evil.example"), found("helpdesk@evil.example"))
        assertEquals(listOf("evil.example"), found("evil.example/?d=Gym,Dentist"))
        assertEquals(listOf("evil.example"), found("go to https://Evil.Example/x now"))
        assertEquals(listOf(Recipients.normalize("+15550100222")), found("+1 (555) 010-0222"))
        assertEquals(listOf("dana@example.com"), found("Dana@Example.com")) // not also "example.com"
        // Ordinary text isn't an address.
        for (t in listOf("octopus facts", "Meeting at 10:30", "2026-11-10", "10/11/2026", "Room 12", "Running late. See you")) {
            assertTrue(t, found(t).isEmpty())
        }
    }

    @Test fun typingAnAddressIntoAnotherAppIsSendingDataOut() {
        val p = Policy(PolicyConfig(allowedDomains = setOf("wikipedia.org"), knownRecipients = setOf("dana@example.com")))
        val ok = dev.agentdodont.app.screen.Element(1, "android.widget.EditText", "To", "", "", true, true, false, null, false, 0, 0, 1, 1)
        dev.agentdodont.app.screen.ScreenState.foreground = "com.google.android.gm"
        dev.agentdodont.app.screen.ScreenState.last = dev.agentdodont.app.screen.Snapshot("com.google.android.gm", "Gmail", listOf(ok), 0)
        try {
            val inGmail = agent.copy(tainted = true, taintSources = listOf("the screen of Gmail"),
                operatedApp = "com.google.android.gm", operatedAppLabel = "Gmail")
            fun type(text: String, ctx: CallContext) =
                p.decide(dev.agentdodont.app.screen.TypeText, args(dev.agentdodont.app.screen.TypeText, mapOf("element" to 1, "text" to text)), ctx)
            // The operated app's own screen counts here: that's where the injection would be.
            val evil = type("helpdesk@evil.example", inGmail)
            assertEquals(Verdict.DENY, evil.verdict)
            assertTrue(evil.rule, evil.rule.contains("helpdesk@evil.example") && evil.rule.contains("the screen of Gmail"))
            assertEquals(Verdict.ASK, type("dana@example.com", inGmail).verdict)
            assertEquals(Verdict.AUTO, type("Running late", inGmail).verdict)
            // Untainted: a new address asks; a contact doesn't.
            val clean = agent.copy(operatedApp = "com.google.android.gm", operatedAppLabel = "Gmail")
            assertEquals(Verdict.ASK, type("mallory@evil.example", clean).verdict)
            assertEquals(Verdict.AUTO, type("dana@example.com", clean).verdict)
        } finally {
            dev.agentdodont.app.screen.ScreenState.foreground = null
            dev.agentdodont.app.screen.ScreenState.last = null
        }
    }
}
