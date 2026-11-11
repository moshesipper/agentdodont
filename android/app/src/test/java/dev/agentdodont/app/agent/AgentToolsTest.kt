package dev.agentdodont.app.agent

import com.anthropic.core.JsonValue
import dev.agentdodont.app.capabilities.CapResult
import dev.agentdodont.app.capabilities.OutputTrust
import dev.agentdodont.app.capabilities.ReadNotifications
import dev.agentdodont.app.capabilities.Registry
import dev.agentdodont.app.capabilities.SetAlarm
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentToolsTest {
    @Test fun everyCapabilityBecomesAStrictTool() {
        for (cap in Registry.all) {
            val tool = Agent.toTool(cap)
            assertEquals(cap.name, tool.name())
            assertEquals(true, tool.strict().orElse(false))
            val schema = tool.inputSchema()
            assertEquals(cap.params.filter { it.required }.map { it.name }, schema.required().orElse(emptyList()))
            assertEquals(JsonValue.from(false), schema._additionalProperties()["additionalProperties"])
            val props = schema.properties().orElseThrow()._additionalProperties()
            assertTrue(cap.name, props.keys == cap.params.map { it.name }.toSet())
            // The API rejects numeric bounds on strict tools (found on the device: 400).
            for ((name, p) in props) {
                val s = p.toString()
                assertTrue("$name: $s", Agent.STRICT_UNSUPPORTED.none { "$it=" in s || "\"$it\"" in s })
            }
        }
    }

    @Test fun whatTaintsATask() {
        val ok = { from: String? -> CapResult.Ok("x", untrustedFrom = from) }
        // Untrusted capability: the result's own account wins, else the declaration.
        assertEquals("notifications", Agent.taintFrom(ReadNotifications, ok(null)))
        assertEquals("notifications from Shell", Agent.taintFrom(ReadNotifications, ok("notifications from Shell")))
        assertNull(Agent.taintFrom(ReadNotifications, ok(""))) // only trusted apps' notifications
        // Trusted capability: no taint, unless a result itself reports untrusted content.
        assertNull(Agent.taintFrom(SetAlarm, ok(null)))
        assertEquals("x", Agent.taintFrom(SetAlarm, ok("x")))
        // Nothing came back: nothing to taint with.
        assertNull(Agent.taintFrom(ReadNotifications, CapResult.Error("no access")))
        assertNull(Agent.taintFrom(ReadNotifications, CapResult.Denied("r")))
    }

    @Test fun everyCapabilityDeclaresTrustExplicitly() {
        // Declarations are compile-time required; their contents must still make sense.
        for (cap in Registry.all) {
            val o = cap.output
            if (o is OutputTrust.Untrusted) assertTrue(cap.name, o.what.isNotBlank())
        }
        assertEquals(setOf("find_calendar_events", "read_notifications", "read_screen"),
            Registry.all.filter { it.untrustedOutput }.map { it.name }.toSet())
    }

    @Test fun systemPromptIsStable() {
        // The system prompt must not contain anything that changes per request (time, ids),
        // or the cached prefix is invalidated on every call.
        assertTrue(!Regex("""\d{4}-\d{2}-\d{2}""").containsMatchIn(Agent.SYSTEM_PROMPT))
    }
}
