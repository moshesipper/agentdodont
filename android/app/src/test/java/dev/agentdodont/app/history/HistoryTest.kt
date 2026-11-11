package dev.agentdodont.app.history

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Event sequences mirror what the app writes (taken from real on-device logs). */
class HistoryTest {
    private var clock = 0.0
    private fun ev(kind: String, vararg f: Pair<String, Any?>) = mapOf("t" to ++clock, "kind" to kind) + f

    private fun call(name: String, agent: Boolean = false, tainted: Boolean = false, approved: Boolean = false) =
        ev("capability_call", "name" to name, "source" to if (agent) "AGENT" else "USER_DIRECT", "tainted" to tainted, "approved" to approved)

    private fun decision(name: String, verdict: String, rule: String, summary: String) =
        ev("decision", "name" to name, "verdict" to verdict, "rule" to rule, "summary" to summary)

    @Test fun agentTaskWithTwoAutomaticActions() {
        val s = History.build(listOf(
            ev("intent", "text" to "add A at 11 and B at 12", "handled_by" to "agent"),
            ev("agent_task", "text" to "add A at 11 and B at 12"),
            ev("model_call", "input_tokens" to 4, "output_tokens" to 109, "cache_read" to 0, "cache_write" to 1522),
            call("add_calendar_event", agent = true),
            decision("add_calendar_event", "AUTO", "add calendar event is reversible (default: \"Do it\")", "Add \"A\""),
            ev("undo_recorded", "name" to "add_calendar_event"),
            ev("capability_result", "name" to "add_calendar_event", "ok" to true, "message" to "Added \"A\""),
            ev("model_call", "input_tokens" to 2, "output_tokens" to 109, "cache_read" to 1522, "cache_write" to 139),
            call("add_calendar_event", agent = true),
            decision("add_calendar_event", "AUTO", "add calendar event is reversible (default: \"Do it\")", "Add \"B\""),
            ev("capability_result", "name" to "add_calendar_event", "ok" to true, "message" to "Added \"B\""),
            ev("model_call", "input_tokens" to 2, "output_tokens" to 61, "cache_read" to 1661, "cache_write" to 137),
            ev("agent_done", "reply" to "I added both.", "ok" to true),
        )).single()
        assertEquals(Kind.AGENT, s.kind)
        assertEquals("\"add A at 11 and B at 12\"", s.title)
        assertEquals(listOf("Add \"A\"", "Add \"B\""), s.steps.map { it.summary })
        assertTrue(s.steps.all { it.outcome == Outcome.DONE && it.byAgent && it.approved == null })
        assertEquals(listOf(true, false), s.steps.map { it.undoable })
        assertEquals(3, s.modelCalls)
        assertEquals(279L, s.outputTokens)
        assertEquals("I added both.", s.reply)
        val why = s.steps[0].why()
        assertEquals("Claude proposed it.", why[0])
        assertTrue(why[1], why[1].startsWith("The policy let it run without asking: add calendar event is reversible"))
        assertTrue(why.contains("It can be undone."))
    }

    @Test fun askThenAllowIsOneStep() {
        val rule = "delete calendar event is irreversible (default: \"Ask me\")"
        val s = History.build(listOf(
            ev("intent", "text" to "delete event Gym", "handled_by" to "quick_parser"),
            call("delete_calendar_event"),
            decision("delete_calendar_event", "ASK", rule, "Delete \"Gym\""),
            ev("capability_result", "name" to "delete_calendar_event", "ok" to false, "needs_confirmation" to rule),
            ev("confirmation", "approved" to true, "rule" to rule),
            call("delete_calendar_event", approved = true),
            decision("delete_calendar_event", "ASK", rule, "Delete \"Gym\""),
            ev("capability_result", "name" to "delete_calendar_event", "ok" to true, "message" to "Deleted \"Gym\""),
        )).single()
        val step = s.steps.single()
        assertEquals(Kind.COMMAND, s.kind)
        assertEquals(Outcome.DONE, step.outcome)
        assertEquals(true, step.approved)
        assertEquals(listOf("You asked for this directly.", "The policy asked you first: $rule.", "You allowed it.",
            "Result: Deleted \"Gym\"."), step.why())
    }

    @Test fun dontAllowIsDeclinedEvenWithoutAFinalResult() {
        val s = History.build(listOf(
            ev("intent", "text" to "delete event Gym", "handled_by" to "quick_parser"),
            call("delete_calendar_event"),
            decision("delete_calendar_event", "ASK", "irreversible", "Delete \"Gym\""),
            ev("capability_result", "name" to "delete_calendar_event", "ok" to false, "needs_confirmation" to "irreversible"),
            ev("confirmation", "approved" to false),
        )).single()
        assertEquals(Outcome.DECLINED, s.steps.single().outcome)
        assertTrue(s.steps.single().why().contains("You declined."))
    }

    @Test fun taintAndDenyAreExplained() {
        val s = History.build(listOf(
            ev("intent", "text" to "clean up my calendar", "handled_by" to "agent"),
            call("find_calendar_events", agent = true),
            decision("find_calendar_events", "AUTO", "find calendar events is none (default: \"Do it\")", "Look up events"),
            ev("capability_result", "name" to "find_calendar_events", "ok" to true, "message" to "Upcoming events: ..."),
            call("delete_calendar_event", agent = true, tainted = true),
            decision("delete_calendar_event", "DENY", "your Policy setting for delete calendar event is \"Never\"", "Delete \"X\""),
            ev("capability_result", "name" to "delete_calendar_event", "ok" to false, "denied" to "..."),
            ev("agent_done", "reply" to "I couldn't delete it: blocked by your policy.", "ok" to true),
        )).single()
        val del = s.steps[1]
        assertEquals(Outcome.BLOCKED, del.outcome)
        assertEquals("Claude proposed it, after the task had read untrusted content.", del.why()[0])
        assertTrue(del.why()[1].startsWith("The policy blocked it: your Policy setting"))
        assertEquals("Nothing ran.", del.why().last())
    }

    @Test fun stoppedTaskLeavesUnansweredStepNotFinished() {
        val s = History.build(listOf(
            ev("intent", "text" to "delete the gym event", "handled_by" to "agent"),
            call("delete_calendar_event", agent = true),
            decision("delete_calendar_event", "ASK", "irreversible", "Delete \"Gym\""),
            ev("capability_result", "name" to "delete_calendar_event", "ok" to false, "needs_confirmation" to "irreversible"),
            ev("agent_stopped", "by" to "user"),
        )).single()
        assertTrue(s.stoppedByUser)
        assertEquals(Outcome.NOT_FINISHED, s.steps.single().outcome)
        assertNull(s.steps.single().approved)
    }

    @Test fun undoStoryShowsWhatWasReversed() {
        val s = History.build(listOf(
            ev("intent", "text" to "undo", "handled_by" to "undo"),
            ev("confirmation", "approved" to true, "summary" to "• Remove \"A\""),
            ev("undo_call", "group" to "agent-1", "ids" to "5, 4"),
            ev("undo_result", "undo_id" to 5, "ok" to true, "message" to "Removed \"B\""),
            ev("undo_result", "undo_id" to 4, "ok" to false, "message" to "\"A\" was edited since Agent Do/Don't added it"),
        )).single()
        assertEquals(Kind.UNDO, s.kind)
        assertTrue(s.steps.isEmpty())
        assertEquals("↶ Removed \"B\"\nCouldn't undo: \"A\" was edited since Agent Do/Don't added it", s.reply)
    }

    @Test fun undoButtonInOldLogsIsItsOwnStoryNotAnApproval() {
        // Real sequence from the S22: an agent task, then the Undo button (which logged no intent).
        val stories = History.build(listOf(
            ev("intent", "text" to "set meeting at 2pm", "handled_by" to "agent"),
            call("add_calendar_event", agent = true),
            decision("add_calendar_event", "AUTO", "add calendar event is reversible", "Add \"Meeting\""),
            ev("capability_result", "name" to "add_calendar_event", "ok" to true, "message" to "Added \"Meeting\""),
            ev("agent_done", "reply" to "Added.", "ok" to true),
            ev("confirmation", "approved" to true, "rule" to "undo changes your phone too, so it shows what it will do first (done just now)"),
            ev("undo_call", "group" to "agent-1", "ids" to "12"),
            ev("undo_result", "undo_id" to 12, "ok" to true, "message" to "Removed \"Meeting\""),
        ))
        assertEquals(listOf(Kind.UNDO, Kind.AGENT), stories.map { it.kind })
        assertEquals("↶ Removed \"Meeting\"", stories[0].reply)
        assertNull(stories[1].steps.single().approved) // it ran automatically; nobody "allowed" it
    }

    @Test fun otherStoriesAndOrdering() {
        val stories = History.build(listOf(
            ev("decision", "verdict" to "AUTO"), // before any request: ignored
            ev("open_app", "package" to "com.android.chrome", "via" to "grid"),
            ev("policy_change", "capability" to "open_url", "level" to "ASK"),
            ev("policy_change", "reset" to true),
        ), appLabel = { if (it == "com.android.chrome") "Chrome" else it })
        assertEquals(listOf("You reset the policy to defaults", "You set open url to \"Ask me\"", "Opened Chrome from the app grid"),
            stories.map { it.title })
        assertEquals(listOf(Kind.POLICY, Kind.POLICY, Kind.APP), stories.map { it.kind })
    }
}

class HistoryClearTest {
    @Test fun aClearLeavesAVisibleContentFreeMarker() {
        val s = History.build(listOf(mapOf("t" to 1.0, "kind" to "history_cleared", "entries" to 412))).single()
        assertEquals(Kind.CLEARED, s.kind)
        assertEquals("You cleared the history (412 entries)", s.title)
    }

    @Test fun undoListClears() {
        val u = dev.agentdodont.app.capabilities.UndoStore(file = null)
        u.add("g", "set_alarm", "x", emptyMap())
        u.clear()
        assertTrue(u.lastGroup().isEmpty() && u.all().isEmpty())
    }
}
