package dev.agentdodont.app.capabilities

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UndoStoreTest {
    @Test fun lastGroupIsNewestFirstAndOnlyThatRequest() {
        val s = UndoStore(file = null)
        s.add("cmd-1", "set_alarm", "a", emptyMap(), t = 1)
        s.add("agent-2", "set_alarm", "b", emptyMap(), t = 2)
        s.add("agent-2", "add_calendar_event", "c", emptyMap(), t = 3)
        assertEquals(listOf("c", "b"), s.lastGroup().map { it.summary })
    }

    @Test fun undoneEntriesDropOutAndTheGroupBeforeBecomesNext() {
        val s = UndoStore(file = null)
        s.add("g1", "set_alarm", "a", emptyMap())
        val b = s.add("g2", "set_alarm", "b", emptyMap())
        val c = s.add("g2", "set_alarm", "c", emptyMap())
        s.markUndone(c.id)
        // A partly undone group (one step failed) is offered again with what's left.
        assertEquals(listOf("b"), s.lastGroup().map { it.summary })
        s.markUndone(b.id)
        assertEquals(listOf("a"), s.lastGroup().map { it.summary })
    }

    @Test fun emptyWhenNothingLeft() {
        val s = UndoStore(file = null)
        assertTrue(s.lastGroup().isEmpty())
        s.markUndone(s.add("g", "set_alarm", "a", emptyMap()).id)
        assertTrue(s.lastGroup().isEmpty())
    }

    @Test fun keepsOnlyTheLastGroups() {
        val s = UndoStore(file = null, maxGroups = 3)
        for (i in 1..5) {
            s.add("g$i", "set_alarm", "x$i", emptyMap())
            s.add("g$i", "set_alarm", "y$i", emptyMap())
        }
        assertEquals(listOf("g3", "g4", "g5"), s.all().map { it.group }.distinct())
    }
}

class UndoSummaryTest {
    @Test fun effectfulCapabilitiesSayHowToUndoAndOthersDont() {
        assertNotNull(SetAlarm.undoSummary(mapOf("hour" to 7, "minute" to 5)))
        assertNotNull(AddCalendarEvent.undoSummary(mapOf("event_id" to 1L, "title" to "Gym", "dtstart" to 0L)))
        assertNotNull(DeleteCalendarEvent.undoSummary(mapOf("title" to "Gym", "dtstart" to 0L)))
        assertNull(OpenUrl.undoSummary(emptyMap()))
        assertNull(OpenApp.undoSummary(mapOf("package" to "x")))
        assertNull(FindCalendarEvents.undoSummary(emptyMap()))
    }

    @Test fun everyReversibleCapabilityCanBeUndone() {
        // Exception: screen actions in another app (tap, type_text). Ordinary ones are reversible
        // in that app by the user, but Agent Do/Don't can't undo them; irreversible-looking ones always ask.
        for (cap in Registry.all.filter { it.risk == Risk.REVERSIBLE && it !is dev.agentdodont.app.screen.ScreenCapability }) {
            assertNotNull(cap.name, cap.undoSummary(mapOf("hour" to 1, "minute" to 2, "title" to "t", "dtstart" to 0L)))
        }
        for (cap in dev.agentdodont.app.screen.SCREEN_CAPABILITIES) assertNull(cap.name, cap.undoSummary(emptyMap()))
    }

    @Test fun summariesAreHonestAboutLimits() {
        // Alarms can only be switched off by the user; JSON may hand numbers back as Int.
        val alarm = SetAlarm.undoSummary(mapOf("hour" to 7, "minute" to 5))!!
        assertTrue(alarm, alarm.contains("07:05") && alarm.contains("yourself"))
        val series = DeleteCalendarEvent.undoSummary(mapOf("title" to "Standup", "dtstart" to 0L, "rrule" to "FREQ=DAILY"))!!
        assertTrue(series, series.contains("repeating series"))
        val add = AddCalendarEvent.undoSummary(mapOf("event_id" to 9, "title" to "Gym", "dtstart" to 0))!!
        assertTrue(add, add.startsWith("Remove \"Gym\""))
    }
}
