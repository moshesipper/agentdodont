package dev.aos.launcher.capabilities

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.LocalDateTime

class QuickParserTest {
    private val now = LocalDateTime.of(2026, 11, 4, 17, 0)
    private fun p(s: String) = QuickParser.parse(s, now)

    @Test fun alarms() {
        assertEquals(ParsedIntent("set_alarm", mapOf("hour" to 7, "minute" to 30)), p("alarm 7:30"))
        assertEquals(ParsedIntent("set_alarm", mapOf("hour" to 6, "minute" to 45)), p("Set an alarm for 6:45 am"))
        assertEquals(ParsedIntent("set_alarm", mapOf("hour" to 19, "minute" to 0)), p("wake me up at 7pm"))
        assertEquals(ParsedIntent("set_alarm", mapOf("hour" to 0, "minute" to 15)), p("alarm 12:15 am"))
        assertEquals(ParsedIntent("set_alarm", mapOf("hour" to 12, "minute" to 0)), p("alarm 12 pm"))
        assertEquals(ParsedIntent("set_alarm", mapOf("hour" to 6, "minute" to 30, "label" to "gym")), p("alarm 6:30 called gym"))
        assertEquals(ParsedIntent("set_alarm", mapOf("hour" to 7, "minute" to 30)), p("alarm 7.30!"))
    }

    @Test fun invalidTimesAreLeftForValidationOrRejected() {
        assertEquals(mapOf("hour" to 25, "minute" to 0), p("alarm 25")!!.args) // parser passes it on...
        assertTrue(validate(SetAlarm, p("alarm 25")!!.args) is Validation.Invalid) // ...validation rejects it
        assertNull(p("alarm 13pm"))
    }

    @Test fun events() {
        assertEquals(
            ParsedIntent("add_calendar_event", mapOf("title" to "Dentist", "start" to "2026-11-05T17:00")),
            p("event Dentist tomorrow at 17:00"),
        )
        assertEquals(
            ParsedIntent("add_calendar_event", mapOf("title" to "Meeting with Dan", "start" to "2026-11-07T15:00", "duration_minutes" to 30)),
            p("meeting with Dan 2026-11-07 3pm for 30 min"),
        )
        assertEquals(
            ParsedIntent("add_calendar_event", mapOf("title" to "Gym", "start" to "2026-11-04T18:30", "duration_minutes" to 120)),
            p("add event Gym today at 6:30pm for 2 hours"),
        )
    }

    @Test fun deleteEvent() {
        assertEquals(ParsedIntent("delete_calendar_event", mapOf("title" to "Dentist")), p("delete event Dentist"))
        assertEquals(ParsedIntent("delete_calendar_event", mapOf("title" to "team sync")), p("cancel the meeting team sync"))
    }

    @Test fun urls() {
        assertEquals(ParsedIntent("open_url", mapOf("url" to "example.com")), p("open example.com"))
        assertEquals(ParsedIntent("open_url", mapOf("url" to "https://news.ycombinator.com")), p("go to https://news.ycombinator.com"))
        assertEquals(ParsedIntent("open_url", mapOf("url" to "wikipedia.org/wiki/Android")), p("wikipedia.org/wiki/Android"))
        assertNull(p("open chrome")) // app, not a URL: handled by direct open
        assertNull(p("open javascript:alert(1)"))
    }

    @Test fun unrecognisedIsLeftForTheAgent() {
        assertNull(p("remind me to call mom"))
        assertNull(p("what's the weather"))
        assertNull(p(""))
    }
}

class ValidationTest {
    @Test fun alarmRanges() {
        assertTrue(validate(SetAlarm, mapOf("hour" to 7, "minute" to 30)) is Validation.Valid)
        assertTrue(validate(SetAlarm, mapOf("hour" to 24, "minute" to 0)) is Validation.Invalid)
        assertTrue(validate(SetAlarm, mapOf("hour" to 7)) is Validation.Invalid)
        assertTrue(validate(SetAlarm, mapOf("hour" to "7", "minute" to 0)) is Validation.Invalid)
    }

    @Test fun jsonNumbersFromAModelAreAccepted() {
        // Tool-call JSON may decode integers as Double or Long.
        val v = validate(SetAlarm, mapOf("hour" to 7.0, "minute" to 30L))
        assertTrue(v is Validation.Valid)
        assertEquals(7, (v as Validation.Valid).args.int("hour"))
        assertTrue(validate(SetAlarm, mapOf("hour" to 7.5, "minute" to 0)) is Validation.Invalid)
    }

    @Test fun unknownParametersAreRejected() {
        assertTrue(validate(SetAlarm, mapOf("hour" to 7, "minute" to 0, "repeat" to true)) is Validation.Invalid)
    }

    @Test fun calendarStartFormat() {
        assertTrue(validate(AddCalendarEvent, mapOf("title" to "x", "start" to "2026-11-05T17:00")) is Validation.Valid)
        assertTrue(validate(AddCalendarEvent, mapOf("title" to "x", "start" to "tomorrow 5pm")) is Validation.Invalid)
    }

    @Test fun urlSchemes() {
        assertEquals("https://example.com", OpenUrl.normalize("example.com"))
        assertEquals("http://example.com/a?b=1", OpenUrl.normalize("http://example.com/a?b=1"))
        assertNull(OpenUrl.normalize("intent://scan/#Intent;scheme=zxing;end"))
        assertNull(OpenUrl.normalize("file:///sdcard/secret.txt"))
        assertNull(OpenUrl.normalize("javascript:alert(1)"))
        assertTrue(validate(OpenUrl, mapOf("url" to "file:///etc/hosts")) is Validation.Invalid)
    }
}

class RegistryTest {
    @Test fun everyCapabilityHasAValidToolSchema() {
        val names = Registry.all.map { it.name }
        assertEquals(names.toSet().size, names.size) // unique names
        for (cap in Registry.all) {
            val schema = toolSchema(cap)
            assertTrue(Regex("^[a-z_]+$").matches(schema["name"] as String))
            @Suppress("UNCHECKED_CAST")
            val input = schema["input_schema"] as Map<String, Any>
            @Suppress("UNCHECKED_CAST")
            val props = input["properties"] as Map<String, Any>
            @Suppress("UNCHECKED_CAST")
            assertTrue(props.keys.containsAll(input["required"] as List<String>))
        }
    }

    @Test fun riskClasses() {
        assertEquals(Risk.REVERSIBLE, Registry.get("set_alarm")!!.risk)
        assertEquals(Risk.NONE, Registry.get("open_url")!!.risk)
        assertTrue(Registry.get("find_calendar_events")!!.untrustedOutput) // invite titles are attacker-controllable
        assertTrue(Registry.get("read_notifications")!!.untrustedOutput) // anyone can send you a message
        // Only open_url can carry data to a third party.
        assertEquals(listOf("open_url", "compose_email", "compose_message"), Registry.all.filter { it.sendsDataOut }.map { it.name })
    }
}
