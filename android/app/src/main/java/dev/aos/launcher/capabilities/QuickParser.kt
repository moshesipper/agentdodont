package dev.aos.launcher.capabilities

import java.time.LocalDate
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

/**
 * Temporary, model-free parsing for a few unambiguous phrasings, so capabilities can be used from
 * the intent box before Claude is connected (step 4). Anything it doesn't recognise returns null
 * and is left for the agent. It only proposes a call; [validate] still checks the arguments.
 *
 *   "alarm 7:30", "set an alarm for 6:45 am", "wake me up at 7pm", "alarm 6:30 called gym"
 *   "event Dentist tomorrow at 17:00", "meeting with Dan 2026-11-07 3pm for 30 min"
 *   "open example.com", "go to https://news.ycombinator.com"
 */
data class ParsedIntent(val capability: String, val args: Map<String, Any?>)

object QuickParser {
    private const val TIME = """(\d{1,2})(?:[:.](\d{2}))?\s*(am|pm|a\.m\.|p\.m\.)?"""
    private val opt = setOf(RegexOption.IGNORE_CASE)

    private val alarm = Regex("""^(?:set\s+(?:an?\s+)?)?alarm\s+(?:for\s+|at\s+)?$TIME(?:\s+(?:called|named|labell?ed|label)\s+(.+))?$""", opt)
    private val wake = Regex("""^wake\s+me(?:\s+up)?\s+at\s+$TIME$""", opt)
    private val event = Regex(
        """^(?:add\s+(?:an?\s+)?)?(event|meeting|appointment)\s+(.+?)\s+(today|tomorrow|(?:on\s+)?\d{4}-\d{2}-\d{2})\s+(?:at\s+)?$TIME(?:\s+for\s+(\d+)\s*(m|min|mins|minutes|h|hr|hrs|hour|hours))?$""",
        opt,
    )
    private val deleteEvent = Regex("""^(?:delete|remove|cancel)\s+(?:the\s+)?(?:event|meeting|appointment)\s+(.+)$""", opt)
    private val url = Regex("""^(?:open|go\s+to|visit|browse)\s+(\S+)$""", opt)
    // "remember that Dana is my sister" / "remember: ..." is a fact. "remember to buy milk" is a
    // reminder, so it is left for the agent.
    private val remember = Regex("""^remember(?:\s+that\s+|\s*:\s*|\s+(?!to\s))(.+)$""", opt)

    fun parse(input: String, now: LocalDateTime = LocalDateTime.now()): ParsedIntent? {
        val text = input.trim().trimEnd('.', '!', '?').trim()
        if (text.isEmpty()) return null

        // Local and model-free on purpose: telling Agent Do/Don't a fact about yourself needn't go to the cloud.
        remember.matchEntire(input.trim())?.let { m -> return ParsedIntent("remember", mapOf("fact" to m.groupValues[1].trim())) }
        alarm.matchEntire(text)?.let { m ->
            val (h, min) = hm(m.groupValues[1], m.groupValues[2], m.groupValues[3]) ?: return null
            val args = mutableMapOf<String, Any?>("hour" to h, "minute" to min)
            m.groupValues[4].takeIf { it.isNotBlank() }?.let { args["label"] = it.trim() }
            return ParsedIntent(SetAlarm.name, args)
        }
        wake.matchEntire(text)?.let { m ->
            val (h, min) = hm(m.groupValues[1], m.groupValues[2], m.groupValues[3]) ?: return null
            return ParsedIntent(SetAlarm.name, mapOf("hour" to h, "minute" to min))
        }
        event.matchEntire(text)?.let { m ->
            val kind = m.groupValues[1].lowercase()
            val rest = m.groupValues[2].trim()
            val title = if (kind == "event") rest else "${kind.replaceFirstChar { it.uppercase() }} $rest"
            val day = when (val d = m.groupValues[3].lowercase().removePrefix("on").trim()) {
                "today" -> now.toLocalDate()
                "tomorrow" -> now.toLocalDate().plusDays(1)
                else -> runCatching { LocalDate.parse(d) }.getOrNull() ?: return null
            }
            val (h, min) = hm(m.groupValues[4], m.groupValues[5], m.groupValues[6]) ?: return null
            if (h !in 0..23 || min !in 0..59) return null
            val args = mutableMapOf<String, Any?>(
                "title" to title,
                "start" to day.atTime(h, min).format(DateTimeFormatter.ISO_LOCAL_DATE_TIME).take(16),
            )
            m.groupValues[7].takeIf { it.isNotBlank() }?.let { n ->
                val unit = m.groupValues[8].lowercase()
                args["duration_minutes"] = n.toInt() * if (unit.startsWith("h")) 60 else 1
            }
            return ParsedIntent(AddCalendarEvent.name, args)
        }
        deleteEvent.matchEntire(text)?.let { m ->
            return ParsedIntent(DeleteCalendarEvent.name, mapOf("title" to m.groupValues[1].trim()))
        }
        url.matchEntire(text)?.let { m ->
            val target = m.groupValues[1]
            if ('.' in target && OpenUrl.normalize(target) != null) return ParsedIntent(OpenUrl.name, mapOf("url" to target))
        }
        if (' ' !in text && '.' in text && OpenUrl.normalize(text) != null && Regex("""\.[a-zA-Z]{2,}(/|$)""").containsMatchIn(text)) {
            return ParsedIntent(OpenUrl.name, mapOf("url" to text))
        }
        return null
    }

    /** Hour/minute in 24-hour form. Out-of-range values are passed through for validation to reject. */
    private fun hm(hStr: String, mStr: String, ampmRaw: String): Pair<Int, Int>? {
        var h = hStr.toIntOrNull() ?: return null
        val m = if (mStr.isEmpty()) 0 else mStr.toInt()
        val ampm = ampmRaw.lowercase().replace(".", "")
        if (ampm.isNotEmpty()) {
            if (h !in 1..12) return null
            if (ampm == "pm" && h < 12) h += 12
            if (ampm == "am" && h == 12) h = 0
        }
        return h to m
    }
}
