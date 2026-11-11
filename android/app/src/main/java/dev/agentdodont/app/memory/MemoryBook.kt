package dev.agentdodont.app.memory

/**
 * What Agent Do/Don't remembers about the user: short facts in plain sentences. Pure Kotlin (storage and
 * encryption live in [MemoryVault]), so the rules are unit-tested.
 *
 * Every fact records who wrote it. Facts reach memory only from the user, or from Claude in a
 * task the policy let through (a task that read untrusted content must ask first), so what's
 * here is the user's own say-so and is given to Claude as such.
 */
enum class Origin { YOU, CLAUDE }

data class MemoryItem(val id: Int, val text: String, val origin: Origin, val createdAt: Long, val updatedAt: Long)

object MemoryRules {
    const val MAX_ITEMS = 100
    const val MAX_CHARS = 300

    private val card = Regex("""(?:\d[ -]?){13,19}""")
    private val secretWords = Regex(
        """(?<![a-z])(password|passcode|passwd|pin|otp|one[- ]time code|verification code|security code|cvv|cvc|""" +
            """seed phrase|recovery phrase|private key|api key|secret key)(?![a-z])""",
        RegexOption.IGNORE_CASE,
    )

    /** Why [text] can't be remembered, or null if it can. Secrets never go into memory. */
    fun problem(text: String): String? {
        val t = text.trim()
        return when {
            t.isEmpty() -> "there's nothing to remember"
            t.length > MAX_CHARS -> "memories are limited to $MAX_CHARS characters"
            card.containsMatchIn(t) -> "it looks like a card or account number; Agent Do/Don't never stores those"
            secretWords.containsMatchIn(t) -> "it looks like a password or code; Agent Do/Don't never stores secrets"
            else -> null
        }
    }
}

class MemoryBook(initial: List<MemoryItem> = emptyList(), private val onChange: (List<MemoryItem>) -> Unit = {}) {
    private val items = initial.toMutableList()
    private var nextId = (items.maxOfOrNull { it.id } ?: 0) + 1

    @Synchronized fun all(): List<MemoryItem> = items.toList()

    @Synchronized fun get(id: Int): MemoryItem? = items.firstOrNull { it.id == id }

    /** Adds a fact; returns it, or throws IllegalArgumentException with the reason. */
    @Synchronized fun add(text: String, origin: Origin, now: Long = System.currentTimeMillis()): MemoryItem {
        MemoryRules.problem(text)?.let { throw IllegalArgumentException(it) }
        require(items.size < MemoryRules.MAX_ITEMS) { "memory is full (${MemoryRules.MAX_ITEMS} facts); delete some first" }
        items.firstOrNull { it.text.equals(text.trim(), ignoreCase = true) }?.let { return it } // no duplicates
        val item = MemoryItem(nextId++, text.trim(), origin, now, now)
        items += item
        onChange(all())
        return item
    }

    @Synchronized fun update(id: Int, text: String, now: Long = System.currentTimeMillis()): MemoryItem {
        MemoryRules.problem(text)?.let { throw IllegalArgumentException(it) }
        val i = items.indexOfFirst { it.id == id }
        require(i >= 0) { "no memory #$id" }
        // Edited by the user from the Memory screen, so it becomes theirs.
        items[i] = items[i].copy(text = text.trim(), origin = Origin.YOU, updatedAt = now)
        onChange(all())
        return items[i]
    }

    @Synchronized fun remove(id: Int): MemoryItem? {
        val i = items.indexOfFirst { it.id == id }
        if (i < 0) return null
        val gone = items.removeAt(i)
        onChange(all())
        return gone
    }

    /** Put back a removed fact with its original id and dates (undo). */
    @Synchronized fun restore(item: MemoryItem) {
        if (items.any { it.id == item.id }) return
        items += item
        items.sortBy { it.id }
        nextId = maxOf(nextId, item.id + 1)
        onChange(all())
    }

    @Synchronized fun clear() {
        items.clear()
        onChange(all())
    }

    /** The block added to a Claude request, or null when there's nothing to share. */
    @Synchronized fun renderForPrompt(): String? {
        if (items.isEmpty()) return null
        return "What the user has asked you to remember (saved by them, or by you with their approval; " +
            "use it when relevant):\n" + items.joinToString("\n") { "[m${it.id}] ${it.text}" }
    }
}
