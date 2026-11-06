package dev.aos.launcher.history

/**
 * Turns the audit log into "stories": one per request (a typed command, an agent task, an undo,
 * an app opened from the grid, a policy change), each with its actions and a plain-language
 * answer to "why did you do that?". Pure Kotlin over already-decoded events, so it is
 * unit-testable and works on every log written so far (no ids needed).
 *
 * Requests run one at a time (a new request stops a running agent task; undo waits for it), so a
 * story is everything from one starting event to the next.
 */
enum class Kind { COMMAND, AGENT, UNDO, APP, POLICY, MEMORY, CLEARED, SIMULATED, UNHANDLED }

enum class Outcome { DONE, FAILED, BLOCKED, DECLINED, NOT_FINISHED }

enum class Verdict { AUTO, ASK, DENY }

data class Step(
    val capability: String,
    val summary: String,
    val byAgent: Boolean,
    val tainted: Boolean,
    val verdict: Verdict?,
    val rule: String?,
    /** null = not asked; true/false = your answer to the confirmation. */
    val approved: Boolean?,
    val outcome: Outcome,
    val message: String?,
    val undoable: Boolean,
) {
    /** The answer to "why did you do that?" for this action, in order: who, policy, result. */
    fun why(): List<String> = buildList {
        add(when {
            !byAgent -> "You asked for this directly."
            tainted -> "Claude proposed it, after the task had read untrusted content."
            else -> "Claude proposed it."
        })
        when (verdict) {
            Verdict.AUTO -> add("The policy let it run without asking: ${rule ?: "no rule recorded"}.")
            Verdict.ASK -> add("The policy asked you first: ${rule ?: "no rule recorded"}.")
            Verdict.DENY -> add("The policy blocked it: ${rule ?: "no rule recorded"}.")
            null -> {}
        }
        when (approved) {
            true -> add("You allowed it.")
            false -> add("You declined.")
            null -> {}
        }
        add(when (outcome) {
            Outcome.DONE -> "Result: ${message ?: "done"}."
            Outcome.FAILED -> "It failed: ${message ?: "unknown error"}."
            Outcome.BLOCKED -> "Nothing ran."
            Outcome.DECLINED -> "Nothing ran."
            Outcome.NOT_FINISHED -> "It didn't finish${message?.let { " ($it)" } ?: ""}."
        })
        if (undoable && outcome == Outcome.DONE) add("It can be undone.")
    }
}

data class Story(
    val t: Double,
    val kind: Kind,
    /** What started it: your words, the app opened, or the setting changed. */
    val title: String,
    val steps: List<Step>,
    /** Claude's final reply, or the status shown for undo. */
    val reply: String?,
    val modelCalls: Int,
    val inputTokens: Long,
    val outputTokens: Long,
    val error: String?,
    val stoppedByUser: Boolean,
    /** How many remembered facts were sent to Claude with this request. */
    val memoriesShared: Int = 0,
)

object History {
    private const val UNDO_RULE = "undo changes your phone"
    private val STARTERS = setOf("intent", "agent_proposal", "open_app", "open_core_surface", "policy_change", "memory_change", "history_cleared", "pairing")

    /**
     * [events] oldest first, each a decoded audit line. [appLabel] turns a package name into the
     * name shown on the home screen. Returns stories newest first.
     */
    fun build(events: List<Map<String, Any?>>, appLabel: (String) -> String = { it }): List<Story> {
        val stories = mutableListOf<Builder>()
        for (e in events) {
            val kind = e["kind"] as? String ?: continue
            // Logs written before the Undo button logged its own start: its confirmation is the start.
            if (kind == "confirmation" && (e["rule"] as? String)?.startsWith(UNDO_RULE) == true &&
                stories.lastOrNull()?.kind != Kind.UNDO
            ) {
                stories += Builder((e["t"] as? Number)?.toDouble() ?: 0.0, Kind.UNDO, "↶ Undo button")
            }
            if (kind in STARTERS) {
                // A simulated (debug) proposal belongs to no request of its own; same for undo's intent.
                stories += Builder.start(e, kind, appLabel) ?: continue
                continue
            }
            stories.lastOrNull()?.add(kind, e)
        }
        return stories.map { it.build() }.reversed()
    }

    private class StepB(val capability: String, val byAgent: Boolean, val tainted: Boolean) {
        var summary: String = capability.replace('_', ' ')
        var verdict: Verdict? = null
        var rule: String? = null
        var approved: Boolean? = null
        var outcome = Outcome.NOT_FINISHED
        var message: String? = null
        var undoable = false
        /** Waiting on a confirmation or permission: the next call to the same capability continues this step. */
        var pending = false

        fun build() = Step(capability, summary, byAgent, tainted, verdict, rule, approved, outcome, message, undoable)
    }

    private class Builder(val t: Double, val kind: Kind, val title: String) {
        val steps = mutableListOf<StepB>()
        var reply: String? = null
        var modelCalls = 0
        var tokensIn = 0L
        var tokensOut = 0L
        var error: String? = null
        var stopped = false
        var memoriesShared = 0
        private val undoLines = mutableListOf<String>()

        companion object {
            fun start(e: Map<String, Any?>, kind: String, appLabel: (String) -> String): Builder? {
                val t = (e["t"] as? Number)?.toDouble() ?: 0.0
                return when (kind) {
                    "intent" -> {
                        val k = when (e["handled_by"]) {
                            "agent" -> Kind.AGENT
                            "undo" -> Kind.UNDO
                            "quick_parser" -> Kind.COMMAND
                            else -> Kind.UNHANDLED
                        }
                        val prefix = when {
                            e["scripted_attack"] == true -> "⚠ Red-team test (scripted attacker instead of Claude): "
                            e["simulated_compromise"] == true -> "⚠ Red-team test (Claude told to obey content): "
                            else -> ""
                        }
                        Builder(t, k, "$prefix\"${e["text"]}\"")
                    }
                    "agent_proposal" -> Builder(t, Kind.SIMULATED, "Simulated agent proposal (debug)")
                    "history_cleared" -> Builder(t, Kind.CLEARED, "You cleared the history (${e["entries"]} entries)")
                    "pairing" -> Builder(t, Kind.CLEARED, when (e["result"]) {
                        "paired" -> "Paired with the laptop relay at ${e["host"]} (${e["device"]})"
                        "unpaired" -> "Unpaired from the laptop relay"
                        "cancelled" -> "Pairing with ${e["host"]} cancelled"
                        else -> "Pairing with ${e["host"]} failed: ${e["error"]}"
                    })
                    // Memory screen edits. The text isn't logged, so deleting a memory deletes it.
                    "memory_change" -> Builder(t, Kind.MEMORY, when (e["action"]) {
                        "add" -> "You added memory m${e["id"]}"
                        "edit" -> "You edited memory m${e["id"]}"
                        "delete" -> "You deleted memory m${e["id"]}"
                        "clear" -> "You cleared all memory (${e["count"]} facts)"
                        else -> "Memory changed"
                    })
                    "open_app" -> Builder(t, Kind.APP, "Opened ${appLabel(e["package"] as? String ?: "?")}" +
                        when (e["via"]) { "grid" -> " from the app grid"; "search" -> " from search results"; else -> "" })
                    "open_core_surface" -> Builder(t, Kind.APP, "Opened ${(e["surface"] as? String)?.lowercase() ?: "?"} from the dock")
                    "policy_change" -> Builder(t, Kind.POLICY, when {
                        e["reset"] == true -> "You reset the policy to defaults"
                        e["capability"] != null -> "You set ${(e["capability"] as String).replace('_', ' ')} to " +
                            levelLabel(e["level"] as? String)
                        e["allowed_domain"] != null -> if (e["allowed"] == true)
                            "You allowed tasks that read untrusted content to send data to ${e["allowed_domain"]}"
                            else "You removed ${e["allowed_domain"]} from sites tasks may send data to"
                        e["trusted_app"] != null -> if (e["trusted"] == true)
                            "You trusted notifications from ${e["label"] ?: e["trusted_app"]}"
                            else "You stopped trusting notifications from ${e["label"] ?: e["trusted_app"]}"
                        else -> "You changed blocked domains: ${e["blocked_domains"]}"
                    })
                    else -> null
                }
            }

            fun levelLabel(level: String?) = when (level) {
                "AUTO" -> "\"Do it\""
                "ASK" -> "\"Ask me\""
                "DENY" -> "\"Never\""
                else -> "its default"
            }
        }

        fun add(kind: String, e: Map<String, Any?>) {
            val cur = steps.lastOrNull()
            when (kind) {
                "capability_call" -> {
                    val name = e["name"] as? String ?: return
                    if (cur != null && cur.pending && cur.capability == name) {
                        cur.pending = false // same call again after a confirmation or permission prompt
                    } else {
                        steps += StepB(name, e["source"] == "AGENT", e["tainted"] == true)
                    }
                }
                "decision" -> cur?.apply {
                    verdict = (e["verdict"] as? String)?.let { runCatching { Verdict.valueOf(it) }.getOrNull() }
                    rule = e["rule"] as? String
                    (e["summary"] as? String)?.let { summary = it }
                }
                "confirmation" -> {
                    // An undo confirmation has no step; record it on the story instead.
                    if (this.kind == Kind.UNDO) {
                        if (e["approved"] == false) undoLines += "You cancelled the undo."
                    } else cur?.approved = e["approved"] as? Boolean
                }
                "capability_result" -> cur?.apply {
                    when {
                        e["ok"] == true -> { outcome = Outcome.DONE; message = e["message"] as? String; pending = false }
                        e["needs_confirmation"] != null || e["needs_permission"] != null -> {
                            pending = true
                            if (e["needs_permission"] != null) message = "waiting for permission"
                        }
                        e["denied"] != null -> { outcome = Outcome.BLOCKED; pending = false }
                        e["declined"] != null -> { outcome = Outcome.DECLINED; pending = false }
                        else -> { outcome = Outcome.FAILED; message = e["message"] as? String; pending = false }
                    }
                }
                "permission_result" -> if (!(e["denied"] as? String).isNullOrBlank()) {
                    cur?.apply { outcome = Outcome.DECLINED; message = "you denied the permission"; pending = false }
                }
                "undo_recorded" -> cur?.undoable = true
                "undo_result" -> undoLines += (if (e["ok"] == true) "↶ " else "Couldn't undo: ") + (e["message"] ?: "")
                "model_call" -> {
                    modelCalls++
                    tokensIn += (e["input_tokens"] as? Number)?.toLong() ?: 0
                    tokensIn += (e["cache_read"] as? Number)?.toLong() ?: 0
                    tokensIn += (e["cache_write"] as? Number)?.toLong() ?: 0
                    tokensOut += (e["output_tokens"] as? Number)?.toLong() ?: 0
                }
                "agent_done" -> reply = e["reply"] as? String
                "agent_task" -> memoriesShared = (e["memories"] as? Number)?.toInt() ?: 0
                "agent_error" -> error = e["error"] as? String
                "agent_stopped" -> if (e["by"] == "user") stopped = true
            }
        }

        fun build(): Story {
            // A step still waiting when the story ended was never answered (e.g. the task was stopped).
            // "Don't allow" ends the call in the UI without another executor run, so a step left
            // waiting with your "no" on record was declined; one left waiting with no answer at all
            // was cut short (task stopped, app closed).
            val built = steps.map { s ->
                if (s.pending && s.outcome == Outcome.NOT_FINISHED) {
                    if (s.approved == false) s.outcome = Outcome.DECLINED
                    else if (s.approved == null) s.message = s.message ?: "no answer"
                }
                s.build()
            }
            val r = if (kind == Kind.UNDO) undoLines.joinToString("\n").ifBlank { reply } else reply
            return Story(t, kind, title, built, r, modelCalls, tokensIn, tokensOut, error, stopped, memoriesShared)
        }
    }
}
