package dev.aos.launcher.capabilities

import android.content.Context
import dev.aos.launcher.AppEntry

/**
 * A typed capability: a named action with typed parameters, a risk class, and an implementation
 * over Android APIs. The same definition will feed the policy engine (step 3) and Claude's tool
 * list (step 4), so the three can never drift apart.
 *
 * Arguments travel as a JSON-like Map<String, Any?> because that is what a model's tool call
 * produces; [validate] turns it into checked values before anything runs.
 */
enum class Risk {
    /** No lasting effect (open an app or a web page). */
    NONE,
    /** Changes state but can be undone (alarm, calendar event). */
    REVERSIBLE,
    /** Cannot be taken back (send, pay, delete). Ask-first by default. */
    IRREVERSIBLE,
}

enum class ParamType { STRING, INTEGER, BOOLEAN }

data class Param(
    val name: String,
    val type: ParamType,
    val description: String,
    val required: Boolean = true,
    val min: Long? = null,
    val max: Long? = null,
)

/**
 * Where a capability's output comes from, declared explicitly by every capability (there is no
 * default, so forgetting it is a compile error rather than a silent "trusted").
 */
sealed interface OutputTrust {
    /** Only the phone's own state or what the user wrote. */
    data object Trusted : OutputTrust

    /** May contain text written by others, e.g. "notifications" or "calendar entries". */
    data class Untrusted(val what: String) : OutputTrust
}

/** A web host (checked against Policy > Sites) or a recipient (checked against the user's contacts). */
data class Destination(val value: String, val recipient: Boolean)

sealed interface CapResult {
    /**
     * [undo] is data needed to reverse the action later (e.g. a calendar event id).
     * [untrustedFrom]: for a capability with untrusted output, what this particular result
     * actually contains from untrusted sources ("notifications from Shell"), or "" if everything
     * in it came from sources the user trusts. null = use the capability's declaration.
     */
    data class Ok(
        val message: String,
        val undo: Map<String, Any?> = emptyMap(),
        val untrustedFrom: String? = null,
    ) : CapResult
    data class Error(val message: String) : CapResult
    data class NeedsPermission(val permissions: List<String>, val why: String) : CapResult
    /** Policy said ASK: show [summary] and [rule] to the user, then re-run with approval. */
    data class NeedsConfirmation(val summary: String, val rule: String, val risk: Risk, val undoLimits: String? = null) : CapResult
    /** Policy said DENY. Nothing ran. */
    data class Denied(val rule: String) : CapResult
    /** The user answered "Don't allow" (or denied a permission). Nothing ran. */
    data class Declined(val what: String) : CapResult
}

/** What a capability may use at run time. [trustedApps]: packages whose notifications the user trusts. */
class CapContext(
    val android: Context,
    val apps: List<AppEntry>,
    val trustedApps: Set<String> = emptySet(),
    /** Who made this call (set by the executor): lets memory record whether you or Claude wrote a fact. */
    val source: Source = Source.AGENT,
)

interface Capability {
    val name: String
    val description: String
    val params: List<Param>
    val risk: Risk
    val permissions: List<String> get() = emptyList()

    /**
     * REQUIRED. Whether the result can contain content the user didn't write (messages, web
     * pages, notifications, invitations). Once such content enters an agent task, the task is
     * tainted and every action with an effect asks first.
     */
    val output: OutputTrust

    val untrustedOutput: Boolean get() = output is OutputTrust.Untrusted

    /**
     * REQUIRED. True if running it can carry data off the phone to a third party (opening a URL
     * puts whatever is in it in someone's server log). In a tainted task such calls are denied
     * unless the destination is on the user's allow-list, because they are how injected
     * instructions exfiltrate what the task has read.
     */
    val sendsDataOut: Boolean

    /** Where a sendsDataOut call would send data (site host or normalised recipient), for the allow-lists. */
    fun destination(args: Args): Destination? = null

    /** Extra checks beyond types and ranges; return an error message or null. Pure (no Android). */
    fun check(args: Args): String? = null

    /** One plain-language line describing exactly what will happen, for confirmations and logs. */
    fun summarize(args: Args): String =
        "$name(" + args.asMap().entries.joinToString { "${it.key}=${it.value}" } + ")"

    fun execute(ctx: CapContext, args: Args): CapResult

    /**
     * How to reverse a past execution, given the [CapResult.Ok.undo] data it returned: one line for
     * the confirmation ("Remove "Gym" (Thu 07:00) from your calendar"), or null if this capability
     * has nothing to undo. Pure (no Android).
     */
    fun undoSummary(data: Map<String, Any?>): String? = null

    /**
     * For an irreversible capability that can still be partly undone: what undo can't bring back,
     * shown in its confirmation instead of a flat "This can't be undone."
     */
    val undoLimits: String? get() = null

    /** Reverse a past execution. Only called after the user confirmed [undoSummary]. */
    fun undo(ctx: CapContext, data: Map<String, Any?>): CapResult = CapResult.Error("$name can't be undone")
}

/** Undo data round-trips through JSON, so numbers may come back as Int or Long. */
internal fun Map<String, Any?>.long(key: String): Long? = (this[key] as? Number)?.toLong()
internal fun Map<String, Any?>.str(key: String): String? = this[key] as? String

internal fun formatWhen(epochMs: Long): String = java.time.Instant.ofEpochMilli(epochMs)
    .atZone(java.time.ZoneId.systemDefault())
    .format(java.time.format.DateTimeFormatter.ofPattern("EEE d MMM HH:mm"))

/** Validated arguments. Only constructed by [validate]. */
class Args internal constructor(private val values: Map<String, Any?>) {
    fun string(name: String): String = values[name] as String
    fun stringOrNull(name: String): String? = values[name] as String?
    fun int(name: String): Int = (values[name] as Long).toInt()
    fun intOrNull(name: String): Int? = (values[name] as Long?)?.toInt()
    fun bool(name: String, default: Boolean = false): Boolean = values[name] as Boolean? ?: default
    fun asMap(): Map<String, Any?> = values
}

sealed interface Validation {
    data class Valid(val args: Args) : Validation
    data class Invalid(val error: String) : Validation
}

/** Type-check raw arguments against a capability's parameter list. Pure, unit-testable. */
fun validate(cap: Capability, raw: Map<String, Any?>): Validation {
    val unknown = raw.keys - cap.params.map { it.name }.toSet()
    if (unknown.isNotEmpty()) return Validation.Invalid("unknown parameter(s): ${unknown.joinToString()}")
    val out = mutableMapOf<String, Any?>()
    for (p in cap.params) {
        val v = raw[p.name]
        if (v == null) {
            if (p.required) return Validation.Invalid("missing required parameter '${p.name}'")
            continue
        }
        out[p.name] = when (p.type) {
            ParamType.STRING -> (v as? String)?.takeIf { it.isNotBlank() }
                ?: return Validation.Invalid("'${p.name}' must be a non-empty string")
            ParamType.BOOLEAN -> v as? Boolean ?: return Validation.Invalid("'${p.name}' must be true or false")
            ParamType.INTEGER -> {
                val n: Long = when (v) {
                    is Int -> v.toLong()
                    is Long -> v
                    is Double -> if (v % 1.0 == 0.0) v.toLong() else return Validation.Invalid("'${p.name}' must be a whole number")
                    else -> return Validation.Invalid("'${p.name}' must be an integer")
                }
                if (p.min != null && n < p.min) return Validation.Invalid("'${p.name}' must be ≥ ${p.min}")
                if (p.max != null && n > p.max) return Validation.Invalid("'${p.name}' must be ≤ ${p.max}")
                n
            }
        }
    }
    val args = Args(out)
    cap.check(args)?.let { return Validation.Invalid(it) }
    return Validation.Valid(args)
}

/** JSON-Schema-shaped description of a capability, ready to become a Claude tool in step 4. */
fun toolSchema(cap: Capability): Map<String, Any> {
    val props = cap.params.associate { p ->
        val type = when (p.type) {
            ParamType.STRING -> "string"
            ParamType.INTEGER -> "integer"
            ParamType.BOOLEAN -> "boolean"
        }
        p.name to buildMap<String, Any> {
            put("type", type)
            put("description", p.description)
            p.min?.let { put("minimum", it) }
            p.max?.let { put("maximum", it) }
        }
    }
    return mapOf(
        "name" to cap.name,
        "description" to cap.description,
        "input_schema" to mapOf(
            "type" to "object",
            "properties" to props,
            "required" to cap.params.filter { it.required }.map { it.name },
            "additionalProperties" to false,
        ),
    )
}
