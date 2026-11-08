package dev.aos.launcher.capabilities

import dev.aos.launcher.screen.ScreenCapability
import dev.aos.launcher.screen.ScreenRules
import dev.aos.launcher.screen.ScreenState

/**
 * The policy engine: sits between every proposal and every capability.
 * "The model proposes; the policy engine decides."
 *
 * Pure Kotlin (no Android types) so it is unit-testable and independent of the model. It decides
 * from facts it can verify: the capability's declared risk, the validated arguments, who started
 * the call, whether the task has touched untrusted content, the user's own settings, and recent
 * call history. Every applicable rule is evaluated and the strictest verdict wins; an approval
 * can never override DENY.
 */
enum class Verdict { AUTO, ASK, DENY }

data class Decision(val verdict: Verdict, val rule: String)

enum class Source {
    /** The user typed an explicit command that was parsed without a model. */
    USER_DIRECT,
    /** Proposed by the agent (step 4). */
    AGENT,
}

data class CallContext(
    val source: Source,
    /** The task so far has read untrusted content (email, web page, notification, SMS). */
    val tainted: Boolean = false,
    /** What tainted it, e.g. "notifications from Shell" (shown in rules and confirmations). */
    val taintSources: List<String> = emptyList(),
    val nowMs: Long = System.currentTimeMillis(),
    /** Groups the actions of one request (one typed command or one agent task) for undo. */
    val taskId: String? = null,
    /** The app this agent task opened with open_app; screen tools work only inside it. */
    val operatedApp: String? = null,
    val operatedAppLabel: String? = null,
)

/** How read_screen names its taint source (also used to recognise the operated app's own screen). */
fun screenSource(appLabel: String) = "the screen of $appLabel"

data class PolicyConfig(
    /** User-chosen level per capability; absent = default from risk. */
    val levels: Map<String, Verdict> = emptyMap(),
    val blockedDomains: Set<String> = emptySet(),
    /** Sites a tainted task may still send data to (after asking). Everything else is denied. */
    val allowedDomains: Set<String> = emptySet(),
    /** Packages whose notifications don't taint a task. */
    val trustedApps: Set<String> = emptySet(),
    /** Normalised phone numbers and emails from the user's contacts: the allow-list for drafts. */
    val knownRecipients: Set<String> = emptySet(),
    val maxCallsPerMinute: Int = 30,
)

/** The words the Policy screen uses, so explanations match what the user set. */
fun Verdict.label(): String = when (this) {
    Verdict.AUTO -> "Do it"
    Verdict.ASK -> "Ask me"
    Verdict.DENY -> "Never"
}

fun riskPhrase(risk: Risk): String = when (risk) {
    Risk.NONE -> "has no lasting effect"
    Risk.REVERSIBLE -> "is reversible"
    Risk.IRREVERSIBLE -> "is irreversible"
}

fun defaultLevel(risk: Risk): Verdict = when (risk) {
    Risk.NONE -> Verdict.AUTO
    Risk.REVERSIBLE -> Verdict.AUTO // do-and-report
    Risk.IRREVERSIBLE -> Verdict.ASK
}

class Policy(var config: PolicyConfig = PolicyConfig()) {
    private val recent = ArrayDeque<Pair<String, Long>>() // (capability, time) of executed calls

    fun decide(cap: Capability, args: Args, ctx: CallContext): Decision {
        val found = mutableListOf<Decision>()

        // 0. Screen actions (operating another app): where, and how risky this exact action is.
        var risk = cap.risk
        var riskWhy = ""
        var taintSources = ctx.taintSources
        if (cap is ScreenCapability) {
            val fg = ScreenState.foreground
            val fgName = ScreenState.foregroundLabel?.takeIf { it.isNotBlank() } ?: fg
            when {
                fg == null -> found += Decision(Verdict.DENY, "screen access is off (Settings > Accessibility > Agent Do/Don't)")
                ScreenRules.isProtected(fg) ->
                    found += Decision(Verdict.DENY, "Agent Do/Don't never reads or operates $fgName (its own screens, system UI, permission prompts)")
                ctx.operatedApp == null ->
                    found += Decision(Verdict.DENY, "screen tools only work inside an app this task opened with open_app")
                fg != ctx.operatedApp ->
                    found += Decision(Verdict.DENY, "the screen now shows $fgName, not ${ctx.operatedAppLabel ?: ctx.operatedApp}, " +
                        "the app this task opened")
            }
            val a = cap.assess(args)
            a.forbidden?.let { found += Decision(Verdict.DENY, it) }
            risk = a.risk
            riskWhy = a.reason
            // Reading the operated app's screen is the point of the task: it doesn't make every tap
            // ask. Per-control risk above handles it. Other sources (notifications...) still count.
            ctx.operatedAppLabel?.let { own -> taintSources = taintSources.filter { it != screenSource(own) } }
        }
        val tainted = ctx.tainted && (cap !is ScreenCapability || taintSources.isNotEmpty())

        // 1. Level: the user's setting, else the default for the risk.
        val user = config.levels[cap.name]
        found += if (user != null) {
            Decision(user, "your Policy setting for ${cap.name.replace('_', ' ')} is \"${user.label()}\"")
        } else {
            Decision(defaultLevel(risk), "${cap.name.replace('_', ' ')} ${riskPhrase(risk)}" +
                (if (riskWhy.isNotBlank()) ": $riskWhy" else "") + " (default: \"${defaultLevel(risk).label()}\")")
        }

        // 2. Floor: irreversible actions the agent proposes always need a human, whatever the setting.
        if (ctx.source == Source.AGENT && risk == Risk.IRREVERSIBLE) {
            found += Decision(Verdict.ASK, "irreversible actions proposed by the agent always ask")
        }

        // 3. Taint: once untrusted content is in play, anything with an effect asks first. Anything
        //    that can carry data off the phone (the exfiltration channel) is denied unless the
        //    destination is on the user's allow-list, and asks even then.
        if (tainted) {
            val read = "this task has read untrusted content (" +
                (taintSources.distinct().joinToString().ifEmpty { "e.g. a message or web page" }) + ")"
            if (risk != Risk.NONE) found += Decision(Verdict.ASK, read)
            if (cap.sendsDataOut) {
                val dest = cap.destination(args)
                found += when {
                    dest == null -> Decision(Verdict.DENY, "$read, and Agent Do/Don't can't tell where this would send data")
                    dest.recipient && dest.value in config.knownRecipients ->
                        Decision(Verdict.ASK, "$read, and this would send data to ${dest.value}, one of your contacts")
                    dest.recipient -> Decision(Verdict.DENY, "$read, and ${dest.value} isn't in your contacts")
                    config.allowedDomains.any { d -> dest.value == d || dest.value.endsWith(".$d") } ->
                        Decision(Verdict.ASK, "$read, and this would send data to ${dest.value}")
                    else -> Decision(Verdict.DENY, "$read, and ${dest.value} isn't on your list of sites " +
                        "it may send data to (Policy > Sites)")
                }
            }
        } else if (ctx.source == Source.AGENT && cap.sendsDataOut) {
            // 3b. Untainted, but proposed by the agent: a model can be malicious before reading
            //     anything (it already knows your memory, contacts, calendar). Sending data anywhere
            //     you haven't already allowed asks first, naming the destination. What you typed
            //     yourself (USER_DIRECT) doesn't ask.
            val dest = cap.destination(args)
            when {
                dest == null -> found += Decision(Verdict.ASK, "the agent wants to send data, and Agent Do/Don't can't tell where")
                dest.recipient && dest.value !in config.knownRecipients ->
                    found += Decision(Verdict.ASK, "the agent wants to send data to ${dest.value}, who isn't in your contacts")
                !dest.recipient && config.allowedDomains.none { d -> dest.value == d || dest.value.endsWith(".$d") } ->
                    found += Decision(Verdict.ASK, "the agent wants to send data to ${dest.value}, which isn't on your " +
                        "list of sites (Policy > Sites)")
            }
        }

        // 4. Argument rules.
        if (cap.name == OpenUrl.name) {
            val host = cap.destination(args)?.value
            val blocked = config.blockedDomains.firstOrNull { d -> host == d || host?.endsWith(".$d") == true }
            if (blocked != null) found += Decision(Verdict.DENY, "$blocked is on your blocked-domains list")
        }

        // 5. Rate limit: protects against a runaway loop.
        val windowStart = ctx.nowMs - 60_000
        while (recent.isNotEmpty() && recent.first().second < windowStart) recent.removeFirst()
        val count = recent.count { it.first == cap.name }
        if (count >= config.maxCallsPerMinute) {
            found += Decision(Verdict.DENY, "${cap.name} ran $count times in the last minute (limit ${config.maxCallsPerMinute})")
        }

        // Strictest verdict wins; the explanation lists every rule that reached it.
        val verdict = found.maxOf { it.verdict }
        return Decision(verdict, found.filter { it.verdict == verdict }.joinToString("; ") { it.rule })
    }

    /** Call when a capability actually executes (feeds the rate limit). */
    fun record(cap: Capability, nowMs: Long = System.currentTimeMillis()) {
        recent.addLast(cap.name to nowMs)
    }
}
