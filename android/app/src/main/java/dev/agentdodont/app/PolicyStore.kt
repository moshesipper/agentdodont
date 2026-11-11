package dev.agentdodont.app

import android.content.Context
import dev.agentdodont.app.capabilities.PolicyConfig
import dev.agentdodont.app.capabilities.Verdict

/** Persists the user's policy settings. Every change is also written to the audit log. */
class PolicyStore(context: Context, private val audit: AuditLog) {
    private val prefs = context.getSharedPreferences("policy", Context.MODE_PRIVATE)

    fun load(): PolicyConfig {
        val levels = prefs.all.mapNotNull { (k, v) ->
            if (!k.startsWith("level.")) null
            else runCatching { k.removePrefix("level.") to Verdict.valueOf(v as String) }.getOrNull()
        }.toMap()
        val domains = prefs.getStringSet("blocked_domains", emptySet())!!.toSet()
        return PolicyConfig(
            levels = levels,
            blockedDomains = domains,
            allowedDomains = prefs.getStringSet("allowed_domains", emptySet())!!.toSet(),
            trustedApps = prefs.getStringSet("trusted_apps", emptySet())!!.toSet(),
        )
    }

    /** level = null resets the capability to its default. */
    fun setLevel(capability: String, level: Verdict?) {
        prefs.edit().apply {
            if (level == null) remove("level.$capability") else putString("level.$capability", level.name)
        }.apply()
        audit.event("policy_change", "capability" to capability, "level" to (level?.name ?: "default"))
    }

    fun setBlockedDomains(domains: Set<String>) {
        prefs.edit().putStringSet("blocked_domains", domains).apply()
        audit.event("policy_change", "blocked_domains" to domains.sorted().joinToString())
    }

    /** Sites a tainted task may send data to (after asking); other agent tasks open them without asking. */
    fun setAllowedDomain(domain: String, allowed: Boolean) {
        val cur = prefs.getStringSet("allowed_domains", emptySet())!!.toMutableSet()
        if (allowed) cur += domain else cur -= domain
        prefs.edit().putStringSet("allowed_domains", cur).apply()
        audit.event("policy_change", "allowed_domain" to domain, "allowed" to allowed)
    }

    /** Apps whose notifications don't taint a task. */
    fun setTrustedApp(pkg: String, label: String, trusted: Boolean) {
        val cur = prefs.getStringSet("trusted_apps", emptySet())!!.toMutableSet()
        if (trusted) cur += pkg else cur -= pkg
        prefs.edit().putStringSet("trusted_apps", cur).apply()
        audit.event("policy_change", "trusted_app" to pkg, "label" to label, "trusted" to trusted)
    }

    fun resetAll() {
        prefs.edit().clear().apply()
        audit.event("policy_change", "reset" to true)
    }
}
