package dev.agentdodont.app

import android.content.Context
import org.json.JSONObject
import java.io.File

/**
 * Append-only on-device audit log, same JSONL shape as the Stage 0 laptop agent
 * ({"t": seconds, "kind": ..., ...}). Lives in app-private storage.
 * Read it from the laptop with:  adb exec-out run-as dev.agentdodont.app cat files/audit.jsonl
 */
class AuditLog(context: Context) {
    private val file = File(context.filesDir, "audit.jsonl")

    @Synchronized
    fun event(kind: String, vararg fields: Pair<String, Any?>) {
        val obj = JSONObject()
        obj.put("t", System.currentTimeMillis() / 1000.0)
        obj.put("kind", kind)
        for ((k, v) in fields) obj.put(k, if (v is Map<*, *>) JSONObject(v) else v ?: JSONObject.NULL)
        file.appendText(obj.toString() + "\n")
    }

    /**
     * The user's "Clear history": delete every entry. One content-free marker remains, so a clear
     * is visible rather than silent. Only reachable from the History screen, never by the agent.
     */
    @Synchronized
    fun clear(): Int {
        val n = if (file.exists()) file.readLines().count { it.isNotBlank() } else 0
        file.writeText("")
        event("history_cleared", "entries" to n)
        return n
    }
}
