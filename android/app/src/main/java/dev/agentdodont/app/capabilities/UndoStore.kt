package dev.agentdodont.app.capabilities

import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Recent undoable actions, grouped by request: one typed command is one group, one agent task is
 * one group ("wake me at 6:30 and add gym at 7" undoes as a unit). Kept in app-private storage so
 * undo survives a restart; only the last [maxGroups] groups are kept.
 *
 * Undo is only ever started by the user (Undo button or typing "undo"), always shows what it will
 * do first, and is not offered to the agent as a tool.
 */
class UndoStore(private val file: File?, private val maxGroups: Int = 20) {
    data class Entry(
        val id: Long,
        val group: String,
        val capability: String,
        val summary: String,
        val data: Map<String, Any?>,
        val t: Long,
        val undone: Boolean = false,
    )

    private val entries = mutableListOf<Entry>()
    private var nextId = 1L

    init {
        load()
    }

    @Synchronized
    fun add(group: String, capability: String, summary: String, data: Map<String, Any?>, t: Long = System.currentTimeMillis()): Entry {
        val e = Entry(nextId++, group, capability, summary, data, t)
        entries += e
        val keep = entries.map { it.group }.distinct().takeLast(maxGroups).toSet()
        entries.retainAll { it.group in keep }
        save()
        return e
    }

    /** The most recent group that still has something to undo, newest action first. */
    @Synchronized
    fun lastGroup(): List<Entry> {
        val group = entries.lastOrNull { !it.undone }?.group ?: return emptyList()
        return entries.filter { it.group == group && !it.undone }.reversed()
    }

    @Synchronized
    fun markUndone(id: Long) {
        val i = entries.indexOfFirst { it.id == id }
        if (i >= 0) {
            entries[i] = entries[i].copy(undone = true)
            save()
        }
    }

    @Synchronized
    fun all(): List<Entry> = entries.toList()

    /** Part of "Clear history": the undo list holds copies of what was changed. */
    @Synchronized
    fun clear() {
        entries.clear()
        save()
    }

    private fun save() {
        val f = file ?: return
        val arr = JSONArray()
        for (e in entries) arr.put(JSONObject().apply {
            put("id", e.id); put("group", e.group); put("capability", e.capability); put("summary", e.summary)
            put("data", JSONObject(e.data.mapValues { it.value ?: JSONObject.NULL })); put("t", e.t); put("undone", e.undone)
        })
        val tmp = File(f.path + ".tmp")
        tmp.writeText(arr.toString())
        tmp.renameTo(f)
    }

    private fun load() {
        val f = file ?: return
        if (!f.exists()) return
        val arr = try {
            JSONArray(f.readText())
        } catch (e: org.json.JSONException) {
            return // a corrupt file only costs the undo history
        }
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            val d = o.getJSONObject("data")
            entries += Entry(o.getLong("id"), o.getString("group"), o.getString("capability"), o.getString("summary"),
                d.keys().asSequence().associateWith { k -> d.get(k).takeUnless { it == JSONObject.NULL } },
                o.getLong("t"), o.getBoolean("undone"))
        }
        nextId = (entries.maxOfOrNull { it.id } ?: 0) + 1
    }
}
