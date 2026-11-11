package dev.agentdodont.app.memory

import android.text.format.DateUtils
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import dev.agentdodont.app.AuditLog

/**
 * Everything Agent Do/Don't remembers about the user: view, add, edit, delete, or forget it all. Changes
 * are audited by id only, never by text, so a deleted fact is really gone from Agent Do/Don't's storage.
 */
@Composable
fun MemoryScreen(audit: AuditLog, onClose: () -> Unit) {
    val book = Memory.book()
    var items by remember { mutableStateOf(book.all()) }
    var error by remember { mutableStateOf<String?>(null) }
    var confirmClear by remember { mutableStateOf(false) }
    val muted = MaterialTheme.colorScheme.onSurfaceVariant
    fun refresh() { items = book.all() }

    Dialog(onDismissRequest = onClose, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            Column(Modifier.systemBarsPadding().padding(horizontal = 16.dp)) {
                Row(Modifier.fillMaxWidth().padding(top = 8.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Memory", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.padding(top = 8.dp))
                    TextButton(onClick = onClose) { Text("Done") }
                }
                Text(
                    "What Agent Do/Don't knows about you. Stored encrypted on this phone only. Sent to Claude with each request " +
                        "so it can use it. Deleting a fact removes it from memory; History still lists past requests " +
                        "that mentioned it.",
                    color = muted, fontSize = 13.sp,
                )
                Spacer(Modifier.height(8.dp))

                var input by remember { mutableStateOf("") }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(
                        value = input, onValueChange = { input = it; error = null },
                        placeholder = { Text("e.g. Dana is my sister") }, modifier = Modifier.weight(1f),
                    )
                    TextButton(enabled = input.isNotBlank(), onClick = {
                        try {
                            val item = book.add(input, Origin.YOU)
                            audit.event("memory_change", "action" to "add", "id" to item.id, "by" to "you")
                            input = ""
                            refresh()
                        } catch (e: IllegalArgumentException) {
                            error = "Not saved: ${e.message}."
                        }
                    }) { Text("Add") }
                }
                error?.let { Text(it, color = MaterialTheme.colorScheme.error, fontSize = 13.sp) }
                if (items.isEmpty()) {
                    Text("Nothing yet. Add a fact above, or type \"remember that …\" on the home screen.",
                        Modifier.padding(top = 16.dp), color = muted)
                }

                LazyColumn(Modifier.weight(1f)) {
                    items(items, key = { it.id }) { item ->
                        MemoryRow(item, muted,
                            onSave = { text ->
                                try {
                                    book.update(item.id, text)
                                    audit.event("memory_change", "action" to "edit", "id" to item.id, "by" to "you")
                                    refresh()
                                    null
                                } catch (e: IllegalArgumentException) {
                                    "Not saved: ${e.message}."
                                }
                            },
                            onDelete = {
                                book.remove(item.id)
                                audit.event("memory_change", "action" to "delete", "id" to item.id, "by" to "you")
                                refresh()
                            })
                    }
                }

                Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), horizontalArrangement = Arrangement.End) {
                    if (!confirmClear) {
                        TextButton(enabled = items.isNotEmpty(), onClick = { confirmClear = true }) { Text("Forget everything") }
                    } else {
                        Text("Delete all ${items.size} facts?", Modifier.align(Alignment.CenterVertically), color = muted)
                        TextButton(onClick = { confirmClear = false }) { Text("Cancel") }
                        TextButton(onClick = {
                            val n = items.size
                            book.clear()
                            audit.event("memory_change", "action" to "clear", "count" to n, "by" to "you")
                            confirmClear = false
                            refresh()
                        }) { Text("Delete all", color = MaterialTheme.colorScheme.error) }
                    }
                }
            }
        }
    }
}

@Composable
private fun MemoryRow(item: MemoryItem, muted: Color, onSave: (String) -> String?, onDelete: () -> Unit) {
    var editing by remember { mutableStateOf(false) }
    var text by remember(item) { mutableStateOf(item.text) }
    var error by remember { mutableStateOf<String?>(null) }
    Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        if (editing) {
            OutlinedTextField(value = text, onValueChange = { text = it; error = null }, modifier = Modifier.fillMaxWidth())
            error?.let { Text(it, color = MaterialTheme.colorScheme.error, fontSize = 13.sp) }
            Row {
                TextButton(onClick = { editing = false; text = item.text }) { Text("Cancel") }
                TextButton(onClick = { error = onSave(text); if (error == null) editing = false }) { Text("Save") }
            }
        } else {
            Text(item.text, style = MaterialTheme.typography.bodyLarge)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "m${item.id} · " + (if (item.origin == Origin.YOU) "you" else "saved by Claude") + " · " +
                        (if (System.currentTimeMillis() - item.updatedAt < 60_000) "just now"
                        else DateUtils.getRelativeTimeSpanString(item.updatedAt, System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS)),
                    Modifier.weight(1f), color = muted, fontSize = 12.sp,
                )
                TextButton(onClick = { editing = true }) { Text("Edit") }
                TextButton(onClick = onDelete) { Text("Delete") }
            }
        }
        HorizontalDivider(color = Color.Gray.copy(alpha = 0.25f))
    }
}
