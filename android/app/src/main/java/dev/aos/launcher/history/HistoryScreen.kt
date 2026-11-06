package dev.aos.launcher.history

import android.content.Context
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
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import org.json.JSONException
import org.json.JSONObject
import java.io.File

/** Read the newest [maxLines] audit events (oldest first) and build stories from them. */
fun loadStories(context: Context, appLabel: (String) -> String, maxLines: Int = 3000): List<Story> {
    val file = File(context.filesDir, "audit.jsonl")
    if (!file.exists()) return emptyList()
    val events = file.readLines().takeLast(maxLines).mapNotNull { line ->
        try {
            val o = JSONObject(line)
            o.keys().asSequence().associateWith { k -> o.get(k).takeUnless { it == JSONObject.NULL } }
        } catch (e: JSONException) {
            null // a torn last line (app killed mid-write) shouldn't hide the rest
        }
    }
    return History.build(events, appLabel)
}

private fun kindLabel(k: Kind) = when (k) {
    Kind.COMMAND -> "Typed command (handled on the phone)"
    Kind.AGENT -> "Asked Claude"
    Kind.UNDO -> "Undo"
    Kind.APP -> "App"
    Kind.POLICY -> "Policy change"
    Kind.MEMORY -> "Memory"
    Kind.CLEARED -> "Privacy & connection"
    Kind.SIMULATED -> "Debug"
    Kind.UNHANDLED -> "Not understood"
}

private fun icon(o: Outcome) = when (o) {
    Outcome.DONE -> "✓"
    Outcome.FAILED -> "✗"
    Outcome.BLOCKED -> "⛔"
    Outcome.DECLINED -> "✋"
    Outcome.NOT_FINISHED -> "…"
}

@Composable
fun HistoryScreen(stories: List<Story>, onClear: () -> Unit, onClose: () -> Unit) {
    var confirmClear by remember { mutableStateOf(false) }
    Dialog(onDismissRequest = onClose, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            Column(Modifier.systemBarsPadding().padding(horizontal = 16.dp)) {
                Row(Modifier.fillMaxWidth().padding(top = 8.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Why did you do that?", style = MaterialTheme.typography.headlineSmall,
                        modifier = Modifier.padding(top = 8.dp))
                    TextButton(onClick = onClose) { Text("Done") }
                }
                Text(
                    "Everything Agent Do/Don't did, newest first, from the on-phone audit log: who asked, which policy " +
                        "rule decided, what you answered, and what happened.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp,
                )
                Spacer(Modifier.height(8.dp))
                if (!confirmClear) {
                    TextButton(onClick = { confirmClear = true }) { Text("Clear history…") }
                } else {
                    Text(
                        "Delete everything listed here and the undo list from this phone? Afterwards nothing " +
                            "can be undone. Your calendar, alarms, memory and settings stay as they are. Requests " +
                            "already sent to Claude were processed by Anthropic and aren't affected by this; the " +
                            "laptop relay's log holds only sizes and costs, never content.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp,
                    )
                    Row {
                        TextButton(onClick = { confirmClear = false }) { Text("Cancel") }
                        TextButton(onClick = { confirmClear = false; onClear() }) {
                            Text("Delete history", color = MaterialTheme.colorScheme.error)
                        }
                    }
                }
                if (stories.isEmpty()) Text("Nothing yet.", Modifier.padding(top = 16.dp))
                LazyColumn(Modifier.fillMaxSize()) {
                    items(stories.take(50)) { StoryCard(it) }
                }
            }
        }
    }
}

@Composable
private fun StoryCard(s: Story) {
    val muted = MaterialTheme.colorScheme.onSurfaceVariant
    Column(Modifier.fillMaxWidth().padding(vertical = 10.dp)) {
        val ms = (s.t * 1000).toLong()
        Text(
            DateUtils.formatDateTime(LocalContext.current, ms, DateUtils.FORMAT_SHOW_TIME) + " · " +
                DateUtils.getRelativeTimeSpanString(ms, System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS) +
                " · " + kindLabel(s.kind),
            color = muted, fontSize = 12.sp,
        )
        Text(s.title, style = MaterialTheme.typography.titleMedium)
        for (step in s.steps) {
            Text("${icon(step.outcome)} ${step.summary}", Modifier.padding(top = 6.dp))
            for (line in step.why()) Text(line, Modifier.padding(start = 20.dp), color = muted, fontSize = 13.sp)
        }
        if (s.kind == Kind.UNHANDLED) {
            Text("No typed command matched and Claude wasn't connected, so nothing ran.", color = muted, fontSize = 13.sp)
        }
        s.reply?.let { Text(if (s.kind == Kind.AGENT) "Claude: $it" else it, Modifier.padding(top = 6.dp)) }
        s.error?.let { Text("Error: $it", Modifier.padding(top = 4.dp), color = MaterialTheme.colorScheme.error, fontSize = 13.sp) }
        if (s.stoppedByUser) Text("You stopped this task.", color = muted, fontSize = 13.sp)
        if (s.modelCalls > 0) {
            Text(
                "Sent to Claude ${s.modelCalls}× · ${"%,d".format(s.inputTokens)} tokens in, " +
                    "${"%,d".format(s.outputTokens)} out" +
                    (if (s.memoriesShared > 0) " · with your ${s.memoriesShared} remembered fact${if (s.memoriesShared > 1) "s" else ""}" else ""),
                Modifier.padding(top = 4.dp), color = muted, fontSize = 12.sp,
            )
        }
        Spacer(Modifier.height(10.dp))
        HorizontalDivider(color = Color.Gray.copy(alpha = 0.25f))
    }
}
