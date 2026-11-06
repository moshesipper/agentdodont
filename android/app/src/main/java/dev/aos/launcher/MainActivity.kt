package dev.aos.launcher

import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Bundle
import android.text.format.DateUtils
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import dev.aos.launcher.agent.Agent
import dev.aos.launcher.capabilities.CallContext
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import dev.aos.launcher.capabilities.CapContext
import dev.aos.launcher.capabilities.Policy
import dev.aos.launcher.capabilities.PolicyConfig
import dev.aos.launcher.capabilities.Registry
import dev.aos.launcher.capabilities.Risk
import dev.aos.launcher.capabilities.Source
import dev.aos.launcher.capabilities.Verdict
import dev.aos.launcher.capabilities.defaultLevel
import dev.aos.launcher.capabilities.label
import dev.aos.launcher.capabilities.CapResult
import dev.aos.launcher.capabilities.Executor
import dev.aos.launcher.capabilities.OpenApp
import dev.aos.launcher.capabilities.ParsedIntent
import dev.aos.launcher.capabilities.QuickParser
import dev.aos.launcher.capabilities.UndoStore
import dev.aos.launcher.history.HistoryScreen
import dev.aos.launcher.screen.ScreenService
import dev.aos.launcher.memory.Memory
import dev.aos.launcher.pairing.PairLink
import dev.aos.launcher.pairing.PairingStore
import dev.aos.launcher.memory.MemoryScreen
import dev.aos.launcher.history.Story
import dev.aos.launcher.history.loadStories
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusProperties
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.text.DateFormat
import java.util.Date

/** "undo", "undo that", "undo it", "undo last", "undo last action". */
private val UNDO_COMMAND = Regex("^undo( that| it| last( action)?)?[.!]?$", RegexOption.IGNORE_CASE)

/** "why", "why did you do that?", "history". */
private val WHY_COMMAND = Regex("^(why( did you do (that|this|it))?|history)[?.!]*$", RegexOption.IGNORE_CASE)

/** "memory", "what do you remember", "what do you know about me". */
private val MEMORY_COMMAND = Regex("^(memory|what do you (remember|know)( about me)?)[?.!]*$", RegexOption.IGNORE_CASE)

/** Whether Claude can be reached right now (shown at the top of the home screen). */
private enum class ClaudeLink { CHECKING, CONNECTED, WIFI, NO_RELAY, NOT_PAIRED }

/** "unpair": forget the Wi-Fi pairing and go back to the USB relay. */
private val UNPAIR_COMMAND = Regex("^unpair[.!]?$", RegexOption.IGNORE_CASE)

class MainActivity : ComponentActivity() {
    /** A pending "Allow?" question. The caller suspends on [answer] until the user taps. */
    private data class Confirmation(
        val summary: String,
        val rule: String,
        val risk: Risk,
        val fromAgent: Boolean,
        val answer: CompletableDeferred<Boolean>,
        val title: String? = null,
        val undoLimits: String? = null,
        val allowLabel: String = "Allow",
        val denyLabel: String = "Don't allow",
    )

    private lateinit var audit: AuditLog
    private lateinit var policyStore: PolicyStore
    private lateinit var executor: Executor
    private var apps by mutableStateOf<List<AppEntry>>(emptyList())
    private var query by mutableStateOf("")
    private var status by mutableStateOf<String?>(null)
    private var homePresses by mutableStateOf(0)
    private var confirmation by mutableStateOf<Confirmation?>(null)
    private var showPolicy by mutableStateOf(false)
    private var showMemory by mutableStateOf(false)
    private var pairRequest by mutableStateOf<PairLink?>(null)
    private var history by mutableStateOf<List<Story>?>(null) // non-null = History screen open
    private var policyLevels by mutableStateOf<Map<String, Verdict>>(emptyMap())
    private var policyConfig by mutableStateOf(PolicyConfig())
    private var pendingPermission: CompletableDeferred<Boolean>? = null
    /** The group "Undo" would reverse right now; offered under the result of an action. */
    private var undoOffer by mutableStateOf<List<UndoStore.Entry>>(emptyList())

    // Agent. Claude is reached only through the laptop relay, which holds the API key: no key is
    // ever in the app. The USB relay token is not in the APK either: the relay writes it into this
    // app's private storage (files/relay_token) over adb, and may replace it at any time, so it is
    // re-read on every request.
    private var agentCache: Pair<String, Agent>? = null
    private var claudeLink by mutableStateOf(ClaudeLink.CHECKING)

    /** Off the main thread: is the relay up, and does this app hold a token for it? */
    private fun probeClaude(): ClaudeLink {
        PairingStore.load(this)?.let { return if (PairingStore.healthy(it)) ClaudeLink.WIFI else ClaudeLink.NO_RELAY }
        val token = try {
            File(filesDir, "relay_token").readText().trim()
        } catch (_: IOException) {
            ""
        }
        if (token.isBlank()) return ClaudeLink.NOT_PAIRED
        return try {
            val c = java.net.URL(getString(R.string.relay_url) + "/health").openConnection() as java.net.HttpURLConnection
            c.connectTimeout = 1500
            c.readTimeout = 1500
            try {
                // Any HTTP answer means a relay is there (an older relay without /health answers 401).
                if (c.responseCode in 200..499) ClaudeLink.CONNECTED else ClaudeLink.NO_RELAY
            } finally {
                c.disconnect()
            }
        } catch (_: IOException) {
            ClaudeLink.NO_RELAY
        }
    }

    private fun refreshClaudeLink() {
        lifecycleScope.launch { claudeLink = withContext(Dispatchers.IO) { probeClaude() } }
    }
    private fun currentAgent(): Agent? {
        // Paired over Wi-Fi wins over the USB relay (debug builds).
        PairingStore.load(this)?.let { p ->
            val credential = "paired:${p.token}"
            agentCache?.let { (c, a) -> if (c == credential) return a }
            return Agent(audit, p.token, relayUrl = p.url, pinnedFingerprint = p.fingerprint).also { agentCache = credential to it }
        }
        val token = try {
            File(filesDir, "relay_token").readText().trim()
        } catch (_: IOException) {
            ""
        }
        if (token.isBlank()) return null
        agentCache?.let { (c, a) -> if (c == token) return a }
        return Agent(audit, token, relayUrl = getString(R.string.relay_url)).also { agentCache = token to it }
    }
    private var agentJob by mutableStateOf<Job?>(null)
    private var currentTask: String? = null
    private var agentLines by mutableStateOf<List<String>>(emptyList())

    private val permissionRequest = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { grants ->
        audit.event("permission_result", "granted" to grants.filterValues { it }.keys.joinToString(),
            "denied" to grants.filterValues { !it }.keys.joinToString())
        if (android.Manifest.permission.READ_CONTACTS in grants.keys) refreshContacts()
        pendingPermission?.complete(grants.values.all { it })
        pendingPermission = null
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        audit = AuditLog(this)
        Memory.init(this)
        policyStore = PolicyStore(this, audit)
        executor = Executor(audit, Policy(), UndoStore(File(filesDir, "undo.json")))
        reloadPolicy()
        handlePairLink(intent)
        // While the home screen is visible, keep the "Claude connected" indicator current.
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.RESUMED) {
                while (true) {
                    claudeLink = withContext(Dispatchers.IO) { probeClaude() }
                    delay(20_000)
                }
            }
        }
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                LaunchedEffect(homePresses) { apps = withContext(Dispatchers.IO) { loadApps(this@MainActivity) } }
                HomeScreen()
                confirmation?.let { ConfirmDialog(it) }
                if (showPolicy) PolicyScreen()
                pairRequest?.let { PairDialog(it) }
                if (showMemory) MemoryScreen(audit) { showMemory = false }
                history?.let { HistoryScreen(it, onClear = ::clearHistory) { history = null } }
            }
        }
    }

    override fun onPause() {
        super.onPause()
        // Leaving Agent Do/Don't while a task runs (it's operating another app): keep it visible and stoppable.
        val job = agentJob
        if (job != null) ScreenService.instance?.showBanner(currentTask ?: "task") { runOnUiThread { stopAgent() } }
    }

    override fun onResume() {
        super.onResume()
        ScreenService.instance?.hideBanner()
        refreshContacts()
        homePresses++ // refresh the app list (installs/uninstalls) whenever home is shown
        // Debug-build simulated agent proposals arrive through the in-process inbox.
        while (true) {
            val c = AgentInbox.poll() ?: break
            audit.event("agent_proposal", "capability" to c.capability, "args" to c.args, "tainted" to c.context.tainted)
            val taskId = newTaskId("debug")
            lifecycleScope.launch {
                status = describe(executeInteractive(c.capability, c.args, c.context.copy(taskId = taskId)), agent = true)
                refreshUndo(taskId)
            }
        }
        while (true) {
            val t = AgentInbox.pollTask() ?: break
            val a = currentAgent() ?: break
            audit.event("intent", "text" to t.text, "handled_by" to "agent", "via" to "debug",
                "simulated_compromise" to t.simulateCompromise, "scripted_attack" to (t.scriptedAttack || t.screenAttack))
            runAgentTask(a, t.text, simulateCompromise = t.simulateCompromise, scriptedAttack = t.scriptedAttack,
                screenAttack = t.screenAttack)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (handlePairLink(intent)) return
        // Home pressed while already home: reset to a clean intent box (a running task keeps going).
        query = ""
        status = null
        if (agentJob == null) agentLines = emptyList()
    }

    private fun launch(app: AppEntry, via: String) {
        audit.event("open_app", "package" to app.packageName, "via" to via)
        try {
            app.launch(this)
        } catch (e: ActivityNotFoundException) {
            status = "Couldn't open ${app.label}."
        }
        query = ""
        status = null
    }

    private fun submit() {
        val text = query.trim()
        if (text.isEmpty()) return
        query = ""
        status = null
        undoOffer = emptyList()
        PairLink.parseTyped(text)?.let { link ->
            agentLines = emptyList()
            pairRequest = link
            return
        }
        if (text.lowercase().startsWith("pair ")) {
            status = "To pair, type: pair <address shown on the laptop> <8-digit code>, e.g. pair 192.168.1.20:8788 1234 5678"
            return
        }
        if (UNPAIR_COMMAND.matches(text)) {
            PairingStore.clear(this)
            agentCache = null
            audit.event("pairing", "result" to "unpaired")
            status = "Unpaired. Claude now goes through the USB relay when the phone is plugged in."
            refreshClaudeLink()
            return
        }
        if (MEMORY_COMMAND.matches(text)) {
            agentLines = emptyList()
            showMemory = true
            return
        }
        if (WHY_COMMAND.matches(text)) {
            agentLines = emptyList()
            openHistory()
            return
        }
        if (UNDO_COMMAND.matches(text)) {
            startUndo(typed = text)
            return
        }
        val best = matchApps(text, apps).firstOrNull()
        val parsed: ParsedIntent? = when {
            isDirectOpen(text, best) -> ParsedIntent(OpenApp.name, mapOf("name" to best!!.label))
            else -> QuickParser.parse(text)
        }
        if (parsed != null) {
            // Fast local path: no model, no network.
            audit.event("intent", "text" to text, "handled_by" to "quick_parser", "capability" to parsed.capability)
            agentLines = emptyList()
            lifecycleScope.launch {
                val ctx = CallContext(Source.USER_DIRECT, taskId = newTaskId("cmd"))
                status = describe(executeInteractive(parsed.capability, parsed.args, ctx), agent = false)
                refreshUndo(ctx.taskId!!)
            }
            return
        }
        val a = currentAgent()
        if (a == null) {
            audit.event("intent", "text" to text, "handled_by" to "none")
            val why = "Claude isn't connected yet: plug the phone into the laptop and run " +
                "`python -m agentdodont relay`, or pair over Wi-Fi (type `pair`)."
            status = "$why Until then I can only handle \"open <app>\", \"alarm 7:30\", " +
                "\"event <title> tomorrow at 17:00\", \"delete event <title>\" and \"open <website>\"."
            return
        }
        audit.event("intent", "text" to text, "handled_by" to "agent")
        runAgentTask(a, text)
    }

    private fun runAgentTask(a: Agent, text: String, simulateCompromise: Boolean = false, scriptedAttack: Boolean = false,
                             screenAttack: Boolean = false) {
        stopAgent(silent = true)
        status = null
        agentLines = listOfNotNull(
            if (simulateCompromise) "⚠ RED-TEAM TEST: Claude told to obey instructions in content (debug)" else null,
            if (scriptedAttack || screenAttack) "⚠ RED-TEAM TEST: a scripted attacker replaces Claude and obeys the injection (debug)"
            else "☁ Asking Claude (cloud, via laptop): \"$text\"",
        )
        val taskId = newTaskId("agent")
        currentTask = text
        agentJob = lifecycleScope.launch {
            val host = object : Agent.Host {
                override suspend fun execute(capability: String, args: Map<String, Any?>, ctx: CallContext): CapResult =
                    withContext(Dispatchers.Main) { executeInteractive(capability, args, ctx.copy(taskId = taskId)) }

                // Suspends until the line is on screen, so lines can't land after the final reply.
                override suspend fun progress(line: String) {
                    withContext(Dispatchers.Main) { agentLines = agentLines + line }
                }
            }
            val out = if (screenAttack) a.runScreenAttack(text, host)
                else if (scriptedAttack) a.runScriptedAttack(text, host)
                else a.run(text, host, simulateCompromise = simulateCompromise, memory = Memory.book().renderForPrompt())
            agentLines = agentLines + out.reply
            agentJob = null
            ScreenService.instance?.hideBanner()
            if (!out.ok) refreshClaudeLink()
            refreshUndo(taskId)
        }
    }

    /** The user's "Clear history": the audit log and the undo list. Not available to the agent. */
    private fun clearHistory() {
        if (agentJob != null) stopAgent()
        audit.clear()
        executor.undo?.clear()
        undoOffer = emptyList()
        agentLines = emptyList()
        status = null
        openHistory()
    }

    /** A pairing link (QR scan or any app): never acted on without the user's confirmation. */
    private fun handlePairLink(intent: Intent?): Boolean {
        val uri = intent?.data ?: return false
        if (uri.scheme != "agentdodont") return false
        val link = PairLink.parseUri(uri.toString())
        if (link == null) {
            status = "That pairing link isn't valid (it must point to your home network)."
            return true
        }
        pairRequest = link
        return true
    }

    private fun startPairing(link: PairLink) {
        status = "Pairing with ${link.host}…"
        agentLines = emptyList()
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { PairingStore.pair(link, android.os.Build.MODEL) }
            }
            result.onSuccess { p ->
                PairingStore.save(this@MainActivity, p)
                agentCache = null
                audit.event("pairing", "result" to "paired", "host" to link.host, "device" to p.deviceId)
                status = "✓ Paired with your laptop's relay at ${link.host}. Claude now works over Wi-Fi."
            }.onFailure { e ->
                audit.event("pairing", "result" to "failed", "host" to link.host, "error" to (e.message ?: e::class.simpleName))
                status = "Pairing failed: ${e.message ?: "couldn't reach ${link.host}"}." +
                    (if (e is dev.aos.launcher.pairing.RelayRefused || e is javax.net.ssl.SSLException) ""
                    else " Is the laptop on the same Wi-Fi and the relay running with --pair?")
            }
            refreshClaudeLink()
        }
    }

    @Composable
    private fun PairDialog(link: PairLink) {
        AlertDialog(
            onDismissRequest = {
                pairRequest = null
                audit.event("pairing", "result" to "cancelled", "host" to link.host)
            },
            title = { Text("Pair with a laptop relay?") },
            text = {
                Column {
                    Text("Address: ${link.host}", style = MaterialTheme.typography.titleMedium)
                    link.shortFingerprint()?.let { Text("Certificate: $it (should match the laptop)") }
                    Spacer(Modifier.height(12.dp))
                    Text(
                        "Only continue if you just started pairing on your own computer. Your Claude requests will " +
                            "go through it. Any app or web page can open a pairing link, so a request you didn't " +
                            "start is a reason to cancel.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
            confirmButton = {
                var armed by remember(link) { mutableStateOf(false) }
                LaunchedEffect(link) { delay(800); armed = true }
                TextButton(onClick = { pairRequest = null; startPairing(link) }, enabled = armed,
                    modifier = Modifier.focusProperties { canFocus = false }) { Text("Pair") }
            },
            dismissButton = {
                TextButton(onClick = {
                    pairRequest = null
                    audit.event("pairing", "result" to "cancelled", "host" to link.host)
                }) { Text("Cancel") }
            },
        )
    }

    private fun openHistory() {
        val labels = apps.associate { it.packageName to it.label }
        lifecycleScope.launch {
            history = withContext(Dispatchers.IO) { loadStories(this@MainActivity, { labels[it] ?: it }) }
        }
    }

    private fun newTaskId(kind: String) = "$kind-${System.currentTimeMillis()}"

    /** Offer Undo only if the newest undoable group came from the request that just finished. */
    private fun refreshUndo(taskId: String) {
        undoOffer = executor.undo?.lastGroup().orEmpty().takeIf { it.firstOrNull()?.group == taskId }.orEmpty()
    }

    /** Undo the most recent group of actions, after showing exactly what that will do. */
    private fun startUndo(typed: String? = null) {
        // Every undo starts its own entry in the log, whether typed or tapped (History relies on it).
        audit.event("intent", "text" to (typed ?: "↶ Undo button"), "handled_by" to "undo")
        if (agentJob != null) {
            status = "Stop or finish the current task before undoing."
            return
        }
        val entries = executor.undo?.lastGroup().orEmpty()
        if (entries.isEmpty()) {
            agentLines = emptyList()
            status = "Nothing to undo."
            return
        }
        undoOffer = emptyList()
        agentLines = emptyList()
        lifecycleScope.launch {
            val answer = CompletableDeferred<Boolean>()
            val age = System.currentTimeMillis() - entries.first().t
            val ago = if (age < 60_000) "just now" else DateUtils.getRelativeTimeSpanString(entries.first().t).toString().lowercase()
            confirmation = Confirmation(
                summary = entries.joinToString("\n") { "• " + it.summary },
                rule = "undo changes your phone too, so it shows what it will do first (done $ago)",
                risk = Risk.REVERSIBLE, fromAgent = false, answer = answer, title = "Undo?",
                allowLabel = "Undo", denyLabel = "Cancel",
            )
            if (!answer.await()) {
                status = "Undo cancelled."
                undoOffer = entries
                return@launch
            }
            val results = executor.undo(CapContext(this@MainActivity, apps, executor.policy.config.trustedApps), entries)
            status = results.joinToString("\n") { (_, r) ->
                when (r) {
                    is CapResult.Ok -> "↶ ${r.message}"
                    is CapResult.Error -> "Couldn't undo: ${r.message}"
                    else -> "Couldn't undo."
                }
            }
        }
    }

    private fun stopAgent(silent: Boolean = false) {
        val job = agentJob ?: return
        job.cancel()
        agentJob = null
        ScreenService.instance?.hideBanner()
        confirmation?.answer?.complete(false)
        confirmation = null
        audit.event("agent_stopped", "by" to if (silent) "new_request" else "user")
        if (!silent) agentLines = agentLines + "Stopped."
    }

    /**
     * Run one capability call to completion on the main thread. Confirmation and permission
     * prompts suspend until the user answers; the policy is re-evaluated after every answer.
     */
    private suspend fun executeInteractive(name: String, args: Map<String, Any?>, ctx: CallContext): CapResult {
        var approved = false
        repeat(4) {
            val r = executor.run(CapContext(this, apps, executor.policy.config.trustedApps), name, args, ctx.copy(nowMs = System.currentTimeMillis()), approved)
            when (r) {
                is CapResult.NeedsConfirmation -> {
                    if (approved) return r
                    val answer = CompletableDeferred<Boolean>()
                    val svc = ScreenService.instance
                    // Not visible = the task is operating another app. (Visible but not yet resumed,
                    // e.g. just brought forward, still gets the normal dialog.)
                    if (!lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) && svc != null) {
                        // Agent Do/Don't isn't on screen (the task is operating another app): ask on top of it.
                        audit.event("confirmation_shown", "where" to "overlay", "summary" to r.summary)
                        svc.confirm(if (ctx.source == Source.AGENT) "The agent wants to:" else "Confirm:", r.summary, r.rule,
                            r.undoLimits ?: if (r.risk == Risk.IRREVERSIBLE) "This can't be undone." else null, answer)
                        val ok = answer.await()
                        audit.event("confirmation", "approved" to ok, "rule" to r.rule, "summary" to r.summary, "where" to "overlay")
                        if (!ok) return CapResult.Declined(r.summary)
                    } else {
                        confirmation = Confirmation(r.summary, r.rule, r.risk, ctx.source == Source.AGENT, answer, undoLimits = r.undoLimits)
                        if (!answer.await()) return CapResult.Declined(r.summary)
                    }
                    approved = true
                }
                is CapResult.NeedsPermission -> {
                    val granted = CompletableDeferred<Boolean>()
                    pendingPermission = granted
                    permissionRequest.launch(r.permissions.toTypedArray())
                    if (!granted.await()) return CapResult.Declined("permission for $name")
                }
                else -> return r
            }
        }
        return CapResult.Error("gave up after repeated prompts")
    }

    private fun describe(r: CapResult, agent: Boolean): String {
        val who = if (agent) "Agent: " else ""
        return when (r) {
            is CapResult.Ok -> "$who✓ ${r.message}"
            is CapResult.Error -> "${who}Couldn't do that: ${r.message}"
            is CapResult.Denied -> "${who}Blocked by policy: ${r.rule}."
            is CapResult.Declined -> "${who}Not done: you declined \"${r.what}\"."
            is CapResult.NeedsConfirmation, is CapResult.NeedsPermission -> "${who}Not done."
        }
    }

    private fun answerConfirmation(c: Confirmation, approved: Boolean) {
        confirmation = null
        audit.event("confirmation", "approved" to approved, "rule" to c.rule, "summary" to c.summary)
        c.answer.complete(approved)
    }

    @Composable
    private fun ConfirmDialog(c: Confirmation) {
        AlertDialog(
            onDismissRequest = { answerConfirmation(c, false) },
            title = { Text(c.title ?: if (c.fromAgent) "The agent wants to:" else "Confirm:") },
            text = {
                Column {
                    Text(c.summary, style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(12.dp))
                    Text("Why I'm asking: ${c.rule}.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    if (c.risk == Risk.IRREVERSIBLE) {
                        Spacer(Modifier.height(8.dp))
                        Text(c.undoLimits ?: "This can't be undone.", color = MaterialTheme.colorScheme.error)
                    }
                }
            },
            confirmButton = {
                // Armed after a short delay so a stray or double tap can't approve an unread prompt,
                // and not focusable so no key event (e.g. a leftover Enter) can press it: touch only.
                var armed by remember(c) { mutableStateOf(false) }
                LaunchedEffect(c) { delay(800); armed = true }
                TextButton(
                    onClick = { answerConfirmation(c, true) },
                    enabled = armed,
                    modifier = Modifier.focusProperties { canFocus = false },
                ) { Text(c.allowLabel) }
            },
            dismissButton = { TextButton(onClick = { answerConfirmation(c, false) }) { Text(c.denyLabel) } },
        )
    }

    /** Normalised numbers and emails of the user's contacts: the allow-list for drafts in tainted tasks. */
    private var knownRecipients: Set<String> = emptySet()

    private fun refreshContacts() {
        if (checkSelfPermission(android.Manifest.permission.READ_CONTACTS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            knownRecipients = emptySet()
            reloadPolicy()
            return
        }
        lifecycleScope.launch {
            knownRecipients = withContext(Dispatchers.IO) {
                buildSet {
                    for ((uri, col) in listOf(
                        android.provider.ContactsContract.CommonDataKinds.Phone.CONTENT_URI to
                            android.provider.ContactsContract.CommonDataKinds.Phone.NUMBER,
                        android.provider.ContactsContract.CommonDataKinds.Email.CONTENT_URI to
                            android.provider.ContactsContract.CommonDataKinds.Email.ADDRESS,
                    )) contentResolver.query(uri, arrayOf(col), null, null, null)?.use { c ->
                        while (c.moveToNext()) c.getString(0)?.let { add(dev.aos.launcher.capabilities.Recipients.normalize(it)) }
                    }
                }
            }
            reloadPolicy()
        }
    }

    private fun reloadPolicy() {
        val config = policyStore.load().copy(knownRecipients = knownRecipients)
        policyLevels = config.levels
        policyConfig = config
        executor.policy.config = config
    }

    @Composable
    private fun PolicyScreen() {
        Dialog(onDismissRequest = { showPolicy = false }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
            Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                Column(Modifier.systemBarsPadding().padding(16.dp).verticalScroll(rememberScrollState())) {
                    Text("Policy", style = MaterialTheme.typography.headlineMedium)
                    Text(
                        "What Agent Do/Don't may do on its own. The policy runs outside the AI, so these settings hold " +
                            "whatever the agent says. Irreversible actions the agent proposes always ask, and once a " +
                            "task has read untrusted content (messages, web pages) every action with an effect asks.",
                        Modifier.padding(vertical = 8.dp),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    for (cap in Registry.all) {
                        val current = policyLevels[cap.name]
                        val default = defaultLevel(cap.risk)
                        Spacer(Modifier.height(12.dp))
                        Text(cap.name.replace('_', ' '), style = MaterialTheme.typography.titleMedium)
                        Text(
                            "${cap.risk.name.lowercase()} · default: ${label(default)}" +
                                (if (current != null) " · your setting: ${label(current)}" else ""),
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            fontSize = 13.sp,
                        )
                        Row {
                            for (v in Verdict.entries) {
                                val selected = (current ?: default) == v
                                TextButton(onClick = {
                                    policyStore.setLevel(cap.name, if (v == default) null else v)
                                    reloadPolicy()
                                }) { Text((if (selected) "● " else "○ ") + label(v)) }
                            }
                        }
                    }
                    SitesSection()
                    TrustedSourcesSection()
                    Spacer(Modifier.height(16.dp))
                    Row {
                        TextButton(onClick = { policyStore.resetAll(); reloadPolicy() }) { Text("Reset to defaults") }
                        Spacer(Modifier.weight(1f))
                        TextButton(onClick = { showPolicy = false }) { Text("Done") }
                    }
                }
            }
        }
    }

    private fun label(v: Verdict) = v.label()

    @Composable
    private fun ClaudeIndicator(modifier: Modifier) {
        val (text, color) = when (claudeLink) {
            ClaudeLink.CHECKING -> "" to MaterialTheme.colorScheme.onSurfaceVariant
            ClaudeLink.CONNECTED -> "● Claude connected" to Color(0xFF7FD48A)
            ClaudeLink.WIFI -> "● Claude connected (Wi-Fi)" to Color(0xFF7FD48A)
            ClaudeLink.NO_RELAY -> "○ Laptop relay not reachable · local commands only" to MaterialTheme.colorScheme.onSurfaceVariant
            ClaudeLink.NOT_PAIRED -> "○ Not paired with the laptop relay · local commands only" to MaterialTheme.colorScheme.onSurfaceVariant
        }
        Text(text, modifier.semantics { contentDescription = "Claude status: $text" }, color = color, fontSize = 12.sp,
            maxLines = 2)
    }

    /** Sites a task that has read untrusted content may still send data to (after asking). */
    @Composable
    private fun SitesSection() {
        val muted = MaterialTheme.colorScheme.onSurfaceVariant
        Spacer(Modifier.height(24.dp))
        Text("Sites", style = MaterialTheme.typography.titleLarge)
        Text(
            "Once a task has read untrusted content (notifications, invitations), opening a web address " +
                "could send what it read to that site. Such a task may only open the sites below, and asks " +
                "you first. Every other site is refused.",
            color = muted, fontSize = 13.sp,
        )
        for (d in policyConfig.allowedDomains.sorted()) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(d, Modifier.weight(1f))
                TextButton(onClick = { policyStore.setAllowedDomain(d, false); reloadPolicy() }) { Text("Remove") }
            }
        }
        if (policyConfig.allowedDomains.isEmpty()) Text("None yet.", color = muted)
        var input by remember { mutableStateOf("") }
        val domain = input.trim().lowercase().removePrefix("https://").removePrefix("http://").substringBefore('/')
        val valid = Regex("^[a-z0-9-]+(\\.[a-z0-9-]+)+$").matches(domain)
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = input, onValueChange = { input = it }, singleLine = true,
                placeholder = { Text("e.g. wikipedia.org") }, modifier = Modifier.weight(1f),
            )
            TextButton(enabled = valid, onClick = {
                policyStore.setAllowedDomain(domain, true); reloadPolicy(); input = ""
            }) { Text("Add") }
        }
    }

    /** Apps whose notifications don't taint a task. */
    @Composable
    private fun TrustedSourcesSection() {
        val muted = MaterialTheme.colorScheme.onSurfaceVariant
        Spacer(Modifier.height(24.dp))
        Text("Trusted notification sources", style = MaterialTheme.typography.titleLarge)
        Text(
            "Notifications are untrusted by default: anyone can send you a message. Trust an app only if " +
                "only you or the app itself write its notifications (e.g. Clock), never a messaging or email app.",
            color = muted, fontSize = 13.sp,
        )
        val current = remember { NotificationReader.current(packageName)?.map { it.pkg }.orEmpty() }
        val labels = (current + policyConfig.trustedApps).distinct().associateWith { appLabel(this, it, apps) }
        val candidates = labels.keys.sortedBy { labels[it] }
        if (candidates.isEmpty()) {
            Text("Apps appear here when they have a notification showing" +
                (if (!NotificationReader.hasAccess(this)) " (Agent Do/Don't needs Notification access)." else "."), color = muted)
        }
        for (pkg in candidates) {
            val trusted = pkg in policyConfig.trustedApps
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(labels[pkg] ?: pkg, Modifier.weight(1f))
                TextButton(onClick = { policyStore.setTrustedApp(pkg, labels[pkg] ?: pkg, !trusted); reloadPolicy() }) {
                    Text(if (trusted) "● Trusted" else "○ Untrusted")
                }
            }
        }
    }

    @Composable
    private fun HomeScreen() {
        val focus = LocalFocusManager.current
        val keyboard = LocalSoftwareKeyboardController.current
        val boxFocus = remember { FocusRequester() }
        BackHandler(enabled = true) { query = ""; status = null; focus.clearFocus() }

        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            Column(
                Modifier
                    .fillMaxSize()
                    .systemBarsPadding()
                    .imePadding()
                    .padding(horizontal = 16.dp),
            ) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    ClaudeIndicator(Modifier.weight(1f).padding(start = 8.dp))
                    TextButton(onClick = { openHistory() }) { Text("History") }
                    TextButton(onClick = { showMemory = true }) { Text("Memory") }
                    TextButton(onClick = { showPolicy = true }) { Text("Policy") }
                }
                Clock()
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it; status = null },
                    modifier = Modifier
                        .fillMaxWidth()
                        .focusRequester(boxFocus)
                        .semantics { contentDescription = "Intent box" },
                    placeholder = { Text("What do you want to do?") },
                    singleLine = true,
                    shape = RoundedCornerShape(24.dp),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Go),
                    // Hide the keyboard on Go so the result, its Undo button and any reply stay visible.
                    keyboardActions = KeyboardActions(onGo = { submit(); keyboard?.hide(); focus.clearFocus() }),
                )
                val lines = if (agentLines.isNotEmpty()) agentLines else listOfNotNull(status)
                for ((i, line) in lines.withIndex()) {
                    Text(
                        line,
                        Modifier.padding(top = if (i == 0) 8.dp else 2.dp, start = 8.dp, end = 8.dp),
                        style = if (i == lines.lastIndex && agentJob == null && agentLines.isNotEmpty())
                            MaterialTheme.typography.bodyLarge else MaterialTheme.typography.bodyMedium,
                        color = if (i == lines.lastIndex && agentJob == null) MaterialTheme.colorScheme.onSurface
                            else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (undoOffer.isNotEmpty() && agentJob == null && lines.isNotEmpty()) {
                    TextButton(onClick = { startUndo() }, Modifier.padding(start = 0.dp)) {
                        Text(if (undoOffer.size == 1) "↶ Undo" else "↶ Undo all ${undoOffer.size}")
                    }
                }
                if (agentJob != null) {
                    Row(Modifier.fillMaxWidth().padding(start = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text("Working…", color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Spacer(Modifier.weight(1f))
                        TextButton(onClick = { stopAgent() }) { Text("Stop") }
                    }
                }
                Spacer(Modifier.height(12.dp))
                val shown = matchApps(query, apps)
                if (query.isNotBlank() && shown.isEmpty()) {
                    Text(
                        "No app matches. Press Go to ask Agent Do/Don't.",
                        Modifier.padding(8.dp),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                LazyVerticalGrid(
                    columns = GridCells.Fixed(4),
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(vertical = 4.dp),
                ) {
                    items(shown, key = { it.packageName + "/" + it.activityName }) { app ->
                        AppCell(app) { launch(app, via = if (query.isBlank()) "grid" else "search") }
                    }
                }
                Dock()
            }
        }
    }

    @Composable
    private fun Clock() {
        var now by remember { mutableStateOf(Date()) }
        LaunchedEffect(Unit) { while (true) { now = Date(); delay(10_000) } }
        Column(Modifier.fillMaxWidth().padding(vertical = 20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Text(DateFormat.getTimeInstance(DateFormat.SHORT).format(now), fontSize = 48.sp)
            Text(DateFormat.getDateInstance(DateFormat.FULL).format(now), color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }

    @Composable
    private fun AppCell(app: AppEntry, onClick: () -> Unit) {
        Column(
            Modifier
                .clickable(onClick = onClick)
                .padding(vertical = 10.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Image(app.icon, contentDescription = null, modifier = Modifier.size(48.dp))
            Text(
                app.label,
                Modifier.padding(top = 4.dp, start = 2.dp, end = 2.dp),
                fontSize = 12.sp,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                textAlign = TextAlign.Center,
            )
        }
    }

    @Composable
    private fun Dock() {
        Row(
            Modifier.fillMaxWidth().padding(vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceEvenly,
        ) {
            for (s in CoreSurface.entries) {
                Box(Modifier.weight(1f), contentAlignment = Alignment.Center) {
                    TextButton(onClick = {
                        audit.event("open_core_surface", "surface" to s.name)
                        try {
                            s.intent(this@MainActivity)?.let { startActivity(it) }
                                ?: run { status = "No ${s.label} app found." }
                        } catch (e: ActivityNotFoundException) {
                            status = "No ${s.label} app found."
                        }
                    }, contentPadding = PaddingValues(horizontal = 2.dp)) {
                        Text(s.label, maxLines = 1, softWrap = false, fontSize = 13.sp)
                    }
                }
            }
        }
    }
}
