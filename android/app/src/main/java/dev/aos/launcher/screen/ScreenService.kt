package dev.aos.launcher.screen

import android.accessibilityservice.AccessibilityService
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.Rect
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import dev.aos.launcher.appLabel
import dev.aos.launcher.capabilities.CapContext
import dev.aos.launcher.capabilities.CapResult
import kotlinx.coroutines.CompletableDeferred

/**
 * Screen access for the screen tools. Enabled by the user under Settings > Accessibility.
 *
 * Safety properties, enforced here as well as in the policy:
 *  - It never reads or acts on protected packages (Agent Do/Don't itself, system UI, permission prompts).
 *  - Actions go to the accessibility node itself (performAction), never to screen coordinates,
 *    so no action can land on Agent Do/Don't's own overlays (the Stop banner, the confirmation).
 *  - It only acts when one of its own agent tasks asks; it does nothing on its own.
 */
class ScreenService : AccessibilityService() {
    enum class Action { TAP, SET_TEXT }

    private val nodes = mutableMapOf<Int, AccessibilityNodeInfo>()
    private var snapshotPkg: String? = null
    private val main = Handler(Looper.getMainLooper())
    private var banner: View? = null
    private var confirmView: View? = null
    private var pendingAnswer: CompletableDeferred<Boolean>? = null

    override fun onServiceConnected() {
        instance = this
        ScreenState.phoneLanguage = resources.configuration.locales[0].language
        updateForeground()
    }

    override fun onUnbind(intent: android.content.Intent?): Boolean {
        declinePending()
        return super.onUnbind(intent)
    }

    /**
     * If the service goes away while a confirmation is open (accessibility turned off, or another
     * accessibility client suspends it), its overlay disappears with it. Treat that as "Don't
     * allow" so the task ends instead of waiting forever for an answer nobody can give.
     */
    private fun declinePending() {
        pendingAnswer?.complete(false)
        pendingAnswer = null
    }

    override fun onDestroy() {
        declinePending()
        hideBanner()
        if (instance === this) instance = null
        ScreenState.foreground = null
        super.onDestroy()
    }

    override fun onInterrupt() {}

    override fun onConfigurationChanged(newConfig: android.content.res.Configuration) {
        super.onConfigurationChanged(newConfig)
        ScreenState.phoneLanguage = newConfig.locales[0].language // the user changed the phone's language
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event?.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED ||
            event?.eventType == AccessibilityEvent.TYPE_WINDOWS_CHANGED
        ) updateForeground()
    }

    /** The app in the active application window (our own overlays are never "active"). */
    private fun updateForeground() {
        val w = windows.firstOrNull { it.isActive && it.type == android.view.accessibility.AccessibilityWindowInfo.TYPE_APPLICATION }
        val pkg = (w?.root ?: rootInActiveWindow)?.packageName?.toString()
        ScreenState.foreground = pkg
        ScreenState.foregroundLabel = pkg?.let { appLabel(this, it) }
    }

    fun snapshot(ctx: CapContext): Snapshot? {
        updateForeground()
        val root = rootInActiveWindow ?: return null
        val pkg = root.packageName?.toString() ?: return null
        if (ScreenRules.isProtected(pkg)) return null
        nodes.clear()
        snapshotPkg = pkg
        val out = mutableListOf<Element>()
        fun walk(n: AccessibilityNodeInfo, depth: Int) {
            if (out.size >= 150 || depth > 40) return
            if (!n.isVisibleToUser) return
            val own = (n.text ?: n.contentDescription)?.toString()?.trim().orEmpty()
            val interactive = n.isClickable || n.isEditable || n.isScrollable || n.isCheckable
            // A clickable row without text of its own is named by its first texts ("Wi-Fi | On").
            val label = if (own.isEmpty() && n.isClickable && !n.isScrollable) childTexts(n).take(3).joinToString(" | ") else own
            if (interactive || own.isNotEmpty()) {
                val id = out.size + 1
                val r = Rect().also { n.getBoundsInScreen(it) }
                out += Element(
                    id = id, cls = n.className?.toString().orEmpty(), label = label,
                    resId = n.viewIdResourceName?.substringAfter(":id/").orEmpty(),
                    hint = n.hintText?.toString().orEmpty(),
                    clickable = n.isClickable, editable = n.isEditable, scrollable = n.isScrollable,
                    checked = if (n.isCheckable) n.isChecked else null, password = n.isPassword,
                    left = r.left, top = r.top, right = r.right, bottom = r.bottom,
                )
                nodes[id] = n
            }
            for (i in 0 until n.childCount) n.getChild(i)?.let { walk(it, depth + 1) }
        }
        walk(root, 0)
        return Snapshot(pkg, appLabel(ctx.android, pkg, ctx.apps), out, System.currentTimeMillis())
    }

    private fun childTexts(n: AccessibilityNodeInfo): List<String> {
        val acc = mutableListOf<String>()
        fun go(c: AccessibilityNodeInfo, d: Int) {
            if (acc.size >= 3 || d > 6) return
            (c.text ?: c.contentDescription)?.toString()?.trim()?.takeIf { it.isNotEmpty() }?.let { acc += it }
            for (i in 0 until c.childCount) c.getChild(i)?.let { go(it, d + 1) }
        }
        for (i in 0 until n.childCount) n.getChild(i)?.let { go(it, 1) }
        return acc
    }

    /** Re-check the node is still there and still in the app the snapshot came from. */
    private fun live(id: Int): AccessibilityNodeInfo? {
        val n = nodes[id] ?: return null
        if (!n.refresh() || !n.isVisibleToUser) return null
        val pkg = n.packageName?.toString() ?: return null
        if (pkg != snapshotPkg || ScreenRules.isProtected(pkg)) return null
        return n
    }

    fun act(id: Int, action: Action, text: String? = null): CapResult {
        val n = live(id) ?: return CapResult.Error("element $id is no longer on screen; read_screen again")
        return when (action) {
            Action.TAP -> {
                var target: AccessibilityNodeInfo? = n
                while (target != null && !target.isClickable) target = target.parent
                if (target == null || ScreenRules.isProtected(target.packageName?.toString().orEmpty())) {
                    CapResult.Error("element $id can't be tapped")
                } else if (target.performAction(AccessibilityNodeInfo.ACTION_CLICK)) CapResult.Ok("Tapped element $id")
                else CapResult.Error("the app ignored the tap on element $id")
            }
            Action.SET_TEXT -> {
                val b = Bundle().apply { putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text) }
                if (n.isEditable && n.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, b)) CapResult.Ok("Typed into element $id")
                else CapResult.Error("element $id didn't accept text")
            }
        }
    }

    fun scroll(id: Int?, down: Boolean): CapResult {
        val a = if (down) AccessibilityNodeInfo.ACTION_SCROLL_FORWARD else AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD
        val target = if (id != null) live(id) else nodes.values.firstOrNull { it.refresh() && it.isScrollable }
        if (target == null) return CapResult.Error("nothing to scroll; read_screen again")
        return if (target.performAction(a)) CapResult.Ok("Scrolled ${if (down) "down" else "up"}")
        else CapResult.Error("couldn't scroll further ${if (down) "down" else "up"}")
    }

    fun back(): CapResult =
        if (performGlobalAction(GLOBAL_ACTION_BACK)) CapResult.Ok("Pressed Back") else CapResult.Error("Back didn't work")

    // --- overlays: drawn by Agent Do/Don't on top of the operated app, out of the agent's reach -------------

    private fun overlayParams(gravity: Int, touchModal: Boolean) = WindowManager.LayoutParams(
        WindowManager.LayoutParams.MATCH_PARENT, WindowManager.LayoutParams.WRAP_CONTENT,
        WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
        // Never focusable: no key event (a leftover Enter) can press a button on it.
        WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
            (if (touchModal) 0 else WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL),
        PixelFormat.TRANSLUCENT,
    ).apply { this.gravity = gravity }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    /** "Agent Do/Don't is working: ... · Stop" across the top while a task operates another app. */
    fun showBanner(task: String, onStop: () -> Unit) = main.post {
        hideBannerNow()
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(Color.argb(235, 40, 30, 70))
            setPadding(dp(16), dp(28), dp(8), dp(8))
            gravity = Gravity.CENTER_VERTICAL
            addView(TextView(context).apply {
                text = "Agent Do/Don't is working: \"${task.take(60)}\""
                setTextColor(Color.WHITE)
                textSize = 13f
            }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            addView(Button(context).apply { text = "Stop"; setOnClickListener { onStop() } })
        }
        getSystemService(WindowManager::class.java).addView(row, overlayParams(Gravity.TOP, touchModal = false))
        banner = row
    }

    fun hideBanner() = main.post { hideBannerNow() }

    private fun hideBannerNow() {
        banner?.let { runCatching { getSystemService(WindowManager::class.java).removeView(it) } }
        banner = null
    }

    /** The confirmation, shown over the operated app. Allow arms after 0.8 s, touch only. */
    fun confirm(title: String, summary: String, rule: String, warning: String?, answer: CompletableDeferred<Boolean>) = main.post {
        confirmView?.let { runCatching { getSystemService(WindowManager::class.java).removeView(it) } }
        val wm = getSystemService(WindowManager::class.java)
        lateinit var panel: View
        fun finish(ok: Boolean) {
            runCatching { wm.removeView(panel) }
            if (confirmView === panel) confirmView = null
            if (pendingAnswer === answer) pendingAnswer = null
            answer.complete(ok)
        }
        val allow = Button(this).apply { text = "Allow"; isEnabled = false; setOnClickListener { finish(true) } }
        panel = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.rgb(32, 30, 40))
            setPadding(dp(24), dp(20), dp(24), dp(28))
            fun line(s: String, size: Float, color: Int) = addView(TextView(context).apply {
                text = s; textSize = size; setTextColor(color); setPadding(0, dp(4), 0, dp(4))
            })
            line(title, 15f, Color.LTGRAY)
            line(summary, 18f, Color.WHITE)
            line("Why I'm asking: $rule.", 13f, Color.LTGRAY)
            warning?.let { line(it, 13f, Color.rgb(255, 140, 140)) }
            addView(LinearLayout(context).apply {
                gravity = Gravity.END
                addView(Button(context).apply { text = "Don't allow"; setOnClickListener { finish(false) } })
                addView(allow)
            })
        }
        wm.addView(panel, overlayParams(Gravity.BOTTOM, touchModal = true))
        confirmView = panel
        pendingAnswer?.complete(false) // only one question at a time
        pendingAnswer = answer
        main.postDelayed({ allow.isEnabled = true }, 800)
        answer.invokeOnCompletion { main.post { if (confirmView === panel) { runCatching { wm.removeView(panel) }; confirmView = null } } }
    }

    companion object {
        @Volatile var instance: ScreenService? = null
    }
}
