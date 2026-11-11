package dev.agentdodont.app

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.core.graphics.drawable.toBitmap

data class AppEntry(
    val label: String,
    val packageName: String,
    val activityName: String,
    val icon: ImageBitmap,
) {
    fun launch(context: Context) {
        val intent = Intent(Intent.ACTION_MAIN)
            .addCategory(Intent.CATEGORY_LAUNCHER)
            .setComponent(ComponentName(packageName, activityName))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED)
        context.startActivity(intent)
    }
}

/** Every activity with a launcher icon, except this home screen itself. Call off the main thread. */
fun loadApps(context: Context): List<AppEntry> {
    val pm = context.packageManager
    val iconPx = (48 * context.resources.displayMetrics.density).toInt()
    val main = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
    return pm.queryIntentActivities(main, 0)
        .filter { it.activityInfo.packageName != context.packageName }
        .map { ri ->
            AppEntry(
                label = ri.loadLabel(pm).toString(),
                packageName = ri.activityInfo.packageName,
                activityName = ri.activityInfo.name,
                icon = ri.loadIcon(pm).toBitmap(iconPx, iconPx).asImageBitmap(),
            )
        }
        .sortedBy { it.label.lowercase() }
}

/**
 * Local, model-free matching of the intent box against app names. "open chrome", "chrome" and
 * "chr" all match Chrome. Returns apps ordered best-first.
 */
fun matchApps(query: String, apps: List<AppEntry>): List<AppEntry> {
    val q = query.trim().lowercase().removePrefix("open ").removePrefix("launch ").trim()
    if (q.isEmpty()) return apps
    val words = q.split(Regex("\\s+"))
    return apps
        .filter { app -> val l = app.label.lowercase(); words.all { it in l } }
        .sortedWith(compareBy<AppEntry>(
            { it.label.lowercase() != q },          // exact name first
            { !it.label.lowercase().startsWith(q) }, // then prefix
            { it.label.length },
        ))
}

/** True when the text reads as "open <exactly this app>", so it can be handled with no agent. */
fun isDirectOpen(query: String, best: AppEntry?): Boolean {
    if (best == null) return false
    val q = query.trim().lowercase()
    val name = q.removePrefix("open ").removePrefix("launch ").trim()
    return name == best.label.lowercase()
}

/** The name Android shows for a package (also for apps without a launcher icon, e.g. "Shell"). */
fun appLabel(context: Context, pkg: String, apps: List<AppEntry> = emptyList()): String =
    apps.firstOrNull { it.packageName == pkg }?.label
        ?: try {
            context.packageManager.getApplicationLabel(context.packageManager.getApplicationInfo(pkg, 0)).toString()
        } catch (e: android.content.pm.PackageManager.NameNotFoundException) {
            pkg
        }
