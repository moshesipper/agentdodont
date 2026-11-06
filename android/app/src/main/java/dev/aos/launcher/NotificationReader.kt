package dev.aos.launcher

import android.app.Notification
import android.content.ComponentName
import android.content.Context
import android.provider.Settings
import android.service.notification.NotificationListenerService

/**
 * Lets Agent Do/Don't read the notifications currently in the shade, on request. Nothing is stored: the
 * read_notifications capability asks the live service for what's there at that moment.
 *
 * Needs the special "Notification access" permission (Settings > Notifications > Notification
 * access > Agent Do/Don't), which the user grants and can revoke at any time.
 */
class NotificationReader : NotificationListenerService() {
    override fun onListenerConnected() {
        instance = this
    }

    override fun onListenerDisconnected() {
        if (instance === this) instance = null
    }

    override fun onDestroy() {
        if (instance === this) instance = null
        super.onDestroy()
    }

    data class Item(val pkg: String, val title: String, val text: String, val postedAt: Long)

    companion object {
        @Volatile private var instance: NotificationReader? = null

        fun hasAccess(context: Context): Boolean {
            val enabled = Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners") ?: return false
            val me = ComponentName(context, NotificationReader::class.java).flattenToString()
            return enabled.split(':').any { it == me }
        }

        /** Newest first; null if the service isn't connected (no access, or not bound yet). */
        fun current(ownPackage: String): List<Item>? {
            val svc = instance ?: return null
            val active = try {
                svc.activeNotifications
            } catch (e: SecurityException) {
                return null
            } ?: return emptyList()
            return active
                .filter { it.packageName != ownPackage && it.notification.flags and Notification.FLAG_GROUP_SUMMARY == 0 }
                .map { sbn ->
                    val ex = sbn.notification.extras
                    Item(
                        pkg = sbn.packageName,
                        title = ex.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty(),
                        text = (ex.getCharSequence(Notification.EXTRA_BIG_TEXT) ?: ex.getCharSequence(Notification.EXTRA_TEXT))
                            ?.toString().orEmpty(),
                        postedAt = sbn.postTime,
                    )
                }
                .filter { it.title.isNotBlank() || it.text.isNotBlank() }
                .sortedByDescending { it.postedAt }
        }
    }
}
