package dev.aos.launcher

import android.content.Context
import android.content.Intent
import android.provider.MediaStore
import android.provider.Settings
import android.provider.Telephony

/**
 * Predictable core surfaces (desideratum 8): always in the same place, always one tap, never
 * routed through the model.
 */
enum class CoreSurface(val label: String) {
    PHONE("Phone"), MESSAGES("Messages"), CAMERA("Camera"), SETTINGS("Settings");

    fun intent(context: Context): Intent? = when (this) {
        PHONE -> Intent(Intent.ACTION_DIAL)
        MESSAGES -> Telephony.Sms.getDefaultSmsPackage(context)
            ?.let { context.packageManager.getLaunchIntentForPackage(it) }
        CAMERA -> Intent(MediaStore.INTENT_ACTION_STILL_IMAGE_CAMERA)
        SETTINGS -> Intent(Settings.ACTION_SETTINGS)
    }?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
}
