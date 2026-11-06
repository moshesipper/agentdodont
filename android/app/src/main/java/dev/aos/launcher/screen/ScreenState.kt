package dev.aos.launcher.screen

import dev.aos.launcher.capabilities.Args
import dev.aos.launcher.capabilities.Capability

/**
 * What the policy needs to know about the screen, kept free of Android types so the rules are
 * unit-testable. [ScreenService] keeps it current.
 */
object ScreenState {
    /** Package of the app in the foreground, or null if screen access (the accessibility service) is off. */
    @Volatile var foreground: String? = null

    /** Display name of [foreground] ("Clock"), for messages; falls back to the package. */
    @Volatile var foregroundLabel: String? = null

    /** The phone's language (ISO 639 code); outside [Lexicon.COVERED], every tap asks. */
    @Volatile var phoneLanguage: String = java.util.Locale.getDefault().language

    /** The latest read_screen result; element ids are only valid for it. */
    @Volatile var last: Snapshot? = null
}

/** A capability that acts on the screen of another app. The policy applies screen rules to it. */
interface ScreenCapability : Capability {
    /** Risk of this particular action on the current screen (null = can't assess: not allowed). */
    fun assess(args: Args): ScreenRules.Assessment
}
