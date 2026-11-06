package dev.aos.launcher.screen

import dev.aos.launcher.capabilities.Args
import dev.aos.launcher.capabilities.CapContext
import dev.aos.launcher.capabilities.CapResult
import dev.aos.launcher.capabilities.OutputTrust
import dev.aos.launcher.capabilities.Param
import dev.aos.launcher.capabilities.ParamType
import dev.aos.launcher.capabilities.Risk
import dev.aos.launcher.capabilities.screenSource

/*
 * The screen-tapping fallback: operate an app that has no typed capability, the way a person
 * would. Every call meets the policy's screen rules (protected screens, scope lock to the app the
 * task opened, per-control risk). Actions go to accessibility nodes, never to screen coordinates,
 * so nothing can "tap through" onto Agent Do/Don't's own overlays.
 */

private const val NO_ACCESS = "Screen access is off: Settings > Accessibility > Installed apps > Agent Do/Don't"

private fun needsElement(args: Args): String? {
    val snap = ScreenState.last ?: return "read_screen first; element numbers come from it"
    if (snap.pkg != ScreenState.foreground) return "the screen changed apps since read_screen; read it again"
    return if (snap.element(args.int("element")) == null) "no element ${args.int("element")} on the last screen read" else null
}

private fun element(args: Args) = ScreenState.last?.element(args.int("element"))

object ReadScreen : ScreenCapability {
    override val name = "read_screen"
    override val description = "List what is on the screen of the app this task opened (with open_app): numbered " +
        "elements with their text and what you can do with them. Read it again after every action."
    override val risk = Risk.NONE
    // Whatever the app shows: emails, messages, web pages. Untrusted by nature.
    override val output = OutputTrust.Untrusted("screen content")
    override val sendsDataOut = false
    override val params = emptyList<Param>()

    override fun summarize(args: Args) = "Read the screen"
    override fun assess(args: Args) = ScreenRules.Assessment(Risk.NONE, "")

    override fun execute(ctx: CapContext, args: Args): CapResult {
        val svc = ScreenService.instance ?: return CapResult.Error(NO_ACCESS)
        val snap = svc.snapshot(ctx) ?: return CapResult.Error("Couldn't read this screen")
        ScreenState.last = snap
        return CapResult.Ok(snap.render(), untrustedFrom = screenSource(snap.appLabel))
    }
}

object Tap : ScreenCapability {
    override val name = "tap"
    override val description = "Tap an element from the last read_screen, by its number."
    override val risk = Risk.REVERSIBLE // per tap, the policy uses assess(): "Send", "Delete"... are irreversible
    override val output = OutputTrust.Trusted
    override val sendsDataOut = false
    override val params = listOf(Param("element", ParamType.INTEGER, "Element number from read_screen"))

    override fun check(args: Args) = needsElement(args)
    override fun summarize(args: Args): String {
        val e = element(args)
        val name = e?.let(ScreenRules::controlName)?.ifBlank { null } ?: e?.label?.take(40) ?: "element ${args.int("element")}"
        return "Tap \"$name\" in ${ScreenState.last?.appLabel ?: "the app"}"
    }
    override fun assess(args: Args) =
        ScreenRules.assess("tap", element(args), ScreenState.last?.pkg.orEmpty(), phoneLanguage = ScreenState.phoneLanguage)

    override fun execute(ctx: CapContext, args: Args): CapResult {
        val svc = ScreenService.instance ?: return CapResult.Error(NO_ACCESS)
        return svc.act(args.int("element"), ScreenService.Action.TAP)
    }
}

object TypeText : ScreenCapability {
    override val name = "type_text"
    override val description = "Replace the text in an editable element from the last read_screen. Doesn't press Enter or Send."
    override val risk = Risk.REVERSIBLE
    override val output = OutputTrust.Trusted
    override val sendsDataOut = false
    override val params = listOf(
        Param("element", ParamType.INTEGER, "Element number of an editable field"),
        Param("text", ParamType.STRING, "The text to put in it"),
    )

    override fun check(args: Args) = needsElement(args)
        ?: if (element(args)?.editable != true) "element ${args.int("element")} isn't editable" else null
    override fun summarize(args: Args) = "Type \"${args.string("text").take(60)}\" into " +
        "\"${element(args)?.let(ScreenRules::controlName)?.ifBlank { null } ?: "a field"}\" in ${ScreenState.last?.appLabel ?: "the app"}"
    override fun assess(args: Args) = ScreenRules.assess("type_text", element(args), ScreenState.last?.pkg.orEmpty(), args.string("text"))

    override fun execute(ctx: CapContext, args: Args): CapResult {
        val svc = ScreenService.instance ?: return CapResult.Error(NO_ACCESS)
        return svc.act(args.int("element"), ScreenService.Action.SET_TEXT, args.string("text"))
    }
}

object Scroll : ScreenCapability {
    override val name = "scroll"
    override val description = "Scroll the screen (or one scrollable element from the last read_screen) up or down."
    override val risk = Risk.NONE
    override val output = OutputTrust.Trusted
    override val sendsDataOut = false
    override val params = listOf(
        Param("direction", ParamType.STRING, "\"down\" (show more below) or \"up\""),
        Param("element", ParamType.INTEGER, "Optional scrollable element number", required = false),
    )

    override fun check(args: Args): String? {
        if (args.string("direction") !in setOf("up", "down")) return "direction must be \"up\" or \"down\""
        return if (args.intOrNull("element") != null) needsElement(args) else null
    }
    override fun summarize(args: Args) = "Scroll ${args.string("direction")} in ${ScreenState.last?.appLabel ?: "the app"}"
    override fun assess(args: Args) = ScreenRules.assess("scroll", null, ScreenState.last?.pkg ?: ScreenState.foreground.orEmpty())

    override fun execute(ctx: CapContext, args: Args): CapResult {
        val svc = ScreenService.instance ?: return CapResult.Error(NO_ACCESS)
        return svc.scroll(args.intOrNull("element"), down = args.string("direction") == "down")
    }
}

object PressBack : ScreenCapability {
    override val name = "press_back"
    override val description = "Press the Back button in the app this task opened."
    override val risk = Risk.NONE
    override val output = OutputTrust.Trusted
    override val sendsDataOut = false
    override val params = emptyList<Param>()

    override fun summarize(args: Args) = "Press Back in ${ScreenState.last?.appLabel ?: "the app"}"
    override fun assess(args: Args) = ScreenRules.assess("back", null, ScreenState.foreground.orEmpty())

    override fun execute(ctx: CapContext, args: Args): CapResult {
        val svc = ScreenService.instance ?: return CapResult.Error(NO_ACCESS)
        return svc.back()
    }
}

val SCREEN_CAPABILITIES = listOf(ReadScreen, Tap, TypeText, Scroll, PressBack)
