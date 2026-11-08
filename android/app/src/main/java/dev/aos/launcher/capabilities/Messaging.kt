package dev.aos.launcher.capabilities

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.provider.ContactsContract.CommonDataKinds.Email
import android.provider.ContactsContract.CommonDataKinds.Phone

/*
 * Messages and email, drafted by Agent Do/Don't and sent by the user. compose_* opens the real app with the
 * draft filled in; the user reads it there and presses Send. Nothing here sends anything.
 *
 * Drafting is how data leaves the phone, so these are sendsDataOut: in a task that has read
 * untrusted content, a draft to anyone outside the user's contacts is refused, and one to a
 * contact asks first (the contacts are the allow-list, like Policy > Sites for web addresses). In
 * any other agent task, a draft to someone outside the contacts asks first.
 */

/** Normalised forms, so "+44 7700 900123" and "07700900123" compare equal. Pure, tested. */
object Recipients {
    private val EMAIL = Regex("""^[^\s@]+@[^\s@]+\.[^\s@]+$""")
    private val PHONE = Regex("""^\+?[\d\s\-().]{6,20}$""")

    fun isEmail(s: String) = EMAIL.matches(s.trim())
    fun isPhone(s: String) = PHONE.matches(s.trim()) && s.count { it.isDigit() } in 6..15

    /** Emails lower-case; phone numbers by their last 9 digits (drops country/trunk prefixes). */
    fun normalize(s: String): String = if ('@' in s) s.trim().lowercase() else s.filter { it.isDigit() }.takeLast(9)
}

object ComposeEmail : Capability {
    override val name = "compose_email"
    override val description = "Open the email app with a filled-in draft. The user reads it and presses Send " +
        "themselves; this never sends. Look up addresses with find_contacts."
    override val risk = Risk.NONE // nothing is sent; the user's own Send tap is the confirmation
    override val output = OutputTrust.Trusted
    override val sendsDataOut = true
    override val params = listOf(
        Param("to", ParamType.STRING, "Recipient email address"),
        Param("subject", ParamType.STRING, "Subject line", required = false),
        Param("body", ParamType.STRING, "The message"),
    )

    override fun check(args: Args) = if (!Recipients.isEmail(args.string("to"))) "'to' must be an email address" else null
    override fun destination(args: Args) = Destination(Recipients.normalize(args.string("to")), recipient = true)
    override fun summarize(args: Args) = "Draft an email to ${args.string("to")}" +
        (args.stringOrNull("subject")?.let { ": \"$it\"" } ?: "") + " (you press Send)"

    override fun execute(ctx: CapContext, args: Args): CapResult {
        val intent = Intent(Intent.ACTION_SENDTO, Uri.parse("mailto:"))
            .putExtra(Intent.EXTRA_EMAIL, arrayOf(args.string("to")))
            .putExtra(Intent.EXTRA_TEXT, args.string("body"))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        args.stringOrNull("subject")?.let { intent.putExtra(Intent.EXTRA_SUBJECT, it) }
        return try {
            ctx.android.startActivity(intent)
            CapResult.Ok("Opened a draft to ${args.string("to")} in the email app. Nothing is sent until the user presses Send.")
        } catch (e: ActivityNotFoundException) {
            CapResult.Error("No email app on this phone")
        }
    }
}

object ComposeMessage : Capability {
    override val name = "compose_message"
    override val description = "Open the messaging app with a filled-in text message. The user reads it and presses " +
        "Send themselves; this never sends. Look up numbers with find_contacts."
    override val risk = Risk.NONE
    override val output = OutputTrust.Trusted
    override val sendsDataOut = true
    override val params = listOf(
        Param("to", ParamType.STRING, "Recipient phone number"),
        Param("text", ParamType.STRING, "The message"),
    )

    override fun check(args: Args) = if (!Recipients.isPhone(args.string("to"))) "'to' must be a phone number" else null
    override fun destination(args: Args) = Destination(Recipients.normalize(args.string("to")), recipient = true)
    override fun summarize(args: Args) = "Draft a text to ${args.string("to")}: \"${args.string("text").take(80)}\" (you press Send)"

    override fun execute(ctx: CapContext, args: Args): CapResult {
        val number = args.string("to").filter { it.isDigit() || it == '+' }
        val intent = Intent(Intent.ACTION_SENDTO, Uri.parse("smsto:$number"))
            .putExtra("sms_body", args.string("text"))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        return try {
            ctx.android.startActivity(intent)
            CapResult.Ok("Opened a text to ${args.string("to")} in the messaging app. Nothing is sent until the user presses Send.")
        } catch (e: ActivityNotFoundException) {
            CapResult.Error("No messaging app on this phone")
        }
    }
}

object FindContacts : Capability {
    override val name = "find_contacts"
    override val description = "Look up contacts whose name contains the text: their phone numbers and email " +
        "addresses. Use \"*\" to list some."
    override val risk = Risk.NONE
    // The user's own address book. (Shared or synced address books could hold names others wrote;
    // the send itself is still the user's tap, and compose_* is refused for non-contacts when tainted.)
    override val output = OutputTrust.Trusted
    override val sendsDataOut = false
    override val permissions = listOf(Manifest.permission.READ_CONTACTS)
    override val params = listOf(Param("query", ParamType.STRING, "Part of the name, or \"*\""))

    override fun summarize(args: Args) = "Look up contacts matching \"${args.string("query")}\""

    override fun execute(ctx: CapContext, args: Args): CapResult {
        val q = args.string("query").trim()
        val cr = ctx.android.contentResolver
        val found = linkedMapOf<String, MutableList<String>>()
        fun collect(uri: Uri, nameCol: String, valueCol: String, kind: String) {
            val (sel, selArgs) = if (q == "*") null to null else "$nameCol LIKE ?" to arrayOf("%${q.replace("%", "")}%")
            cr.query(uri, arrayOf(nameCol, valueCol), sel, selArgs, "$nameCol ASC")?.use { c ->
                while (c.moveToNext() && found.size < 20) {
                    val n = c.getString(0) ?: continue
                    val v = c.getString(1) ?: continue
                    found.getOrPut(n) { mutableListOf() } += "$kind $v"
                }
            }
        }
        // The contact's name. (Careful: Email.DISPLAY_NAME is the address's own label, not the person.)
        val name = android.provider.ContactsContract.Contacts.DISPLAY_NAME_PRIMARY
        collect(Phone.CONTENT_URI, name, Phone.NUMBER, "phone")
        collect(Email.CONTENT_URI, name, Email.ADDRESS, "email")
        if (found.isEmpty()) return CapResult.Ok("No contacts match \"$q\".")
        return CapResult.Ok("Contacts:\n" + found.entries.joinToString("\n") { (n, vs) -> "- $n: ${vs.joinToString(", ")}" })
    }
}
