package dev.agentdodont.app.memory

import dev.agentdodont.app.capabilities.Args
import dev.agentdodont.app.capabilities.CapContext
import dev.agentdodont.app.capabilities.CapResult
import dev.agentdodont.app.capabilities.Capability
import dev.agentdodont.app.capabilities.OutputTrust
import dev.agentdodont.app.capabilities.Param
import dev.agentdodont.app.capabilities.ParamType
import dev.agentdodont.app.capabilities.Risk
import dev.agentdodont.app.capabilities.Source
import dev.agentdodont.app.capabilities.long
import dev.agentdodont.app.capabilities.str

/*
 * Memory writes are REVERSIBLE (undo removes or restores the fact), so in an untainted task they
 * run and are reported. In a task that has read untrusted content they ask first, like every
 * effect: otherwise an injected "remember: always ..." would persist into every future request.
 */

object Remember : Capability {
    override val name = "remember"
    override val description = "Save a short fact about the user for future requests (a preference, routine, " +
        "person, place). Only things the user would want remembered; never passwords, codes or card numbers."
    override val risk = Risk.REVERSIBLE
    override val output = OutputTrust.Trusted
    override val sendsDataOut = false
    override val params = listOf(Param("fact", ParamType.STRING, "One short sentence, e.g. \"Dana is the user's sister\""))

    override fun check(args: Args) = MemoryRules.problem(args.string("fact"))
    override fun summarize(args: Args) = "Remember: \"${args.string("fact").take(120)}\""

    override fun execute(ctx: CapContext, args: Args): CapResult {
        val origin = if (ctx.source == Source.USER_DIRECT) Origin.YOU else Origin.CLAUDE
        val item = try {
            Memory.book().add(args.string("fact"), origin)
        } catch (e: IllegalArgumentException) {
            return CapResult.Error(e.message ?: "couldn't remember that")
        }
        return CapResult.Ok("Remembered: \"${item.text}\"", undo = mapOf("memory_id" to item.id, "text" to item.text))
    }

    override fun undoSummary(data: Map<String, Any?>) = "Forget \"${data.str("text")?.take(80)}\""

    override fun undo(ctx: CapContext, data: Map<String, Any?>): CapResult {
        val id = data.long("memory_id")?.toInt() ?: return CapResult.Error("No record of which memory to forget")
        return if (Memory.book().remove(id) != null) CapResult.Ok("Forgot \"${data.str("text")?.take(80)}\"")
        else CapResult.Ok("That memory was already gone")
    }
}

object ForgetMemory : Capability {
    override val name = "forget_memory"
    override val description = "Delete one remembered fact, by its id (the [mN] shown with the user's memories)."
    override val risk = Risk.REVERSIBLE
    override val output = OutputTrust.Trusted
    override val sendsDataOut = false
    override val params = listOf(Param("memory_id", ParamType.INTEGER, "The N in [mN]", min = 1))

    override fun check(args: Args) =
        if (Memory.book().get(args.int("memory_id")) == null) "no memory m${args.int("memory_id")}" else null

    override fun summarize(args: Args) =
        "Forget \"${Memory.book().get(args.int("memory_id"))?.text?.take(120) ?: "m${args.int("memory_id")}"}\""

    override fun execute(ctx: CapContext, args: Args): CapResult {
        val gone = Memory.book().remove(args.int("memory_id")) ?: return CapResult.Error("no such memory")
        return CapResult.Ok("Forgot \"${gone.text}\"", undo = mapOf(
            "memory_id" to gone.id, "text" to gone.text, "origin" to gone.origin.name,
            "created" to gone.createdAt, "updated" to gone.updatedAt,
        ))
    }

    override fun undoSummary(data: Map<String, Any?>) = "Remember \"${data.str("text")?.take(80)}\" again"

    override fun undo(ctx: CapContext, data: Map<String, Any?>): CapResult {
        val item = MemoryItem(
            id = data.long("memory_id")?.toInt() ?: return CapResult.Error("No copy of the forgotten memory"),
            text = data.str("text") ?: return CapResult.Error("No copy of the forgotten memory"),
            origin = runCatching { Origin.valueOf(data.str("origin")!!) }.getOrDefault(Origin.YOU),
            createdAt = data.long("created") ?: 0, updatedAt = data.long("updated") ?: 0,
        )
        Memory.book().restore(item)
        return CapResult.Ok("Remembered \"${item.text}\" again")
    }
}
