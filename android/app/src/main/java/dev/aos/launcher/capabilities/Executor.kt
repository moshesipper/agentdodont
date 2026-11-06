package dev.aos.launcher.capabilities

import android.content.pm.PackageManager
import dev.aos.launcher.AuditLog

/**
 * The single path every capability call takes:
 *   look up -> validate -> POLICY (auto / ask / deny) -> permissions -> execute -> audit.
 * Nothing calls Capability.execute directly.
 *
 * A call that needs confirmation returns NeedsConfirmation; the UI asks the user and, on approval,
 * calls [run] again with approved = true. The policy is evaluated again on that second run, so an
 * approval can satisfy ASK but never overrides DENY.
 */
class Executor(private val audit: AuditLog, val policy: Policy, val undo: UndoStore? = null) {

    fun run(
        ctx: CapContext,
        name: String,
        raw: Map<String, Any?>,
        call: CallContext,
        approved: Boolean = false,
    ): CapResult {
        val cap = Registry.get(name)
        audit.event("capability_call", "name" to name, "args" to raw, "risk" to cap?.risk?.name,
            "source" to call.source.name, "tainted" to call.tainted, "approved" to approved)
        if (cap == null) return finish(name, CapResult.Error("unknown capability '$name'"))

        val args = when (val v = validate(cap, raw)) {
            is Validation.Invalid -> return finish(name, CapResult.Error(v.error))
            is Validation.Valid -> v.args
        }

        val decision = policy.decide(cap, args, call)
        audit.event("decision", "name" to name, "verdict" to decision.verdict.name, "rule" to decision.rule,
            "summary" to cap.summarize(args))
        when (decision.verdict) {
            Verdict.DENY -> return finish(name, CapResult.Denied(decision.rule))
            Verdict.ASK -> if (!approved) {
                return finish(name, CapResult.NeedsConfirmation(cap.summarize(args), decision.rule, cap.risk, cap.undoLimits))
            }
            Verdict.AUTO -> Unit
        }

        val missing = cap.permissions.filter { ctx.android.checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
        if (missing.isNotEmpty()) {
            return finish(name, CapResult.NeedsPermission(missing, "${cap.name.replace('_', ' ')} needs permission: ${missing.joinToString { it.substringAfterLast('.') }}"))
        }

        policy.record(cap, call.nowMs)
        val result = try {
            cap.execute(CapContext(ctx.android, ctx.apps, ctx.trustedApps, call.source), args)
        } catch (e: SecurityException) {
            CapResult.Error("permission denied: ${e.message}")
        } catch (e: RuntimeException) {
            CapResult.Error("${e::class.simpleName}: ${e.message}")
        }
        if (result is CapResult.Ok && undo != null) {
            cap.undoSummary(result.undo)?.let { summary ->
                val e = undo.add(call.taskId ?: "single-${call.nowMs}-$name", name, summary, result.undo)
                audit.event("undo_recorded", "name" to name, "undo_id" to e.id, "group" to e.group, "summary" to summary)
            }
        }
        return finish(name, result)
    }

    /**
     * Reverse previously recorded actions (newest first). Only reachable from the user's own
     * Undo, after a confirmation that showed every entry's summary.
     */
    fun undo(ctx: CapContext, entries: List<UndoStore.Entry>): List<Pair<UndoStore.Entry, CapResult>> {
        val store = undo ?: return emptyList()
        audit.event("undo_call", "group" to entries.firstOrNull()?.group, "ids" to entries.joinToString { it.id.toString() })
        return entries.map { e ->
            val cap = Registry.get(e.capability)
            val missing = cap?.permissions.orEmpty().filter { ctx.android.checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
            val r = when {
                cap == null -> CapResult.Error("unknown capability '${e.capability}'")
                missing.isNotEmpty() -> CapResult.Error("needs calendar access to undo")
                else -> try {
                    cap.undo(ctx, e.data)
                } catch (ex: SecurityException) {
                    CapResult.Error("permission denied: ${ex.message}")
                } catch (ex: RuntimeException) {
                    CapResult.Error("${ex::class.simpleName}: ${ex.message}")
                }
            }
            // Settled either way: a refused undo (e.g. the event was edited since) would otherwise sit
            // on top of the stack and block every older action. The outcome is shown and logged.
            store.markUndone(e.id)
            audit.event("undo_result", "undo_id" to e.id, "name" to e.capability, "ok" to (r is CapResult.Ok),
                "message" to ((r as? CapResult.Ok)?.message ?: (r as? CapResult.Error)?.message))
            e to r
        }
    }

    private fun finish(name: String, r: CapResult): CapResult {
        when (r) {
            is CapResult.Ok -> audit.event("capability_result", "name" to name, "ok" to true, "message" to r.message, "undo" to r.undo)
            is CapResult.Error -> audit.event("capability_result", "name" to name, "ok" to false, "message" to r.message)
            is CapResult.NeedsPermission -> audit.event("capability_result", "name" to name, "ok" to false, "needs_permission" to r.permissions.joinToString())
            is CapResult.NeedsConfirmation -> audit.event("capability_result", "name" to name, "ok" to false, "needs_confirmation" to r.rule)
            is CapResult.Denied -> audit.event("capability_result", "name" to name, "ok" to false, "denied" to r.rule)
            is CapResult.Declined -> audit.event("capability_result", "name" to name, "ok" to false, "declined" to r.what)
        }
        return r
    }
}
