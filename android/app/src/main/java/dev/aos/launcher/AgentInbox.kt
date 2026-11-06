package dev.aos.launcher

import dev.aos.launcher.capabilities.CallContext
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * In-process hand-off of agent-proposed calls to the UI. Kept inside the app process on purpose:
 * MainActivity is exported (it is the home screen), so agent calls must never arrive as Intent
 * extras that any other app could forge.
 */
object AgentInbox {
    data class Call(val capability: String, val args: Map<String, Any?>, val context: CallContext)

    /** A whole agent task, optionally in red-team "compromised model" mode (debug only). */
    data class Task(val text: String, val simulateCompromise: Boolean, val scriptedAttack: Boolean = false,
                    val screenAttack: Boolean = false)

    private val queue = ConcurrentLinkedQueue<Call>()
    private val tasks = ConcurrentLinkedQueue<Task>()

    fun postTask(task: Task) {
        tasks.add(task)
    }

    fun pollTask(): Task? = tasks.poll()

    fun post(call: Call) {
        queue.add(call)
    }

    fun poll(): Call? = queue.poll()
}
