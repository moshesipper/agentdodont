package dev.aos.launcher

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import dev.aos.launcher.capabilities.CallContext
import dev.aos.launcher.capabilities.Source
import org.json.JSONObject

/**
 * Debug-only: simulate a call proposed by the agent.
 *
 *   adb shell am broadcast -n dev.aos.launcher/.DebugAgentReceiver \
 *       -a dev.aos.launcher.DEBUG_AGENT_CALL --es name set_alarm --es args '{"hour":6,"minute":5}' --ez tainted true
 */
class DebugAgentReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == ACTION_TASK) {
            // Run a whole agent task (real Claude), e.g. the prompt-injection red-team test:
            //   adb shell am broadcast -n dev.aos.launcher/.DebugAgentReceiver -a dev.aos.launcher.DEBUG_AGENT_TASK             //       --es task "what are my notifications?" --ez compromised true
            // or, with a scripted attacker in place of Claude (the model fully compromised):
            //       --es task "check my notifications" --ez attack true
            val text = intent.getStringExtra("task") ?: return
            AgentInbox.postTask(AgentInbox.Task(text, intent.getBooleanExtra("compromised", false),
                scriptedAttack = intent.getBooleanExtra("attack", false),
                screenAttack = intent.getBooleanExtra("screen_attack", false)))
            Log.i("AgentDoDont", "debug agent task: $text")
            context.startActivity(Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            return
        }
        val name = intent.getStringExtra("name") ?: return
        val json = JSONObject(intent.getStringExtra("args") ?: "{}")
        val args = json.keys().asSequence().associateWith { k -> json.get(k).takeUnless { it == JSONObject.NULL } }
        val call = AgentInbox.Call(name, args, CallContext(Source.AGENT, tainted = intent.getBooleanExtra("tainted", false)))
        Log.i("AgentDoDont", "debug agent call: $call")
        AgentInbox.post(call)
        context.startActivity(Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    companion object {
        const val ACTION_TASK = "dev.aos.launcher.DEBUG_AGENT_TASK"
    }
}
