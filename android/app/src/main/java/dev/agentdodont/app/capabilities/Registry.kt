package dev.agentdodont.app.capabilities

/** The single list of what Agent Do/Don't can do. Policy (step 3) and Claude's tools (step 4) derive from it. */
object Registry {
    val all: List<Capability> = listOf(SetAlarm, AddCalendarEvent, FindCalendarEvents, DeleteCalendarEvent, OpenUrl, OpenApp, ReadNotifications,
        dev.agentdodont.app.memory.Remember, dev.agentdodont.app.memory.ForgetMemory,
        FindContacts, ComposeEmail, ComposeMessage) +
        dev.agentdodont.app.screen.SCREEN_CAPABILITIES
    private val byName = all.associateBy { it.name }

    fun get(name: String): Capability? = byName[name]
}
