//! Plugin event definitions.

/// Events exposed to Python callbacks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PluginEvent {
    /// Agent check-in callback notifications.
    AgentCheckin,
    /// Agent registration (DemonInit) callback notifications.
    AgentRegistered,
    /// Agent death or stale timeout callback notifications.
    AgentDead,
    /// Agent command output callback notifications.
    CommandOutput,
    /// Loot (download, screenshot, credential) captured callback notifications.
    LootCaptured,
    /// Task queued for an agent callback notifications.
    TaskCreated,
}

impl PluginEvent {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::AgentCheckin => "agent_checkin",
            Self::AgentRegistered => "agent_registered",
            Self::AgentDead => "agent_dead",
            Self::CommandOutput => "command_output",
            Self::LootCaptured => "loot_captured",
            Self::TaskCreated => "task_created",
        }
    }

    pub(super) fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "agent_checkin" => Some(Self::AgentCheckin),
            "agent_registered" => Some(Self::AgentRegistered),
            "agent_dead" => Some(Self::AgentDead),
            "command_output" => Some(Self::CommandOutput),
            "loot_captured" => Some(Self::LootCaptured),
            "task_created" => Some(Self::TaskCreated),
            _ => None,
        }
    }
}
