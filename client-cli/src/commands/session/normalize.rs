//! Session command allowlist and default-agent injection for NDJSON lines.

use std::collections::HashSet;
use std::sync::LazyLock;

use crate::AgentId;
use crate::error::CliError;

/// Valid `cmd` values for session NDJSON (keep in sync with teamserver
/// `build_session_rest_request` in `teamserver/src/api.rs`, plus CLI-stable
/// aliases for subcommands that callers expect to spell like the CLI).
static SESSION_KNOWN_COMMANDS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "status",
        "agent.list",
        "agent.show",
        "agent.exec",
        "agent.output",
        "agent.kill",
        "agent.upload",
        "agent.download",
        "agent.groups",
        "agent.set_groups",
        "listener.list",
        "listener.show",
        "listener.create",
        "listener.update",
        "listener.start",
        "listener.stop",
        "listener.delete",
        "listener.mark",
        "listener.access",
        "listener.set_access",
        "operator.list",
        "operator.create",
        "operator.delete",
        "operator.set_role",
        "operator.show_agent_groups",
        "operator.set_agent_groups",
        "audit.list",
        "log.list",
        "log.tail",
        "session_activity.list",
        "credential.list",
        "credential.show",
        "job.list",
        "job.show",
        "loot.list",
        "loot.download",
        "loot.show",
        "payload.list",
        "payload.build",
        "payload.job",
        "payload.download",
        "payload_cache.flush",
        "payload-cache.flush",
        "webhooks.stats",
    ])
});

#[inline]
pub(crate) fn is_known_session_command(cmd: &str) -> bool {
    SESSION_KNOWN_COMMANDS.contains(cmd)
}

pub(crate) fn normalize_agent_id_field(
    cmd: &str,
    value: &mut serde_json::Value,
    default_agent: Option<AgentId>,
) -> Result<(), CliError> {
    if !command_accepts_agent_id(cmd) {
        return Ok(());
    }

    let Some(object) = value.as_object_mut() else {
        return Ok(());
    };

    let normalized = match object.get("id") {
        Some(raw) if !raw.is_null() => Some(parse_agent_id_value(raw)?),
        _ => default_agent,
    };

    if let Some(id) = normalized {
        object.insert("id".to_owned(), serde_json::json!(id));
    }

    Ok(())
}

fn command_accepts_agent_id(cmd: &str) -> bool {
    matches!(
        cmd,
        "agent.show"
            | "agent.exec"
            | "agent.output"
            | "agent.kill"
            | "agent.upload"
            | "agent.download"
            | "agent.groups"
            | "agent.set_groups"
    )
}

fn parse_agent_id_value(value: &serde_json::Value) -> Result<AgentId, CliError> {
    serde_json::from_value::<AgentId>(value.clone())
        .map_err(|err| CliError::InvalidArgs(format!("invalid agent id: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_session_commands_match_teamserver_router() {
        assert!(is_known_session_command("agent.list"));
        assert!(is_known_session_command("credential.list"));
        assert!(is_known_session_command("operator.set_role"));
    }

    #[test]
    fn unknown_session_commands_rejected_before_forward() {
        assert!(!is_known_session_command("agent.lst"));
        assert!(!is_known_session_command("nosuch"));
        assert!(!is_known_session_command(""));
    }
}
