use clap::Parser;

use crate::AgentId;
use crate::cli::{AgentCommands, Cli, Commands, ListenerCommands, OperatorCommands};

#[test]
fn rbac_agent_groups_subcommands_parse() {
    let g =
        Cli::try_parse_from(["red-cell-cli", "agent", "groups", "DEADBEEF"]).expect("agent groups");
    assert!(matches!(g.command, Some(Commands::Agent { action: AgentCommands::Groups { .. } })));

    let s = Cli::try_parse_from([
        "red-cell-cli",
        "agent",
        "set-groups",
        "AABBCCDD",
        "--group",
        "g1",
        "--group",
        "g2",
    ])
    .expect("agent set-groups");
    match s.command {
        Some(Commands::Agent { action: AgentCommands::SetGroups { id, group } }) => {
            assert_eq!(id, AgentId::new(0xAABBCCDD));
            assert_eq!(group, vec!["g1", "g2"]);
        }
        other => panic!("expected Agent::SetGroups, got {other:?}"),
    }
}

#[test]
fn rbac_operator_agent_groups_subcommands_parse() {
    let show = Cli::try_parse_from(["red-cell-cli", "operator", "show-agent-groups", "alice"])
        .expect("show-agent-groups");
    assert!(matches!(
        show.command,
        Some(Commands::Operator { action: OperatorCommands::ShowAgentGroups { .. } })
    ));

    let set = Cli::try_parse_from([
        "red-cell-cli",
        "operator",
        "set-agent-groups",
        "bob",
        "--group",
        "tier1",
    ])
    .expect("set-agent-groups");
    match set.command {
        Some(Commands::Operator {
            action: OperatorCommands::SetAgentGroups { username, group },
        }) => {
            assert_eq!(username, "bob");
            assert_eq!(group, vec!["tier1"]);
        }
        other => panic!("expected Operator::SetAgentGroups, got {other:?}"),
    }
}

#[test]
fn rbac_listener_access_subcommands_parse() {
    let a = Cli::try_parse_from(["red-cell-cli", "listener", "access", "http1"]).expect("access");
    assert!(matches!(
        a.command,
        Some(Commands::Listener { action: ListenerCommands::Access { .. } })
    ));

    let s = Cli::try_parse_from([
        "red-cell-cli",
        "listener",
        "set-access",
        "dns1",
        "--allow-operator",
        "u1",
        "--allow-operator",
        "u2",
    ])
    .expect("set-access");
    match s.command {
        Some(Commands::Listener {
            action: ListenerCommands::SetAccess { name, allow_operator },
        }) => {
            assert_eq!(name, "dns1");
            assert_eq!(allow_operator, vec!["u1", "u2"]);
        }
        other => panic!("expected Listener::SetAccess, got {other:?}"),
    }
}
