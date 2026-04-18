//! Console command specification, history, and completion helpers.

use crate::AgentConsoleState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HistoryDirection {
    Older,
    Newer,
}

/// Handles client-side commands that do not require a round-trip to the teamserver.
///
/// Returns `Some(output)` when the input matches a local command, or `None` if the
/// command should be forwarded to the teamserver.
pub(crate) fn handle_local_command(input: &str) -> Option<String> {
    let trimmed = input.trim();
    let mut parts = trimmed.split_whitespace();
    let command = parts.next()?.to_ascii_lowercase();

    match command.as_str() {
        "help" | "?" => {
            let topic = parts.next();
            Some(build_help_output(topic))
        }
        _ => None,
    }
}

/// Builds the formatted help text.
///
/// When `topic` is `None`, a full command table is produced (matching Havoc's
/// `help` output). When a specific command name is given, only that command's
/// usage and description are shown.
pub(crate) fn build_help_output(topic: Option<&str>) -> String {
    if let Some(name) = topic {
        let needle = name.to_ascii_lowercase();
        let spec = CONSOLE_COMMANDS
            .iter()
            .find(|spec| spec.name == needle || spec.aliases.iter().any(|alias| *alias == needle));
        return match spec {
            Some(spec) => {
                let mut out = format!(" {}\n", spec.name);
                out.push_str(&format!("   Usage:       {}\n", spec.usage));
                out.push_str(&format!("   Type:        {}\n", spec.cmd_type));
                out.push_str(&format!("   Description: {}\n", spec.description));
                if !spec.aliases.is_empty() {
                    out.push_str(&format!("   Aliases:     {}\n", spec.aliases.join(", ")));
                }
                out
            }
            None => format!("Unknown command `{name}`. Type `help` for available commands."),
        };
    }

    // Full command table.
    let mut out = String::from(" Demon Commands\n\n");
    out.push_str(&format!(" {:<22} {:<12} {}\n", "Command", "Type", "Description"));
    out.push_str(&format!(" {:<22} {:<12} {}\n", "-------", "----", "-----------"));
    for spec in &CONSOLE_COMMANDS {
        out.push_str(&format!(" {:<22} {:<12} {}\n", spec.name, spec.cmd_type, spec.description));
    }
    out
}

/// Formats the Havoc-style console prompt: `[operator/AGENT_ID] demon.x64 >> `.
pub(crate) fn format_console_prompt(operator: &str, agent_id: &str) -> String {
    let op = if operator.is_empty() { "operator" } else { operator };
    format!("[{op}/{agent_id}] demon.x64 >> ")
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ConsoleCommandSpec {
    pub(crate) name: &'static str,
    pub(crate) aliases: &'static [&'static str],
    pub(crate) usage: &'static str,
    pub(crate) cmd_type: &'static str,
    pub(crate) description: &'static str,
}

pub(crate) const CONSOLE_COMMANDS: [ConsoleCommandSpec; 28] = [
    ConsoleCommandSpec {
        name: "help",
        aliases: &["?"],
        usage: "help [command]",
        cmd_type: "Command",
        description: "Show available commands or help for a specific command",
    },
    ConsoleCommandSpec {
        name: "shell",
        aliases: &[],
        usage: "shell <command>",
        cmd_type: "Command",
        description: "Executes a shell command via cmd.exe",
    },
    ConsoleCommandSpec {
        name: "sleep",
        aliases: &[],
        usage: "sleep <seconds> [jitter%]",
        cmd_type: "Command",
        description: "Sets the agent sleep delay and optional jitter",
    },
    ConsoleCommandSpec {
        name: "checkin",
        aliases: &[],
        usage: "checkin",
        cmd_type: "Command",
        description: "Request the agent to check in immediately",
    },
    ConsoleCommandSpec {
        name: "kill",
        aliases: &["exit"],
        usage: "kill [process]",
        cmd_type: "Command",
        description: "Kill the agent (thread or process)",
    },
    ConsoleCommandSpec {
        name: "ps",
        aliases: &["proclist"],
        usage: "ps",
        cmd_type: "Command",
        description: "List running processes",
    },
    ConsoleCommandSpec {
        name: "screenshot",
        aliases: &[],
        usage: "screenshot",
        cmd_type: "Command",
        description: "Takes a screenshot of the current desktop",
    },
    ConsoleCommandSpec {
        name: "pwd",
        aliases: &[],
        usage: "pwd",
        cmd_type: "Command",
        description: "Print the current working directory",
    },
    ConsoleCommandSpec {
        name: "cd",
        aliases: &[],
        usage: "cd <path>",
        cmd_type: "Command",
        description: "Change the working directory",
    },
    ConsoleCommandSpec {
        name: "dir",
        aliases: &["ls"],
        usage: "dir <path>",
        cmd_type: "Command",
        description: "List files in a directory",
    },
    ConsoleCommandSpec {
        name: "mkdir",
        aliases: &[],
        usage: "mkdir <path>",
        cmd_type: "Command",
        description: "Create a directory",
    },
    ConsoleCommandSpec {
        name: "rm",
        aliases: &["del", "remove"],
        usage: "rm <path>",
        cmd_type: "Command",
        description: "Delete a file or directory",
    },
    ConsoleCommandSpec {
        name: "cp",
        aliases: &["copy"],
        usage: "cp <src> <dst>",
        cmd_type: "Command",
        description: "Copy a file to another location",
    },
    ConsoleCommandSpec {
        name: "mv",
        aliases: &["move"],
        usage: "mv <src> <dst>",
        cmd_type: "Command",
        description: "Move or rename a file",
    },
    ConsoleCommandSpec {
        name: "cat",
        aliases: &["type"],
        usage: "cat <path>",
        cmd_type: "Command",
        description: "Read and display a file's contents",
    },
    ConsoleCommandSpec {
        name: "download",
        aliases: &[],
        usage: "download <path>",
        cmd_type: "Command",
        description: "Download a file from the target",
    },
    ConsoleCommandSpec {
        name: "upload",
        aliases: &[],
        usage: "upload <local> <remote>",
        cmd_type: "Command",
        description: "Upload a local file to the target",
    },
    ConsoleCommandSpec {
        name: "proc",
        aliases: &[],
        usage: "proc <kill|modules|grep|create|memory> [args]",
        cmd_type: "Command",
        description: "Process management and inspection",
    },
    ConsoleCommandSpec {
        name: "token",
        aliases: &[],
        usage: "token <list|steal|make|impersonate|revert|privs|uid|clear> [args]",
        cmd_type: "Command",
        description: "Token impersonation and management",
    },
    ConsoleCommandSpec {
        name: "inline-execute",
        aliases: &["bof"],
        usage: "inline-execute <bof-path> [args]",
        cmd_type: "Command",
        description: "Execute a Beacon Object File (COFF) in-process",
    },
    ConsoleCommandSpec {
        name: "inject-dll",
        aliases: &[],
        usage: "inject-dll <pid> <dll-path>",
        cmd_type: "Module",
        description: "Inject a DLL into a remote process",
    },
    ConsoleCommandSpec {
        name: "inject-shellcode",
        aliases: &[],
        usage: "inject-shellcode <pid> <bin-path>",
        cmd_type: "Module",
        description: "Inject shellcode into a remote process",
    },
    ConsoleCommandSpec {
        name: "spawn-dll",
        aliases: &[],
        usage: "spawn-dll <dll-path> [args]",
        cmd_type: "Module",
        description: "Spawn a sacrificial process and inject a DLL",
    },
    ConsoleCommandSpec {
        name: "net",
        aliases: &[],
        usage: "net <domain|logons|sessions|computers|dclist|share|localgroup|group> [args]",
        cmd_type: "Command",
        description: "Network and Active Directory enumeration",
    },
    ConsoleCommandSpec {
        name: "pivot",
        aliases: &[],
        usage: "pivot <list|connect|disconnect> [args]",
        cmd_type: "Command",
        description: "SMB pivot link management",
    },
    ConsoleCommandSpec {
        name: "rportfwd",
        aliases: &[],
        usage: "rportfwd <add|remove|list|clear> [args]",
        cmd_type: "Command",
        description: "Reverse port forwarding through the agent",
    },
    ConsoleCommandSpec {
        name: "kerberos",
        aliases: &[],
        usage: "kerberos <luid|klist|purge|ptt> [args]",
        cmd_type: "Command",
        description: "Kerberos ticket management",
    },
    ConsoleCommandSpec {
        name: "config",
        aliases: &[],
        usage: "config <sleep-obf|implant.verbose|inject.spoofaddr|killdate|workinghours> [args]",
        cmd_type: "Command",
        description: "Modify agent runtime configuration",
    },
];

pub(crate) fn push_history_entry(console: &mut AgentConsoleState, command_line: &str) {
    if console.history.last().is_some_and(|last| last == command_line) {
        console.history_index = None;
        console.completion_index = 0;
        console.completion_seed = None;
        return;
    }

    console.history.push(command_line.to_owned());
    console.history_index = None;
    console.completion_index = 0;
    console.completion_seed = None;
}

pub(crate) fn apply_history_step(console: &mut AgentConsoleState, direction: HistoryDirection) {
    if console.history.is_empty() {
        return;
    }

    let next_index = match (direction, console.history_index) {
        (HistoryDirection::Older, None) => Some(console.history.len().saturating_sub(1)),
        (HistoryDirection::Older, Some(index)) => Some(index.saturating_sub(1)),
        (HistoryDirection::Newer, Some(index)) if index + 1 < console.history.len() => {
            Some(index + 1)
        }
        (HistoryDirection::Newer, Some(_)) => None,
        (HistoryDirection::Newer, None) => None,
    };

    console.history_index = next_index;
    console.input =
        next_index.and_then(|index| console.history.get(index).cloned()).unwrap_or_default();
    console.completion_index = 0;
    console.completion_seed = None;
}

pub(crate) fn apply_completion(console: &mut AgentConsoleState) {
    let prefix = console.input.trim();
    if prefix.contains(char::is_whitespace) {
        return;
    }

    let seed = console
        .completion_seed
        .clone()
        .filter(|seed| !seed.is_empty())
        .unwrap_or_else(|| prefix.to_owned());
    let matches = console_completion_candidates(&seed);
    if matches.is_empty() {
        return;
    }

    if console.completion_seed.as_deref() != Some(seed.as_str()) {
        console.completion_index = 0;
    }

    let next = console.completion_index % matches.len();
    console.input = matches[next].to_owned();
    console.completion_index = next + 1;
    console.completion_seed = Some(seed);
}

pub(crate) fn console_completion_candidates(prefix: &str) -> Vec<&'static str> {
    let needle = prefix.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return CONSOLE_COMMANDS.iter().map(|spec| spec.name).collect();
    }

    CONSOLE_COMMANDS
        .iter()
        .filter(|spec| {
            spec.name.starts_with(&needle)
                || spec.aliases.iter().any(|alias| alias.starts_with(&needle))
        })
        .map(|spec| spec.name)
        .collect()
}

pub(crate) fn closest_command_usage(command: &str) -> Option<&'static str> {
    CONSOLE_COMMANDS.iter().find_map(|spec| {
        (spec.name == command || spec.aliases.contains(&command)).then_some(spec.usage)
    })
}

#[allow(dead_code)]
pub(crate) fn split_console_selection<'a>(
    open_consoles: &'a [String],
    selected_console: Option<&'a str>,
) -> Vec<&'a str> {
    if open_consoles.is_empty() {
        return Vec::new();
    }

    let selected = selected_console.unwrap_or(open_consoles[0].as_str());
    let mut visible = vec![selected];
    for agent_id in open_consoles {
        if agent_id != selected {
            visible.push(agent_id.as_str());
        }
        if visible.len() == 2 {
            break;
        }
    }
    visible
}
