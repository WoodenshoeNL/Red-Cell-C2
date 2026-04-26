//! `payload inspect` handler (local, no server connection needed).

use serde::Serialize;

use crate::error::{CliError, EXIT_SUCCESS};
use crate::output::{OutputFormat, TextRender, print_error, print_success};

/// Metadata extracted from a built payload's embedded manifest.
#[derive(Debug, Serialize)]
pub struct InspectResult {
    pub agent_type: String,
    pub arch: String,
    pub format: String,
    pub callback_url: Option<String>,
    pub hosts: Vec<String>,
    pub port: Option<u16>,
    pub secure: bool,
    pub sleep_ms: Option<u64>,
    pub jitter: Option<u32>,
    pub init_secret_hash: Option<String>,
    pub kill_date: Option<String>,
    pub working_hours_mask: Option<u32>,
    pub listener_name: String,
    pub export_name: Option<String>,
    pub built_at: String,
}

impl TextRender for InspectResult {
    fn render_text(&self) -> String {
        let mut lines = Vec::with_capacity(16);
        lines.push(format!("Agent type:       {}", self.agent_type));
        lines.push(format!("Architecture:     {}", self.arch));
        lines.push(format!("Format:           {}", self.format));
        if let Some(ref url) = self.callback_url {
            lines.push(format!("Callback URL:     {url}"));
        }
        if !self.hosts.is_empty() {
            lines.push(format!("Hosts:            {}", self.hosts.join(", ")));
        }
        if let Some(port) = self.port {
            lines.push(format!("Port:             {port}"));
        }
        lines.push(format!("TLS:              {}", self.secure));
        if let Some(ms) = self.sleep_ms {
            lines.push(format!("Sleep:            {ms} ms"));
        }
        if let Some(j) = self.jitter {
            lines.push(format!("Jitter:           {j}%"));
        }
        if let Some(ref h) = self.init_secret_hash {
            lines.push(format!("Init secret hash: {h}"));
        }
        if let Some(ref kd) = self.kill_date {
            lines.push(format!("Kill date:        {kd}"));
        }
        if let Some(mask) = self.working_hours_mask {
            lines.push(format!("Working hours:    0x{mask:08X}"));
        }
        lines.push(format!("Listener:         {}", self.listener_name));
        if let Some(ref name) = self.export_name {
            lines.push(format!("Export name:      {name}"));
        }
        lines.push(format!("Built at:         {}", self.built_at));
        lines.join("\n")
    }
}

/// Inspect a local payload file and print its embedded build manifest.
///
/// This is a synchronous, server-independent operation dispatched before
/// config resolution by [`crate::dispatch::dispatch`].
pub fn inspect_local(file: &str, fmt: &OutputFormat) -> i32 {
    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            let err = CliError::Io(format!("failed to read {file}: {e}"));
            print_error(&err).ok();
            return err.exit_code();
        }
    };

    let manifest = match red_cell_common::payload_manifest::extract_manifest(&data) {
        Some(m) => m,
        None => {
            let err = CliError::General(format!(
                "no build manifest found in {file} — the payload may have been \
                 built before manifest embedding was added, or the file is not \
                 a Red Cell payload"
            ));
            print_error(&err).ok();
            return err.exit_code();
        }
    };

    let result = InspectResult {
        agent_type: manifest.agent_type,
        arch: manifest.arch,
        format: manifest.format,
        callback_url: manifest.callback_url,
        hosts: manifest.hosts,
        port: manifest.port,
        secure: manifest.secure,
        sleep_ms: manifest.sleep_ms,
        jitter: manifest.jitter,
        init_secret_hash: manifest.init_secret_hash,
        kill_date: manifest.kill_date,
        working_hours_mask: manifest.working_hours_mask,
        listener_name: manifest.listener_name,
        export_name: manifest.export_name,
        built_at: manifest.built_at,
    };

    match print_success(fmt, &result) {
        Ok(()) => EXIT_SUCCESS,
        Err(e) => {
            print_error(&e).ok();
            e.exit_code()
        }
    }
}
