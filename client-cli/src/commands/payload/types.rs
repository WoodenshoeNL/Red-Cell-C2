//! Shared types for `red-cell-cli payload` subcommands.

use serde::{Deserialize, Serialize};

use crate::output::{TextRender, TextRow};

// ── raw API response shapes ───────────────────────────────────────────────────

/// The server also sends `size_bytes` which is silently ignored by serde.
#[derive(Debug, Deserialize)]
pub(super) struct RawPayloadSummary {
    pub id: String,
    pub name: String,
    pub arch: String,
    pub format: String,
    pub built_at: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct BuildSubmitResponse {
    pub job_id: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct BuildJobStatus {
    pub job_id: String,
    /// `"pending"` | `"running"` | `"done"` | `"error"`
    pub status: String,
    pub agent_type: Option<String>,
    pub payload_id: Option<String>,
    pub size_bytes: Option<u64>,
    pub error: Option<String>,
}

// ── public output types ───────────────────────────────────────────────────────

/// Summary row returned by `payload list`.
#[derive(Debug, Clone, Serialize)]
pub struct PayloadRow {
    /// Unique payload identifier.
    pub id: String,
    /// Display name of the payload.
    pub name: String,
    /// Target CPU architecture (e.g. `"x86_64"`).
    pub arch: String,
    /// File format: `"exe"`, `"dll"`, or `"bin"`.
    pub format: String,
    /// RFC 3339 build timestamp.
    pub built_at: String,
}

impl TextRow for PayloadRow {
    fn headers() -> Vec<&'static str> {
        vec!["ID", "Name", "Arch", "Format", "Built At"]
    }

    fn row(&self) -> Vec<String> {
        vec![
            self.id.clone(),
            self.name.clone(),
            self.arch.clone(),
            self.format.clone(),
            self.built_at.clone(),
        ]
    }
}

/// Result returned by `payload build` without `--wait`.
#[derive(Debug, Clone, Serialize)]
pub struct BuildJobSubmitted {
    /// Server-assigned build job identifier.
    pub job_id: String,
}

impl TextRender for BuildJobSubmitted {
    fn render_text(&self) -> String {
        format!("Build job submitted: {}", self.job_id)
    }
}

/// Result returned by `payload build --wait` on success.
#[derive(Debug, Clone, Serialize)]
pub struct BuildCompleted {
    /// Unique identifier of the finished payload.
    pub id: String,
    /// Size of the finished payload in bytes.
    pub size_bytes: u64,
}

impl TextRender for BuildCompleted {
    fn render_text(&self) -> String {
        format!("Payload {} built ({} bytes)", self.id, self.size_bytes)
    }
}

/// Result returned by `payload build-status`.
#[derive(Debug, Clone, Serialize)]
pub struct BuildJobStatusResult {
    /// Build job identifier.
    pub job_id: String,
    /// Current status: `"pending"`, `"running"`, `"done"`, or `"error"`.
    pub status: String,
    /// Agent type that was requested.
    pub agent_type: Option<String>,
    /// Payload identifier (set when status is `"done"`).
    pub payload_id: Option<String>,
    /// Artifact size in bytes (set when status is `"done"`).
    pub size_bytes: Option<u64>,
    /// Error message (set when status is `"error"`).
    pub error: Option<String>,
}

impl TextRender for BuildJobStatusResult {
    fn render_text(&self) -> String {
        let mut parts = vec![format!("Job {} — {}", self.job_id, self.status)];
        if let Some(ref agent) = self.agent_type {
            parts.push(format!("  agent: {agent}"));
        }
        if let Some(ref pid) = self.payload_id {
            parts.push(format!("  payload_id: {pid}"));
        }
        if let Some(bytes) = self.size_bytes {
            parts.push(format!("  size: {bytes} bytes"));
        }
        if let Some(ref err) = self.error {
            parts.push(format!("  error: {err}"));
        }
        parts.join("\n")
    }
}

/// Result returned by `payload build-wait` on success.
#[derive(Debug, Clone, Serialize)]
pub struct BuildWaitCompleted {
    /// Unique identifier of the finished payload.
    pub payload_id: String,
    /// Size of the finished payload in bytes.
    pub size_bytes: u64,
    /// Local path where the payload was saved (if `--output` was used).
    pub output: Option<String>,
}

impl TextRender for BuildWaitCompleted {
    fn render_text(&self) -> String {
        let base = format!("Payload {} built ({} bytes)", self.payload_id, self.size_bytes);
        match self.output {
            Some(ref path) => format!("{base} → {path}"),
            None => base,
        }
    }
}

/// Result returned by `payload download`.
#[derive(Debug, Clone, Serialize)]
pub struct DownloadResult {
    /// Payload ID that was downloaded.
    pub id: String,
    /// Local path where the payload was written.
    pub dst: String,
    /// Number of bytes written to disk.
    pub size_bytes: u64,
}

impl TextRender for DownloadResult {
    fn render_text(&self) -> String {
        format!("Saved {} ({} bytes) → {}", self.id, self.size_bytes, self.dst)
    }
}

/// Result returned by `payload cache-flush`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheFlushResult {
    /// Number of cached payload entries that were removed.
    pub flushed: u64,
}

impl TextRender for CacheFlushResult {
    fn render_text(&self) -> String {
        format!("Flushed {} cached payload(s).", self.flushed)
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

pub(super) fn payload_row_from_raw(raw: RawPayloadSummary) -> PayloadRow {
    PayloadRow {
        id: raw.id,
        name: raw.name,
        arch: raw.arch,
        format: raw.format,
        built_at: raw.built_at,
    }
}
