//! `agent packet-ring` — fetch the last N raw protocol frames for an agent.

use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::AgentId;
use crate::client::ApiClient;
use crate::error::CliError;
use crate::output::TextRender;

/// A single captured packet frame returned by the server.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PacketRingFrame {
    /// Direction: `"rx"` (agent → teamserver) or `"tx"` (teamserver → agent).
    pub direction: String,
    /// Agent-protocol sequence number for this frame, if known.
    pub seq: Option<u64>,
    /// Raw frame bytes, hex-encoded.
    pub bytes_hex: String,
}

/// Response data for `agent packet-ring`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PacketRingData {
    /// Agent id in hex.
    pub agent_id: String,
    /// Requested frame count per direction.
    pub n: u8,
    /// Captured frames (empty when the ring-buffer is not yet populated).
    pub frames: Vec<PacketRingFrame>,
    /// Human-readable note when the ring-buffer is unavailable.
    pub note: Option<String>,
}

impl TextRender for PacketRingData {
    fn render_text(&self) -> String {
        if self.frames.is_empty() {
            let note = self.note.as_deref().unwrap_or("no frames available");
            return format!("agent {} — 0 frames (n={})\nnote: {}", self.agent_id, self.n, note);
        }
        let mut lines = vec![format!(
            "agent {} — {} frame(s) (n={})",
            self.agent_id,
            self.frames.len(),
            self.n
        )];
        for (i, frame) in self.frames.iter().enumerate() {
            let seq_label = frame.seq.map_or_else(|| "?".to_owned(), |s| s.to_string());
            let trunc = if frame.bytes_hex.len() > 64 {
                format!("{}…({} hex chars)", &frame.bytes_hex[..64], frame.bytes_hex.len())
            } else {
                frame.bytes_hex.clone()
            };
            lines.push(format!("  [{i}] dir={} seq={seq_label} bytes={}", frame.direction, trunc));
        }
        if let Some(note) = &self.note {
            lines.push(format!("note: {note}"));
        }
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_data(frames: Vec<PacketRingFrame>, note: Option<&str>) -> PacketRingData {
        PacketRingData {
            agent_id: "deadbeef".to_owned(),
            n: 5,
            frames,
            note: note.map(str::to_owned),
        }
    }

    #[test]
    fn render_text_empty_frames_with_note() {
        let data = make_data(vec![], Some("ring-buffer not yet populated"));
        let out = data.render_text();
        assert!(out.contains("deadbeef"), "should contain agent id");
        assert!(out.contains("n=5"), "should contain n value");
        assert!(out.contains("ring-buffer not yet populated"), "should contain the note");
        assert!(out.contains("0 frames"), "should show zero frames");
    }

    #[test]
    fn render_text_empty_frames_no_note_uses_fallback() {
        let data = make_data(vec![], None);
        let out = data.render_text();
        assert!(out.contains("no frames available"), "should use fallback note text");
    }

    #[test]
    fn render_text_frames_present_short_bytes() {
        let frame = PacketRingFrame {
            direction: "rx".to_owned(),
            seq: Some(42),
            bytes_hex: "aabbcc".to_owned(),
        };
        let data = make_data(vec![frame], None);
        let out = data.render_text();
        assert!(out.contains("1 frame(s)"), "should show frame count");
        assert!(out.contains("dir=rx"), "should show direction");
        assert!(out.contains("seq=42"), "should show seq number");
        assert!(out.contains("bytes=aabbcc"), "should show bytes without truncation");
        // no note line when note is None
        assert!(!out.contains("note:"), "should not show note line");
    }

    #[test]
    fn render_text_frames_present_long_bytes_truncated() {
        // 128 hex chars (64 bytes) — exceeds the 64-char cutoff
        let long_hex = "ab".repeat(64);
        let frame =
            PacketRingFrame { direction: "tx".to_owned(), seq: None, bytes_hex: long_hex.clone() };
        let data = make_data(vec![frame], None);
        let out = data.render_text();
        assert!(out.contains(&long_hex[..64]), "should include first 64 hex chars");
        assert!(out.contains("128 hex chars"), "should show total char count");
        assert!(out.contains('…'), "should include ellipsis");
        assert!(out.contains("seq=?"), "should show ? for unknown seq");
    }

    #[test]
    fn render_text_frames_present_with_note() {
        let frame = PacketRingFrame {
            direction: "rx".to_owned(),
            seq: Some(1),
            bytes_hex: "ff".to_owned(),
        };
        let data = make_data(vec![frame], Some("partial capture"));
        let out = data.render_text();
        assert!(out.contains("note: partial capture"), "should append note after frames");
    }

    #[test]
    fn render_text_multiple_frames_indexed() {
        let frames = vec![
            PacketRingFrame {
                direction: "rx".to_owned(),
                seq: Some(0),
                bytes_hex: "00".to_owned(),
            },
            PacketRingFrame {
                direction: "tx".to_owned(),
                seq: Some(1),
                bytes_hex: "01".to_owned(),
            },
        ];
        let data = make_data(frames, None);
        let out = data.render_text();
        assert!(out.contains("2 frame(s)"), "should show 2 frames");
        assert!(out.contains("[0]"), "should index first frame");
        assert!(out.contains("[1]"), "should index second frame");
    }
}

/// `agent packet-ring <id> [--n N]` — fetch the last N raw frames per direction.
///
/// Calls `GET /agents/{id}/debug/packet-ring?n={n}`.
/// Returns an empty `frames` list (with a `note`) when the server has the
/// endpoint but has not yet implemented the ring-buffer backing store.
#[instrument(skip(client))]
pub async fn fetch_packet_ring(
    client: &ApiClient,
    id: AgentId,
    n: u8,
) -> Result<PacketRingData, CliError> {
    client.get(&format!("/agents/{id}/debug/packet-ring?n={n}")).await
}
