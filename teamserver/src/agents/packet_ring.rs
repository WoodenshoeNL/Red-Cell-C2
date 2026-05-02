//! Bounded per-agent capture of raw transport frames for debug / diagnostics.

use std::collections::VecDeque;

use crate::AgentRegistry;

/// Upper bound on how many frames are retained per agent (RX and TX combined).
pub(crate) const PACKET_RING_MAX_FRAMES: usize = 256;
/// Maximum number of raw bytes stored per frame (excess is truncated for memory safety).
pub(crate) const PACKET_RING_MAX_FRAME_BYTES: usize = 256 * 1024;

/// Wire direction for a captured frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PacketRingDirection {
    /// Agent → teamserver (request body).
    Rx,
    /// Teamserver → agent (response body).
    Tx,
}

impl PacketRingDirection {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Rx => "rx",
            Self::Tx => "tx",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PacketRingCapturedFrame {
    pub(crate) direction: PacketRingDirection,
    pub(crate) seq: Option<u64>,
    pub(crate) bytes: Vec<u8>,
}

/// FIFO-bounded ring of captured frames (combined RX/TX; evicts oldest entries).
#[derive(Debug)]
pub(crate) struct PacketRingBuffer {
    frames: VecDeque<PacketRingCapturedFrame>,
}

impl Default for PacketRingBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketRingBuffer {
    pub(crate) fn new() -> Self {
        Self { frames: VecDeque::new() }
    }

    pub(crate) fn clear(&mut self) {
        self.frames.clear();
    }

    /// Append one frame; drops the oldest entries when over [`PACKET_RING_MAX_FRAMES`].
    pub(crate) fn push(&mut self, direction: PacketRingDirection, seq: Option<u64>, bytes: &[u8]) {
        let take = bytes.len().min(PACKET_RING_MAX_FRAME_BYTES);
        let bytes = bytes[..take].to_vec();
        self.frames.push_back(PacketRingCapturedFrame { direction, seq, bytes });
        while self.frames.len() > PACKET_RING_MAX_FRAMES {
            self.frames.pop_front();
        }
    }

    /// Last `n` RX and last `n` TX frames, merged in chronological order (oldest first).
    pub(crate) fn snapshot_last_n_per_direction(&self, n: u8) -> Vec<PacketRingCapturedFrame> {
        let n = usize::from(n);
        if n == 0 || self.frames.is_empty() {
            return Vec::new();
        }

        let mut picked_indices: Vec<usize> = Vec::new();
        let mut rx_count = 0usize;
        let mut tx_count = 0usize;

        for (idx, entry) in self.frames.iter().enumerate().rev() {
            match entry.direction {
                PacketRingDirection::Rx if rx_count < n => {
                    picked_indices.push(idx);
                    rx_count += 1;
                }
                PacketRingDirection::Tx if tx_count < n => {
                    picked_indices.push(idx);
                    tx_count += 1;
                }
                _ => {}
            }

            if rx_count >= n && tx_count >= n {
                break;
            }
        }

        picked_indices.sort_unstable();
        picked_indices.into_iter().filter_map(|i| self.frames.get(i).cloned()).collect()
    }
}

impl AgentRegistry {
    /// Append one RX and one TX snapshot after a completed Demon/Archon transport round-trip
    /// (HTTP body bytes and response payload as seen on the wire).
    #[inline]
    pub(crate) async fn record_packet_ring_exchange(
        &self,
        agent_id: u32,
        rx: &[u8],
        tx: &[u8],
        seq: Option<u64>,
    ) {
        let Some(entry) = self.entry(agent_id).await else {
            return;
        };
        let mut ring = entry.packet_ring.lock().await;
        ring.push(PacketRingDirection::Rx, seq, rx);
        ring.push(PacketRingDirection::Tx, seq, tx);
    }

    /// Return up to the last `n` RX and `n` TX frames (merged in time order) for the packet-ring debug endpoint.
    pub(crate) async fn packet_ring_snapshot(
        &self,
        agent_id: u32,
        n: u8,
    ) -> Vec<PacketRingCapturedFrame> {
        let Some(entry) = self.entry(agent_id).await else {
            return Vec::new();
        };
        let ring = entry.packet_ring.lock().await;
        ring.snapshot_last_n_per_direction(n)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PACKET_RING_MAX_FRAME_BYTES, PACKET_RING_MAX_FRAMES, PacketRingBuffer, PacketRingDirection,
    };

    #[test]
    fn ring_evicts_oldest_when_over_cap() {
        let mut ring = PacketRingBuffer::new();
        for i in 0..(PACKET_RING_MAX_FRAMES + 10) {
            let b = [u8::try_from(i & 0xff).expect("fits")];
            ring.push(PacketRingDirection::Rx, None, &b);
        }
        assert_eq!(ring.frames.len(), PACKET_RING_MAX_FRAMES);
        assert_eq!(
            ring.frames.front().expect("non-empty").bytes,
            vec![10],
            "first of 266 pushes should have dropped 0..9"
        );
    }

    #[test]
    fn snapshot_takes_last_n_per_direction_in_time_order() {
        let mut ring = PacketRingBuffer::new();
        ring.push(PacketRingDirection::Rx, Some(1), b"a");
        ring.push(PacketRingDirection::Tx, Some(1), b"b");
        ring.push(PacketRingDirection::Rx, Some(2), b"c");
        ring.push(PacketRingDirection::Tx, Some(2), b"d");

        let snap = ring.snapshot_last_n_per_direction(1);
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].bytes, b"c");
        assert_eq!(snap[0].direction, PacketRingDirection::Rx);
        assert_eq!(snap[1].bytes, b"d");
        assert_eq!(snap[1].direction, PacketRingDirection::Tx);
    }

    #[test]
    fn snapshot_with_n_two_returns_last_two_each_merged_chronologically() {
        let mut ring = PacketRingBuffer::new();
        for i in 0u8..6 {
            ring.push(PacketRingDirection::Rx, Some(u64::from(i)), &[i]);
            ring.push(PacketRingDirection::Tx, Some(u64::from(i)), &[0x80 | i]);
        }
        let snap = ring.snapshot_last_n_per_direction(2);
        assert_eq!(snap.len(), 4);
        assert_eq!(snap[0].bytes, vec![4]);
        assert_eq!(snap[1].bytes, vec![0x84]);
        assert_eq!(snap[2].bytes, vec![5]);
        assert_eq!(snap[3].bytes, vec![0x85]);
    }

    #[test]
    fn truncate_oversized_frame() {
        let mut ring = PacketRingBuffer::new();
        let huge = vec![7_u8; PACKET_RING_MAX_FRAME_BYTES + 10_000];
        ring.push(PacketRingDirection::Tx, None, &huge);
        let f = ring.frames.back().expect("frame");
        assert_eq!(f.bytes.len(), PACKET_RING_MAX_FRAME_BYTES);
    }
}
