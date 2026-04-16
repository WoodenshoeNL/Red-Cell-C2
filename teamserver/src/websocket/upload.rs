//! Upload-chunking logic: splits large file uploads into MemFile chunks
//! followed by a final filesystem upload job.

use red_cell_common::demon::{DemonCommand, DemonFilesystemCommand};

use super::AgentCommandError;
use super::command_enc::{
    encode_utf16, random_u32, required_string, write_len_prefixed_bytes, write_u32, write_u64,
};
use crate::{Job, MAX_AGENT_MESSAGE_LEN};

/// Build the sequence of jobs needed to upload a file to an agent.
///
/// Large uploads are split into `MAX_AGENT_MESSAGE_LEN`-sized MemFile chunks,
/// followed by a final filesystem-upload job that references the same `memfile_id`.
pub(super) fn build_upload_jobs(
    info: &red_cell_common::operator::AgentTaskInfo,
    request_id: u32,
    created_at: &str,
    operator: &str,
) -> Result<Vec<Job>, AgentCommandError> {
    let remote_path = upload_remote_path(info)?;
    let content = upload_content(info)?;
    let memfile_id = random_u32();
    let mut jobs = Vec::new();

    for chunk in content.chunks(MAX_AGENT_MESSAGE_LEN) {
        let mut payload = Vec::new();
        write_u32(&mut payload, memfile_id);
        write_u64(&mut payload, content.len() as u64);
        write_len_prefixed_bytes(&mut payload, chunk)?;
        jobs.push(Job {
            command: u32::from(DemonCommand::CommandMemFile),
            request_id: random_u32(),
            payload,
            command_line: info.command_line.clone(),
            task_id: info.task_id.clone(),
            created_at: created_at.to_owned(),
            operator: operator.to_owned(),
        });
    }

    let mut payload = Vec::new();
    write_u32(&mut payload, u32::from(DemonFilesystemCommand::Upload));
    write_len_prefixed_bytes(&mut payload, &encode_utf16(&remote_path))?;
    write_u32(&mut payload, memfile_id);
    jobs.push(Job {
        command: u32::from(DemonCommand::CommandFs),
        request_id,
        payload,
        command_line: info.command_line.clone(),
        task_id: info.task_id.clone(),
        created_at: created_at.to_owned(),
        operator: operator.to_owned(),
    });

    Ok(jobs)
}

/// Extract the remote file path from a filesystem-upload task's arguments.
///
/// The `Arguments` field is expected to contain two base64-encoded values
/// separated by `;` — the first is the remote path.
pub(super) fn upload_remote_path(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<String, AgentCommandError> {
    let args = required_string(info, &["Arguments"], "Arguments")?;
    let remote =
        args.split(';').next().ok_or(AgentCommandError::MissingField { field: "Arguments" })?;
    let remote = decode_base64_field("Arguments[0]", remote)?;
    Ok(String::from_utf8_lossy(&remote).into_owned())
}

/// Extract the file content from a filesystem-upload task's arguments.
///
/// The `Arguments` field is expected to contain two base64-encoded values
/// separated by `;` — the second is the file content.
pub(super) fn upload_content(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Vec<u8>, AgentCommandError> {
    let args = required_string(info, &["Arguments"], "Arguments")?;
    let mut parts = args.splitn(2, ';');
    let _remote = parts.next().ok_or(AgentCommandError::MissingField { field: "Arguments" })?;
    let content = parts.next().ok_or(AgentCommandError::MissingField { field: "Arguments" })?;
    decode_base64_field("Arguments[1]", content)
}

/// Decode a base64-encoded field value.
fn decode_base64_field(field: &str, value: &str) -> Result<Vec<u8>, AgentCommandError> {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

    BASE64_STANDARD.decode(value.trim()).map_err(|error| AgentCommandError::InvalidBase64Field {
        field: field.to_owned(),
        message: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use red_cell_common::demon::{DemonCommand, DemonFilesystemCommand};
    use red_cell_common::operator::AgentTaskInfo;

    use super::super::command_enc::{build_jobs, encode_utf16};
    use crate::MAX_AGENT_MESSAGE_LEN;

    #[test]
    fn build_jobs_splits_upload_into_memfile_chunks_and_final_fs_job() {
        let content = vec![0x41; MAX_AGENT_MESSAGE_LEN + 16];
        let jobs = build_jobs(
            &AgentTaskInfo {
                task_id: "2F".to_owned(),
                command_line: "upload local.bin remote.bin".to_owned(),
                demon_id: "DEADBEEF".to_owned(),
                command_id: u32::from(DemonCommand::CommandFs).to_string(),
                sub_command: Some("upload".to_owned()),
                arguments: Some(format!(
                    "{};{}",
                    BASE64_STANDARD.encode("C:\\Temp\\remote.bin"),
                    BASE64_STANDARD.encode(&content)
                )),
                ..AgentTaskInfo::default()
            },
            "",
        )
        .expect("filesystem upload should encode");

        assert_eq!(jobs.len(), 3);
        assert_eq!(jobs[0].command, u32::from(DemonCommand::CommandMemFile));
        assert_eq!(jobs[1].command, u32::from(DemonCommand::CommandMemFile));
        assert_eq!(jobs[2].command, u32::from(DemonCommand::CommandFs));
        assert_eq!(jobs[2].request_id, 0x2F);

        let memfile_id =
            u32::from_le_bytes(jobs[0].payload[0..4].try_into().expect("memfile id should exist"));
        assert_eq!(
            u64::from_le_bytes(
                jobs[0].payload[4..12].try_into().expect("memfile size should exist")
            ),
            u64::try_from(content.len()).expect("content length should fit"),
        );
        assert_eq!(
            u32::from_le_bytes(
                jobs[2].payload[0..4].try_into().expect("upload command should exist")
            ),
            u32::from(DemonFilesystemCommand::Upload)
        );
        let final_memfile_id = u32::from_le_bytes(
            jobs[2].payload[jobs[2].payload.len() - 4..]
                .try_into()
                .expect("final memfile id should exist"),
        );
        assert_eq!(memfile_id, final_memfile_id);
    }

    #[test]
    fn upload_remote_path_extracts_first_argument() {
        let info = AgentTaskInfo {
            arguments: Some(format!(
                "{};{}",
                BASE64_STANDARD.encode("C:\\Windows\\remote.txt"),
                BASE64_STANDARD.encode("file-content")
            )),
            ..AgentTaskInfo::default()
        };
        let path = super::upload_remote_path(&info).expect("should extract remote path");
        assert_eq!(path, "C:\\Windows\\remote.txt");
    }

    #[test]
    fn upload_content_extracts_second_argument() {
        let info = AgentTaskInfo {
            arguments: Some(format!(
                "{};{}",
                BASE64_STANDARD.encode("C:\\remote.bin"),
                BASE64_STANDARD.encode(b"\xDE\xAD\xBE\xEF")
            )),
            ..AgentTaskInfo::default()
        };
        let content = super::upload_content(&info).expect("should extract content");
        assert_eq!(content, b"\xDE\xAD\xBE\xEF");
    }

    #[test]
    fn build_upload_jobs_single_chunk() {
        let content = vec![0x42; 100]; // small enough for one chunk
        let jobs = super::build_upload_jobs(
            &AgentTaskInfo {
                task_id: "10".to_owned(),
                command_line: "upload small.bin remote.bin".to_owned(),
                demon_id: "DEADBEEF".to_owned(),
                command_id: u32::from(DemonCommand::CommandFs).to_string(),
                sub_command: Some("upload".to_owned()),
                arguments: Some(format!(
                    "{};{}",
                    BASE64_STANDARD.encode("C:\\remote.bin"),
                    BASE64_STANDARD.encode(&content)
                )),
                ..AgentTaskInfo::default()
            },
            0x10,
            "2026-01-01T00:00:00Z",
            "operator1",
        )
        .expect("small upload should encode");

        // One memfile chunk + one fs command
        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].command, u32::from(DemonCommand::CommandMemFile));
        assert_eq!(jobs[1].command, u32::from(DemonCommand::CommandFs));
        assert_eq!(jobs[1].request_id, 0x10);
        assert_eq!(jobs[1].operator, "operator1");
    }

    #[test]
    fn upload_remote_path_missing_arguments_fails() {
        let info = AgentTaskInfo::default();
        assert!(super::upload_remote_path(&info).is_err());
    }

    #[test]
    fn upload_content_missing_second_part_fails() {
        let info = AgentTaskInfo {
            arguments: Some(BASE64_STANDARD.encode("only-one-part")),
            ..AgentTaskInfo::default()
        };
        assert!(super::upload_content(&info).is_err());
    }
}
