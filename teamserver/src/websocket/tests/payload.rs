//! Demon-job payload encoding tests: `build_job` / `build_jobs` coverage
//! across every DemonCommand variant, task-id validation, unknown-command
//! handling, plus the shared `write_len_prefixed_bytes` and
//! `serialize_for_audit` helpers.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::{
    demon::{
        DemonCommand, DemonFilesystemCommand, DemonInjectWay, DemonProcessCommand,
        DemonTokenCommand,
    },
    operator::AgentTaskInfo,
};
use serde_json::Value;

use super::super::{
    AgentCommandError, build_job, build_jobs, encode_utf16, write_len_prefixed_bytes, write_u32,
};
use super::{decode_utf16, read_len_prefixed_bytes, read_u32_le};

#[test]
fn build_job_encodes_process_list_payload() {
    let job = build_job(&AgentTaskInfo {
        task_id: "2A".to_owned(),
        command_line: "ps".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandProcList).to_string(),
        extra: BTreeMap::from([(String::from("FromProcessManager"), Value::Bool(true))]),
        ..AgentTaskInfo::default()
    })
    .expect("process list job should build");

    assert_eq!(job.command, u32::from(DemonCommand::CommandProcList));
    assert_eq!(job.payload, 1_u32.to_le_bytes());
}

#[test]
fn build_job_encodes_process_create_payload() {
    let encoded_args = BASE64_STANDARD.encode("\"C:\\Windows\\System32\\cmd.exe\" /c whoami");
    let job = build_job(&AgentTaskInfo {
        task_id: "2B".to_owned(),
        command_line: "proc create normal cmd.exe /c whoami".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandProc).to_string(),
        sub_command: Some("create".to_owned()),
        extra: BTreeMap::from([(
            String::from("Args"),
            Value::String(format!("0;TRUE;FALSE;C:\\Windows\\System32\\cmd.exe;{encoded_args}")),
        )]),
        ..AgentTaskInfo::default()
    })
    .expect("process create job should build");

    let mut offset = 0usize;
    assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonProcessCommand::Create));
    assert_eq!(read_u32_le(&job.payload, &mut offset), 0);
    assert_eq!(
        decode_utf16(read_len_prefixed_bytes(&job.payload, &mut offset)),
        "C:\\Windows\\System32\\cmd.exe"
    );
    assert_eq!(
        decode_utf16(read_len_prefixed_bytes(&job.payload, &mut offset)),
        "\"C:\\Windows\\System32\\cmd.exe\" /c whoami"
    );
    assert_eq!(read_u32_le(&job.payload, &mut offset), 0);
    assert_eq!(read_u32_le(&job.payload, &mut offset), 1);
}

/// Empty program must encode as length=0 so Demon sets Process=NULL (not L"" which fails CreateProcessW).
/// Args must be wrapped in "cmd.exe /c " so CMD builtins and executables without full paths work.
#[test]
fn build_job_encodes_process_create_empty_program_as_length_zero() {
    use red_cell_common::demon::format_proc_create_args;

    let args = format_proc_create_args("whoami");
    let job = build_job(&AgentTaskInfo {
        task_id: "2B2".to_owned(),
        command_line: "whoami".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandProc).to_string(),
        sub_command: Some("create".to_owned()),
        extra: BTreeMap::from([(String::from("Args"), Value::String(args))]),
        ..AgentTaskInfo::default()
    })
    .expect("process create (empty program) job should build");

    let mut offset = 0usize;
    assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonProcessCommand::Create));
    assert_eq!(read_u32_le(&job.payload, &mut offset), 0); // state
    // Program field must be length=0 (no bytes), not length=2 (null-terminator only)
    let program_bytes = read_len_prefixed_bytes(&job.payload, &mut offset);
    assert_eq!(
        program_bytes.len(),
        0,
        "empty program must encode as 0 bytes so Demon sets Process=NULL"
    );
    // Args field must decode to the cmd.exe-wrapped command so CMD builtins work
    assert_eq!(
        decode_utf16(read_len_prefixed_bytes(&job.payload, &mut offset)),
        "cmd.exe /c whoami"
    );
    assert_eq!(read_u32_le(&job.payload, &mut offset), 1); // piped
    assert_eq!(read_u32_le(&job.payload, &mut offset), 1); // verbose
}

#[test]
fn build_job_encodes_shellcode_inject_and_token_impersonation() {
    let shellcode = BASE64_STANDARD.encode([0x90_u8, 0x90, 0xCC]);
    let shellcode_job = build_job(&AgentTaskInfo {
        task_id: "2C".to_owned(),
        command_line: "shellcode inject x64 4444 /tmp/payload.bin".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandInjectShellcode).to_string(),
        extra: BTreeMap::from([
            (String::from("Way"), Value::String("Inject".to_owned())),
            (String::from("Technique"), Value::String("default".to_owned())),
            (String::from("Arch"), Value::String("x64".to_owned())),
            (String::from("Binary"), Value::String(shellcode)),
            (String::from("PID"), Value::String("4444".to_owned())),
        ]),
        ..AgentTaskInfo::default()
    })
    .expect("shellcode inject job should build");

    let mut offset = 0usize;
    assert_eq!(read_u32_le(&shellcode_job.payload, &mut offset), u32::from(DemonInjectWay::Inject));
    assert_eq!(read_u32_le(&shellcode_job.payload, &mut offset), 0);
    assert_eq!(read_u32_le(&shellcode_job.payload, &mut offset), 1);
    assert_eq!(
        read_len_prefixed_bytes(&shellcode_job.payload, &mut offset),
        vec![0x90, 0x90, 0xCC]
    );
    assert_eq!(read_len_prefixed_bytes(&shellcode_job.payload, &mut offset), Vec::<u8>::new());
    assert_eq!(read_u32_le(&shellcode_job.payload, &mut offset), 4444);

    let token_job = build_job(&AgentTaskInfo {
        task_id: "2D".to_owned(),
        command_line: "token impersonate 7".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandToken).to_string(),
        sub_command: Some("impersonate".to_owned()),
        arguments: Some("7".to_owned()),
        ..AgentTaskInfo::default()
    })
    .expect("token impersonation job should build");
    assert_eq!(
        token_job.payload,
        [u32::from(DemonTokenCommand::Impersonate).to_le_bytes(), 7_u32.to_le_bytes()].concat()
    );
}

#[test]
fn build_jobs_encodes_filesystem_copy_payload() -> Result<(), crate::TeamserverError> {
    let jobs = build_jobs(
        &AgentTaskInfo {
            task_id: "2E".to_owned(),
            command_line: "cp a b".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandFs).to_string(),
            sub_command: Some("cp".to_owned()),
            arguments: Some(format!(
                "{};{}",
                BASE64_STANDARD.encode("C:\\temp\\a.txt"),
                BASE64_STANDARD.encode("D:\\loot\\b.txt")
            )),
            ..AgentTaskInfo::default()
        },
        "",
    )
    .expect("filesystem copy should encode");

    assert_eq!(jobs.len(), 1);
    let mut expected = Vec::new();
    write_u32(&mut expected, u32::from(DemonFilesystemCommand::Copy));
    write_len_prefixed_bytes(&mut expected, &encode_utf16("C:\\temp\\a.txt"))?;
    write_len_prefixed_bytes(&mut expected, &encode_utf16("D:\\loot\\b.txt"))?;
    assert_eq!(jobs[0].command, u32::from(DemonCommand::CommandFs));
    assert_eq!(jobs[0].payload, expected);
    Ok(())
}

#[test]
fn build_job_encodes_filesystem_dir_payload() -> Result<(), crate::TeamserverError> {
    let args = "C:\\Users;true;false;true;false;*.txt;2024-01-01;name".to_owned();
    let job = build_job(&AgentTaskInfo {
        task_id: "40".to_owned(),
        command_line: "ls C:\\Users".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        sub_command: Some("dir".to_owned()),
        arguments: Some(args),
        ..AgentTaskInfo::default()
    })
    .expect("filesystem dir should encode");

    assert_eq!(job.command, u32::from(DemonCommand::CommandFs));
    let mut offset = 0usize;
    assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonFilesystemCommand::Dir));
    assert_eq!(read_u32_le(&job.payload, &mut offset), 0); // reserved zero
    assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), encode_utf16("C:\\Users"));
    assert_eq!(read_u32_le(&job.payload, &mut offset), 1); // bool true
    assert_eq!(read_u32_le(&job.payload, &mut offset), 0); // bool false
    assert_eq!(read_u32_le(&job.payload, &mut offset), 1); // bool true
    assert_eq!(read_u32_le(&job.payload, &mut offset), 0); // bool false
    assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), encode_utf16("*.txt"));
    assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), encode_utf16("2024-01-01"));
    assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), encode_utf16("name"));
    assert_eq!(offset, job.payload.len());
    Ok(())
}

#[test]
fn build_job_encodes_filesystem_download_payload() -> Result<(), crate::TeamserverError> {
    let job = build_job(&AgentTaskInfo {
        task_id: "41".to_owned(),
        command_line: "download C:\\secret.txt".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        sub_command: Some("download".to_owned()),
        arguments: Some(BASE64_STANDARD.encode("C:\\secret.txt")),
        ..AgentTaskInfo::default()
    })
    .expect("filesystem download should encode");

    assert_eq!(job.command, u32::from(DemonCommand::CommandFs));
    let mut offset = 0usize;
    assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonFilesystemCommand::Download));
    assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), encode_utf16("C:\\secret.txt"));
    assert_eq!(offset, job.payload.len());
    Ok(())
}

#[test]
fn build_job_encodes_filesystem_cat_payload() -> Result<(), crate::TeamserverError> {
    let job = build_job(&AgentTaskInfo {
        task_id: "42".to_owned(),
        command_line: "cat C:\\etc\\hosts".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        sub_command: Some("cat".to_owned()),
        arguments: Some(BASE64_STANDARD.encode("C:\\etc\\hosts")),
        ..AgentTaskInfo::default()
    })
    .expect("filesystem cat should encode");

    assert_eq!(job.command, u32::from(DemonCommand::CommandFs));
    let mut offset = 0usize;
    assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonFilesystemCommand::Cat));
    assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), encode_utf16("C:\\etc\\hosts"));
    assert_eq!(offset, job.payload.len());
    Ok(())
}

#[test]
fn build_job_encodes_filesystem_cd_payload() -> Result<(), crate::TeamserverError> {
    let job = build_job(&AgentTaskInfo {
        task_id: "43".to_owned(),
        command_line: "cd C:\\Windows".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        sub_command: Some("cd".to_owned()),
        arguments: Some("C:\\Windows".to_owned()),
        ..AgentTaskInfo::default()
    })
    .expect("filesystem cd should encode");

    assert_eq!(job.command, u32::from(DemonCommand::CommandFs));
    let mut offset = 0usize;
    assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonFilesystemCommand::Cd));
    assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), encode_utf16("C:\\Windows"));
    assert_eq!(offset, job.payload.len());
    Ok(())
}

#[test]
fn build_job_encodes_filesystem_remove_payload() -> Result<(), crate::TeamserverError> {
    let job = build_job(&AgentTaskInfo {
        task_id: "44".to_owned(),
        command_line: "rm C:\\tmp\\evil.exe".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        sub_command: Some("remove".to_owned()),
        arguments: Some("C:\\tmp\\evil.exe".to_owned()),
        ..AgentTaskInfo::default()
    })
    .expect("filesystem remove should encode");

    assert_eq!(job.command, u32::from(DemonCommand::CommandFs));
    let mut offset = 0usize;
    assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonFilesystemCommand::Remove));
    assert_eq!(
        read_len_prefixed_bytes(&job.payload, &mut offset),
        encode_utf16("C:\\tmp\\evil.exe")
    );
    assert_eq!(offset, job.payload.len());
    Ok(())
}

#[test]
fn build_job_encodes_filesystem_mkdir_payload() -> Result<(), crate::TeamserverError> {
    let job = build_job(&AgentTaskInfo {
        task_id: "45".to_owned(),
        command_line: "mkdir C:\\loot".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        sub_command: Some("mkdir".to_owned()),
        arguments: Some("C:\\loot".to_owned()),
        ..AgentTaskInfo::default()
    })
    .expect("filesystem mkdir should encode");

    assert_eq!(job.command, u32::from(DemonCommand::CommandFs));
    let mut offset = 0usize;
    assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonFilesystemCommand::Mkdir));
    assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), encode_utf16("C:\\loot"));
    assert_eq!(offset, job.payload.len());
    Ok(())
}

#[test]
fn build_job_encodes_filesystem_move_payload() -> Result<(), crate::TeamserverError> {
    let job = build_job(&AgentTaskInfo {
        task_id: "46".to_owned(),
        command_line: "mv C:\\src.txt C:\\dst.txt".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        sub_command: Some("move".to_owned()),
        arguments: Some(format!(
            "{};{}",
            BASE64_STANDARD.encode("C:\\src.txt"),
            BASE64_STANDARD.encode("C:\\dst.txt")
        )),
        ..AgentTaskInfo::default()
    })
    .expect("filesystem move should encode");

    assert_eq!(job.command, u32::from(DemonCommand::CommandFs));
    let mut offset = 0usize;
    assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonFilesystemCommand::Move));
    assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), encode_utf16("C:\\src.txt"));
    assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), encode_utf16("C:\\dst.txt"));
    assert_eq!(offset, job.payload.len());
    Ok(())
}

#[test]
fn build_job_encodes_filesystem_getpwd_payload() {
    let job = build_job(&AgentTaskInfo {
        task_id: "47".to_owned(),
        command_line: "pwd".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        sub_command: Some("pwd".to_owned()),
        ..AgentTaskInfo::default()
    })
    .expect("filesystem getpwd should encode");

    assert_eq!(job.command, u32::from(DemonCommand::CommandFs));
    // GetPwd writes only the 4-byte subcommand discriminant and nothing else.
    assert_eq!(job.payload.len(), 4);
    assert_eq!(
        u32::from_le_bytes(job.payload[0..4].try_into().expect("discriminant fits")),
        u32::from(DemonFilesystemCommand::GetPwd)
    );
}

#[test]
fn build_job_rejects_unknown_filesystem_subcommand() {
    let err = build_job(&AgentTaskInfo {
        task_id: "48".to_owned(),
        command_line: "fs cat_dog".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        sub_command: Some("cat_dog".to_owned()),
        ..AgentTaskInfo::default()
    })
    .expect_err("unknown filesystem subcommand should be rejected");

    assert!(
        matches!(err, AgentCommandError::UnsupportedFilesystemSubcommand { .. }),
        "expected UnsupportedFilesystemSubcommand, got {err:?}"
    );
}

#[test]
fn build_job_encodes_token_privs_list_payload_from_extra_subcommand_string() {
    let job = build_job(&AgentTaskInfo {
        task_id: "2F".to_owned(),
        command_line: "token privs-list".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandToken).to_string(),
        extra: BTreeMap::from([(
            String::from("SubCommand"),
            Value::String("privs-list".to_owned()),
        )]),
        ..AgentTaskInfo::default()
    })
    .expect("token privs-list job should build from extras");

    assert_eq!(
        job.payload,
        [u32::from(DemonTokenCommand::PrivsGetOrList).to_le_bytes(), 1_u32.to_le_bytes(),].concat()
    );
}

#[test]
fn build_job_encodes_token_privs_list_payload_from_extra_subcommand_numeric() {
    let job = build_job(&AgentTaskInfo {
        task_id: "30".to_owned(),
        command_line: "token 4".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandToken).to_string(),
        extra: BTreeMap::from([(String::from("SubCommand"), Value::String("4".to_owned()))]),
        ..AgentTaskInfo::default()
    })
    .expect("token privs-list job should build from numeric extra");

    assert_eq!(
        job.payload,
        [u32::from(DemonTokenCommand::PrivsGetOrList).to_le_bytes(), 1_u32.to_le_bytes(),].concat()
    );
}

#[test]
fn build_job_encodes_inject_dll_payload() {
    let loader = BASE64_STANDARD.encode([0xCC_u8, 0xDD, 0xEE]);
    let binary = BASE64_STANDARD.encode([0x4D_u8, 0x5A, 0x90, 0x00]);
    let arguments = BASE64_STANDARD.encode("test-arg");
    let job = build_job(&AgentTaskInfo {
        task_id: "30".to_owned(),
        command_line: "inject-dll 1234 payload.dll".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandInjectDll).to_string(),
        extra: BTreeMap::from([
            (String::from("PID"), Value::String("1234".to_owned())),
            (String::from("DllLoader"), Value::String(loader)),
            (String::from("Binary"), Value::String(binary)),
            (String::from("Arguments"), Value::String(arguments)),
            (String::from("Technique"), Value::String("0".to_owned())),
        ]),
        ..AgentTaskInfo::default()
    })
    .expect("inject dll job should build");

    assert_eq!(job.command, u32::from(DemonCommand::CommandInjectDll));
    let mut offset = 0usize;
    assert_eq!(read_u32_le(&job.payload, &mut offset), 0);
    assert_eq!(read_u32_le(&job.payload, &mut offset), 1234);
    assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), vec![0xCC, 0xDD, 0xEE]);
    assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), vec![0x4D, 0x5A, 0x90, 0x00]);
    assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), b"test-arg".to_vec());
}

#[test]
fn build_job_encodes_inject_dll_with_default_technique() {
    let loader = BASE64_STANDARD.encode([0xAA_u8]);
    let binary = BASE64_STANDARD.encode([0xBB_u8]);
    let job = build_job(&AgentTaskInfo {
        task_id: "31".to_owned(),
        command_line: "inject-dll 5555 minimal.dll".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandInjectDll).to_string(),
        extra: BTreeMap::from([
            (String::from("PID"), Value::String("5555".to_owned())),
            (String::from("DllLoader"), Value::String(loader)),
            (String::from("Binary"), Value::String(binary)),
        ]),
        ..AgentTaskInfo::default()
    })
    .expect("inject dll job should build with default technique");

    let mut offset = 0usize;
    assert_eq!(read_u32_le(&job.payload, &mut offset), 0);
    assert_eq!(read_u32_le(&job.payload, &mut offset), 5555);
}

#[test]
fn build_job_encodes_spawn_dll_payload() {
    let loader = BASE64_STANDARD.encode([0x11_u8, 0x22, 0x33]);
    let binary = BASE64_STANDARD.encode([0x4D_u8, 0x5A]);
    let arguments = BASE64_STANDARD.encode("spawn-args");
    let job = build_job(&AgentTaskInfo {
        task_id: "32".to_owned(),
        command_line: "spawn-dll payload.dll".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandSpawnDll).to_string(),
        extra: BTreeMap::from([
            (String::from("DllLoader"), Value::String(loader)),
            (String::from("Binary"), Value::String(binary)),
            (String::from("Arguments"), Value::String(arguments)),
        ]),
        ..AgentTaskInfo::default()
    })
    .expect("spawn dll job should build");

    assert_eq!(job.command, u32::from(DemonCommand::CommandSpawnDll));
    let mut offset = 0usize;
    assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), vec![0x11, 0x22, 0x33]);
    assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), vec![0x4D, 0x5A]);
    assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), b"spawn-args".to_vec());
}

#[test]
fn build_job_encodes_process_modules_payload() {
    let job = build_job(&AgentTaskInfo {
        task_id: "33".to_owned(),
        command_line: "proc modules 8888".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandProc).to_string(),
        sub_command: Some("modules".to_owned()),
        extra: BTreeMap::from([(String::from("Args"), Value::String("8888".to_owned()))]),
        ..AgentTaskInfo::default()
    })
    .expect("proc modules job should build");

    assert_eq!(job.command, u32::from(DemonCommand::CommandProc));
    let mut offset = 0usize;
    assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonProcessCommand::Modules));
    assert_eq!(read_u32_le(&job.payload, &mut offset), 8888);
}

#[test]
fn build_job_encodes_process_grep_payload() {
    let job = build_job(&AgentTaskInfo {
        task_id: "34".to_owned(),
        command_line: "proc grep svchost".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandProc).to_string(),
        sub_command: Some("grep".to_owned()),
        extra: BTreeMap::from([(String::from("Args"), Value::String("svchost".to_owned()))]),
        ..AgentTaskInfo::default()
    })
    .expect("proc grep job should build");

    assert_eq!(job.command, u32::from(DemonCommand::CommandProc));
    let mut offset = 0usize;
    assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonProcessCommand::Grep));
    let grep_pattern = decode_utf16(read_len_prefixed_bytes(&job.payload, &mut offset));
    assert_eq!(grep_pattern, "svchost");
}

#[test]
fn build_job_encodes_process_memory_payload() {
    let job = build_job(&AgentTaskInfo {
        task_id: "35".to_owned(),
        command_line: "proc memory 4321 PAGE_EXECUTE_READWRITE".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandProc).to_string(),
        sub_command: Some("memory".to_owned()),
        extra: BTreeMap::from([(
            String::from("Args"),
            Value::String("4321 PAGE_EXECUTE_READWRITE".to_owned()),
        )]),
        ..AgentTaskInfo::default()
    })
    .expect("proc memory job should build");

    assert_eq!(job.command, u32::from(DemonCommand::CommandProc));
    let mut offset = 0usize;
    assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonProcessCommand::Memory));
    assert_eq!(read_u32_le(&job.payload, &mut offset), 4321);
    assert_eq!(read_u32_le(&job.payload, &mut offset), 0x40);
}

#[test]
fn build_job_rejects_empty_task_id() {
    let result = build_job(&AgentTaskInfo {
        task_id: String::new(),
        command_line: "checkin".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
        ..AgentTaskInfo::default()
    });
    let err = result.expect_err("empty task_id should fail");
    assert!(matches!(err, AgentCommandError::InvalidTaskId { .. }));
}

#[test]
fn build_job_rejects_non_hex_task_id() {
    let result = build_job(&AgentTaskInfo {
        task_id: "not-hex".to_owned(),
        command_line: "checkin".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
        ..AgentTaskInfo::default()
    });
    let err = result.expect_err("non-hex task_id should fail");
    assert!(matches!(err, AgentCommandError::InvalidTaskId { .. }));
}

#[test]
fn build_job_rejects_overflowing_task_id() {
    let result = build_job(&AgentTaskInfo {
        task_id: "FFFFFFFFFF".to_owned(),
        command_line: "checkin".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
        ..AgentTaskInfo::default()
    });
    let err = result.expect_err("overflowing task_id should fail");
    assert!(matches!(err, AgentCommandError::InvalidTaskId { .. }));
}

#[test]
fn build_job_accepts_valid_hex_task_id() {
    let job = build_job(&AgentTaskInfo {
        task_id: "FF".to_owned(),
        command_line: "checkin".to_owned(),
        demon_id: "DEADBEEF".to_owned(),
        command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
        ..AgentTaskInfo::default()
    })
    .expect("valid hex task_id should succeed");
    assert_eq!(job.request_id, 0xFF);
}

#[test]
fn build_jobs_rejects_unknown_command_id_without_raw_payload() {
    // An unrecognised numeric command ID with no raw payload must be rejected.
    let result = build_jobs(
        &AgentTaskInfo {
            task_id: "01".to_owned(),
            command_line: "bogus".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: "99999".to_owned(),
            ..AgentTaskInfo::default()
        },
        "op",
    );
    match result {
        Err(AgentCommandError::UnsupportedCommandId { command_id }) => {
            assert_eq!(command_id, 99999);
        }
        other => panic!("expected UnsupportedCommandId, got {other:?}"),
    }
}

#[test]
fn build_jobs_accepts_unknown_command_id_with_raw_payload() {
    // An unrecognised command ID should still be accepted when the caller
    // provides an explicit raw payload.
    let mut extra = BTreeMap::new();
    extra.insert("Payload".to_owned(), serde_json::Value::String("hello".to_owned()));
    let jobs = build_jobs(
        &AgentTaskInfo {
            task_id: "01".to_owned(),
            command_line: "custom".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: "99999".to_owned(),
            extra,
            ..AgentTaskInfo::default()
        },
        "op",
    )
    .expect("unknown command with raw payload should succeed");
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].command, 99999);
    assert_eq!(jobs[0].payload, b"hello");
}

#[test]
fn build_jobs_accepts_known_command_without_explicit_payload() {
    // A recognised Demon command that does not have a specialised encoder
    // should succeed with an empty payload.
    let jobs = build_jobs(
        &AgentTaskInfo {
            task_id: "0A".to_owned(),
            command_line: "checkin".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
            ..AgentTaskInfo::default()
        },
        "op",
    )
    .expect("known command without payload should succeed");
    assert_eq!(jobs.len(), 1);
    assert!(jobs[0].payload.is_empty());
}

#[test]
fn write_len_prefixed_bytes_normal_input() -> Result<(), crate::TeamserverError> {
    let mut buf = Vec::new();
    write_len_prefixed_bytes(&mut buf, b"test")?;
    assert_eq!(buf[..4], 4_u32.to_le_bytes());
    assert_eq!(&buf[4..], b"test");
    Ok(())
}

#[test]
fn write_len_prefixed_bytes_empty_input() -> Result<(), crate::TeamserverError> {
    let mut buf = Vec::new();
    write_len_prefixed_bytes(&mut buf, &[])?;
    assert_eq!(buf, 0_u32.to_le_bytes());
    Ok(())
}

#[test]
fn serialize_for_audit_returns_value_on_success() {
    let data = serde_json::json!({"key": "value"});
    let result = super::super::serialize_for_audit(&data, "test");
    assert_eq!(result, Some(data));
}

#[test]
fn serialize_for_audit_returns_none_on_failure() {
    /// A type whose `Serialize` implementation always fails.
    struct AlwaysFail;
    impl serde::Serialize for AlwaysFail {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("intentional failure"))
        }
    }
    let result = super::super::serialize_for_audit(&AlwaysFail, "test.fail");
    assert!(result.is_none(), "should return None on serialization failure");
}
