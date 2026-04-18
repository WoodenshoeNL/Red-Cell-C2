use super::*;

#[test]
fn payload_dialog_new_defaults() {
    let dialog = PayloadDialogState::new();
    assert_eq!(dialog.agent_type, "Demon");
    assert!(dialog.listener.is_empty());
    assert_eq!(dialog.arch, PayloadArch::X64);
    assert_eq!(dialog.format, PayloadFormat::WindowsExe);
    assert_eq!(dialog.sleep, "2");
    assert_eq!(dialog.jitter, "20");
    assert!(dialog.indirect_syscall);
    assert_eq!(dialog.sleep_technique, SleepTechnique::WaitForSingleObjectEx);
    assert_eq!(dialog.alloc, AllocMethod::NativeSyscall);
    assert_eq!(dialog.execute, ExecuteMethod::NativeSyscall);
    assert_eq!(dialog.spawn64, r"C:\Windows\System32\notepad.exe");
    assert_eq!(dialog.spawn32, r"C:\Windows\SysWOW64\notepad.exe");
    assert!(!dialog.building);
}

#[test]
fn payload_dialog_config_json_contains_all_fields() {
    let dialog = PayloadDialogState::new();
    let json_str = dialog.config_json();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(parsed["Sleep"], "2");
    assert_eq!(parsed["Jitter"], "20");
    assert_eq!(parsed["IndirectSyscall"], true);
    assert_eq!(parsed["SleepTechnique"], "WaitForSingleObjectEx");
    assert_eq!(parsed["Alloc"], "Native/Syscall");
    assert_eq!(parsed["Execute"], "Native/Syscall");
    assert_eq!(parsed["Spawn64"], r"C:\Windows\System32\notepad.exe");
    assert_eq!(parsed["Spawn32"], r"C:\Windows\SysWOW64\notepad.exe");
}

#[test]
fn payload_dialog_config_json_reflects_changes() {
    let mut dialog = PayloadDialogState::new();
    dialog.sleep = "10".to_owned();
    dialog.jitter = "50".to_owned();
    dialog.indirect_syscall = false;
    dialog.sleep_technique = SleepTechnique::Ekko;
    dialog.alloc = AllocMethod::Win32;
    dialog.execute = ExecuteMethod::Win32;

    let json_str = dialog.config_json();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(parsed["Sleep"], "10");
    assert_eq!(parsed["Jitter"], "50");
    assert_eq!(parsed["IndirectSyscall"], false);
    assert_eq!(parsed["SleepTechnique"], "Ekko");
    assert_eq!(parsed["Alloc"], "Win32");
    assert_eq!(parsed["Execute"], "Win32");
}

#[test]
fn build_payload_request_creates_correct_message() {
    let mut dialog = PayloadDialogState::new();
    dialog.listener = "http-listener".to_owned();
    dialog.arch = PayloadArch::X86;
    dialog.format = PayloadFormat::WindowsShellcode;

    let msg = build_payload_request(&dialog, "operator1");
    match msg {
        OperatorMessage::BuildPayloadRequest(m) => {
            assert_eq!(m.head.event, EventCode::Gate);
            assert_eq!(m.head.user, "operator1");
            assert_eq!(m.info.agent_type, "Demon");
            assert_eq!(m.info.listener, "http-listener");
            assert_eq!(m.info.arch, "x86");
            assert_eq!(m.info.format, "Windows Shellcode");
            // Config should be valid JSON
            let config: serde_json::Value = serde_json::from_str(&m.info.config).unwrap();
            assert_eq!(config["Sleep"], "2");
        }
        _ => panic!("expected BuildPayloadRequest"),
    }
}

#[test]
fn payload_arch_labels() {
    assert_eq!(PayloadArch::X64.label(), "x64");
    assert_eq!(PayloadArch::X86.label(), "x86");
}

#[test]
fn payload_format_labels() {
    assert_eq!(PayloadFormat::WindowsExe.label(), "Windows Exe");
    assert_eq!(PayloadFormat::WindowsServiceExe.label(), "Windows Service Exe");
    assert_eq!(PayloadFormat::WindowsDll.label(), "Windows Dll");
    assert_eq!(PayloadFormat::WindowsReflectiveDll.label(), "Windows Reflective Dll");
    assert_eq!(PayloadFormat::WindowsShellcode.label(), "Windows Shellcode");
}

#[test]
fn sleep_technique_labels() {
    assert_eq!(SleepTechnique::WaitForSingleObjectEx.label(), "WaitForSingleObjectEx");
    assert_eq!(SleepTechnique::Ekko.label(), "Ekko");
    assert_eq!(SleepTechnique::Zilean.label(), "Zilean");
    assert_eq!(SleepTechnique::None.label(), "None");
}

#[test]
fn alloc_execute_method_labels() {
    assert_eq!(AllocMethod::NativeSyscall.label(), "Native/Syscall");
    assert_eq!(AllocMethod::Win32.label(), "Win32");
    assert_eq!(ExecuteMethod::NativeSyscall.label(), "Native/Syscall");
    assert_eq!(ExecuteMethod::Win32.label(), "Win32");
}
