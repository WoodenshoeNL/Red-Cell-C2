use super::*;

// ── Agent format matrix: archon vs demon binary differences ──────────

#[test]
fn pack_config_heap_enc_false_is_packed_as_zero() -> Result<(), Box<dyn std::error::Error>> {
    let config = serde_json::from_value::<Map<String, Value>>(json!({
        "Sleep": "5",
        "Jitter": "0",
        "Sleep Technique": "WaitForSingleObjectEx",
        "HeapEnc": false,
        "Injection": {
            "Alloc": "Win32",
            "Execute": "Win32",
            "Spawn64": "a",
            "Spawn32": "b"
        }
    }))?;
    let listener = ListenerConfig::Smb(red_cell_common::SmbListenerConfig {
        name: "smb".to_owned(),
        pipe_name: "pivot".to_owned(),
        kill_date: None,
        working_hours: None,
    });

    // HeapEnc is Archon-only — use "archon" to verify the explicit-false case.
    let bytes = pack_config(&listener, &config, "archon")?;
    let mut cursor = bytes.as_slice();
    assert_eq!(read_u32(&mut cursor)?, 5);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 1);
    assert_eq!(read_u32(&mut cursor)?, 1);
    assert_eq!(read_wstring(&mut cursor)?, "a");
    assert_eq!(read_wstring(&mut cursor)?, "b");
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0); // HeapEnc (explicit false)
    read_u32(&mut cursor)?; // JobExecution (Archon-only)
    read_wstring(&mut cursor)?; // StompDll (Archon-only)
    assert_eq!(read_wstring(&mut cursor)?, r"\\.\pipe\pivot");
    assert_eq!(read_u64(&mut cursor)?, 0);
    assert_eq!(read_u32(&mut cursor)?, 0);
    assert!(cursor.is_empty());
    Ok(())
}

#[test]
fn pack_config_job_execution_threadpool_is_packed_as_one() -> Result<(), Box<dyn std::error::Error>>
{
    let config = serde_json::from_value::<Map<String, Value>>(json!({
        "Sleep": "5",
        "Jitter": "0",
        "Sleep Technique": "WaitForSingleObjectEx",
        "JobExecution": "threadpool",
        "Injection": {
            "Alloc": "Win32",
            "Execute": "Win32",
            "Spawn64": "a",
            "Spawn32": "b"
        }
    }))?;
    let listener = ListenerConfig::Smb(red_cell_common::SmbListenerConfig {
        name: "smb".to_owned(),
        pipe_name: "pivot".to_owned(),
        kill_date: None,
        working_hours: None,
    });
    let bytes = pack_config(&listener, &config, "archon")?;
    let mut cursor = bytes.as_slice();
    // skip sleep, jitter, alloc, execute, spawn64, spawn32, technique, bypass, stackspoof,
    // proxyloading, syscall, amsi, heapenc
    read_u32(&mut cursor)?; // sleep
    read_u32(&mut cursor)?; // jitter
    read_u32(&mut cursor)?; // alloc
    read_u32(&mut cursor)?; // execute
    read_wstring(&mut cursor)?; // spawn64
    read_wstring(&mut cursor)?; // spawn32
    read_u32(&mut cursor)?; // SleepTechnique
    read_u32(&mut cursor)?; // SleepJmpBypass
    read_u32(&mut cursor)?; // StackSpoof
    read_u32(&mut cursor)?; // ProxyLoading
    read_u32(&mut cursor)?; // SysIndirect
    read_u32(&mut cursor)?; // AmsiEtwPatch
    read_u32(&mut cursor)?; // HeapEnc
    assert_eq!(read_u32(&mut cursor)?, 1); // JobExecution: threadpool (Archon-only)
    assert_eq!(read_wstring(&mut cursor)?, ""); // StompDll: auto-select (Archon-only)
    Ok(())
}

#[test]
fn pack_config_stomp_dll_is_packed_as_wstring() -> Result<(), Box<dyn std::error::Error>> {
    let config = serde_json::from_value::<Map<String, Value>>(json!({
        "Sleep": "5",
        "Jitter": "0",
        "Sleep Technique": "WaitForSingleObjectEx",
        "StompDll": "WINMM.DLL",
        "Injection": {
            "Alloc": "Win32",
            "Execute": "Win32",
            "Spawn64": "a",
            "Spawn32": "b"
        }
    }))?;
    let listener = ListenerConfig::Smb(red_cell_common::SmbListenerConfig {
        name: "smb".to_owned(),
        pipe_name: "pivot".to_owned(),
        kill_date: None,
        working_hours: None,
    });
    let bytes = pack_config(&listener, &config, "archon")?;
    let mut cursor = bytes.as_slice();
    read_u32(&mut cursor)?; // sleep
    read_u32(&mut cursor)?; // jitter
    read_u32(&mut cursor)?; // alloc
    read_u32(&mut cursor)?; // execute
    read_wstring(&mut cursor)?; // spawn64
    read_wstring(&mut cursor)?; // spawn32
    read_u32(&mut cursor)?; // SleepTechnique
    read_u32(&mut cursor)?; // SleepJmpBypass
    read_u32(&mut cursor)?; // StackSpoof
    read_u32(&mut cursor)?; // ProxyLoading
    read_u32(&mut cursor)?; // SysIndirect
    read_u32(&mut cursor)?; // AmsiEtwPatch
    read_u32(&mut cursor)?; // HeapEnc
    assert_eq!(read_u32(&mut cursor)?, 0); // JobExecution: thread (default, Archon-only)
    assert_eq!(read_wstring(&mut cursor)?, "WINMM.DLL"); // StompDll (Archon-only)
    Ok(())
}

#[test]
fn pack_config_demon_excludes_archon_only_fields() -> Result<(), Box<dyn std::error::Error>> {
    // Demon blobs must NOT include HeapEnc, JobExecution, or StompDll, even
    // when those keys are present in the config map.  After AmsiEtwPatch, the
    // next bytes must be the SMB pipe wstring — the frozen Demon agent does
    // not read any Archon-only fields.
    let config = serde_json::from_value::<Map<String, Value>>(json!({
        "Sleep": "5",
        "Jitter": "0",
        "Sleep Technique": "WaitForSingleObjectEx",
        "HeapEnc": true,
        "JobExecution": "threadpool",
        "StompDll": "WINMM.DLL",
        "Injection": {
            "Alloc": "Win32",
            "Execute": "Win32",
            "Spawn64": "a",
            "Spawn32": "b"
        }
    }))?;
    let listener = ListenerConfig::Smb(red_cell_common::SmbListenerConfig {
        name: "smb".to_owned(),
        pipe_name: "pivot".to_owned(),
        kill_date: None,
        working_hours: None,
    });
    let bytes = pack_config(&listener, &config, "demon")?;
    let mut cursor = bytes.as_slice();
    read_u32(&mut cursor)?; // sleep
    read_u32(&mut cursor)?; // jitter
    read_u32(&mut cursor)?; // alloc
    read_u32(&mut cursor)?; // execute
    read_wstring(&mut cursor)?; // spawn64
    read_wstring(&mut cursor)?; // spawn32
    read_u32(&mut cursor)?; // SleepTechnique
    read_u32(&mut cursor)?; // SleepJmpBypass
    read_u32(&mut cursor)?; // StackSpoof
    read_u32(&mut cursor)?; // ProxyLoading
    read_u32(&mut cursor)?; // SysIndirect
    read_u32(&mut cursor)?; // AmsiEtwPatch
    // Next field must be the pipe path — HeapEnc/JobExecution/StompDll must not be present
    assert_eq!(read_wstring(&mut cursor)?, r"\\.\pipe\pivot");
    read_u64(&mut cursor)?; // KillDate
    read_u32(&mut cursor)?; // WorkingHours
    assert!(cursor.is_empty(), "demon blob has unexpected trailing bytes (Archon fields leaked)");
    Ok(())
}
