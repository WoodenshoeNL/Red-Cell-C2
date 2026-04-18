use super::*;

#[tokio::test]
async fn get_pwd_queues_structured_fs_callback() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(DemonFilesystemCommand::GetPwd as i32).to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Structured { command_id, request_id, payload }] = callbacks.as_slice()
    else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandFs));
    assert_eq!(*request_id, 1);

    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), u32::from(DemonFilesystemCommand::GetPwd));
    let path = read_utf16(payload, &mut offset);
    assert!(!path.is_empty());
}

#[tokio::test]
async fn memfile_then_upload_emits_expected_callbacks() {
    let content = b"phantom-upload";

    let mut memfile = Vec::new();
    memfile.extend_from_slice(&77_i32.to_le_bytes());
    memfile.extend_from_slice(&(content.len() as i64).to_le_bytes());
    memfile.extend_from_slice(&(content.len() as i32).to_le_bytes());
    memfile.extend_from_slice(content);

    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("upload.bin");

    let mut upload = Vec::new();
    upload.extend_from_slice(&(DemonFilesystemCommand::Upload as i32).to_le_bytes());
    upload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
    upload.extend_from_slice(&77_i32.to_le_bytes());

    let mut state = PhantomState::default();
    execute(
        &DemonPackage::new(DemonCommand::CommandMemFile, 3, memfile),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("memfile");
    execute(
        &DemonPackage::new(DemonCommand::CommandFs, 4, upload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("upload");

    let callbacks = state.drain_callbacks();
    assert!(matches!(
        callbacks.as_slice(),
        [
            PendingCallback::MemFileAck { request_id: 3, mem_file_id: 77, success: true },
            PendingCallback::FsUpload { request_id: 4, file_size, .. }
        ] if *file_size == content.len() as u32
    ));
    assert_eq!(std::fs::read(path).expect("read back"), content);
}

// ── CommandTransfer / chunked download tests ───────────────────────────

#[tokio::test]
async fn fs_download_queues_file_open_and_registers_download() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("download.bin");
    std::fs::write(&path, b"hello download").expect("write test file");

    let mut payload = Vec::new();
    payload.extend_from_slice(&(DemonFilesystemCommand::Download as i32).to_le_bytes());
    payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
    let package = DemonPackage::new(DemonCommand::CommandFs, 42, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::FileOpen { request_id, file_id, file_size, file_path } = &callbacks[0]
    else {
        panic!("expected FileOpen, got: {callbacks:?}");
    };
    assert_eq!(*request_id, 42);
    assert_eq!(*file_size, 14);
    assert!(!file_path.is_empty());
    let _ = *file_id; // random value, just ensure the field exists

    assert_eq!(state.downloads.len(), 1);
    assert_eq!(state.downloads[0].total_size, 14);
    assert_eq!(state.downloads[0].state, DownloadTransferState::Running);
}

#[tokio::test]
async fn push_download_chunks_sends_data_and_close() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("chunked.bin");
    let data = vec![0xAB_u8; 100];
    std::fs::write(&path, &data).expect("write test file");

    let mut payload = Vec::new();
    payload.extend_from_slice(&(DemonFilesystemCommand::Download as i32).to_le_bytes());
    payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
    let package = DemonPackage::new(DemonCommand::CommandFs, 50, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");
    state.drain_callbacks(); // drain the FileOpen

    // Poll to push chunks.
    state.push_download_chunks();
    let callbacks = state.drain_callbacks();

    // With 100 bytes and a 512 KiB chunk size, should get one chunk + close.
    assert_eq!(callbacks.len(), 2);

    let PendingCallback::FileChunk { data: chunk, .. } = &callbacks[0] else {
        panic!("expected FileChunk, got: {:?}", callbacks[0]);
    };
    assert_eq!(chunk.len(), 100);
    assert!(chunk.iter().all(|b| *b == 0xAB));

    assert!(matches!(&callbacks[1], PendingCallback::FileClose { .. }));
    assert!(state.downloads.is_empty());
}

#[tokio::test]
async fn file_open_callback_encodes_beacon_output_command_id() {
    let callback = PendingCallback::FileOpen {
        request_id: 1,
        file_id: 0x1234,
        file_size: 4096,
        file_path: "/tmp/test.bin".to_owned(),
    };
    assert_eq!(callback.command_id(), u32::from(DemonCommand::BeaconOutput));

    let payload = callback.payload().expect("payload");
    let mut offset = 0;
    assert_eq!(read_u32(&payload, &mut offset), u32::from(DemonCallback::File));
    let inner_len = read_u32(&payload, &mut offset) as usize;
    assert_eq!(inner_len, 4 + 4 + "/tmp/test.bin".len());
    assert_eq!(read_u32(&payload, &mut offset), 0x1234);
    assert_eq!(read_u32(&payload, &mut offset), 4096);
    let path_bytes = &payload[offset..];
    assert_eq!(path_bytes, b"/tmp/test.bin");
}

#[tokio::test]
async fn file_chunk_callback_encodes_correctly() {
    let callback =
        PendingCallback::FileChunk { request_id: 2, file_id: 0xDEAD, data: vec![1, 2, 3, 4] };
    assert_eq!(callback.command_id(), u32::from(DemonCommand::BeaconOutput));

    let payload = callback.payload().expect("payload");
    let mut offset = 0;
    assert_eq!(read_u32(&payload, &mut offset), u32::from(DemonCallback::FileWrite));
    let inner_len = read_u32(&payload, &mut offset) as usize;
    assert_eq!(inner_len, 4 + 4); // file_id + data
    assert_eq!(read_u32(&payload, &mut offset), 0xDEAD);
    assert_eq!(&payload[offset..], &[1, 2, 3, 4]);
}

#[tokio::test]
async fn file_close_callback_encodes_correctly() {
    let callback = PendingCallback::FileClose { request_id: 3, file_id: 0xBEEF };
    assert_eq!(callback.command_id(), u32::from(DemonCommand::BeaconOutput));

    let payload = callback.payload().expect("payload");
    let mut offset = 0;
    assert_eq!(read_u32(&payload, &mut offset), u32::from(DemonCallback::FileClose));
    assert_eq!(read_u32(&payload, &mut offset), 4); // inner len
    assert_eq!(read_u32(&payload, &mut offset), 0xBEEF);
}

#[tokio::test]
async fn transfer_list_returns_active_downloads() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("list.bin");
    std::fs::write(&path, b"list test data").expect("write");

    let mut fs_payload = Vec::new();
    fs_payload.extend_from_slice(&(DemonFilesystemCommand::Download as i32).to_le_bytes());
    fs_payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
    let mut state = PhantomState::default();
    execute(
        &DemonPackage::new(DemonCommand::CommandFs, 1, fs_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("download");
    state.drain_callbacks();

    let file_id = state.downloads[0].file_id;

    // Send CommandTransfer List
    let mut transfer_payload = Vec::new();
    transfer_payload.extend_from_slice(&(DemonTransferCommand::List as i32).to_le_bytes());
    execute(
        &DemonPackage::new(DemonCommand::CommandTransfer, 10, transfer_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("transfer list");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Structured { command_id, request_id, payload }] = callbacks.as_slice()
    else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandTransfer));
    assert_eq!(*request_id, 10);

    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), u32::from(DemonTransferCommand::List));
    // One download entry: file_id + read_size + state
    assert_eq!(read_u32(payload, &mut offset), file_id);
    assert_eq!(read_u32(payload, &mut offset), 0); // read_size = 0 (not started)
    assert_eq!(read_u32(payload, &mut offset), DownloadTransferState::Running as u32);
}

#[tokio::test]
async fn transfer_stop_pauses_download() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("stop.bin");
    std::fs::write(&path, vec![0u8; 1024 * 1024]).expect("write");

    let mut fs_payload = Vec::new();
    fs_payload.extend_from_slice(&(DemonFilesystemCommand::Download as i32).to_le_bytes());
    fs_payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
    let mut state = PhantomState::default();
    execute(
        &DemonPackage::new(DemonCommand::CommandFs, 1, fs_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("download");
    state.drain_callbacks();

    let file_id = state.downloads[0].file_id;

    // Stop the download.
    let mut stop_payload = Vec::new();
    stop_payload.extend_from_slice(&(DemonTransferCommand::Stop as i32).to_le_bytes());
    stop_payload.extend_from_slice(&(file_id as i32).to_le_bytes());
    execute(
        &DemonPackage::new(DemonCommand::CommandTransfer, 20, stop_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("transfer stop");

    assert_eq!(state.downloads[0].state, DownloadTransferState::Stopped);

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Structured { payload, .. }] = callbacks.as_slice() else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), u32::from(DemonTransferCommand::Stop));
    assert_eq!(read_u32(payload, &mut offset), 1); // found = true
    assert_eq!(read_u32(payload, &mut offset), file_id);

    // Pushing chunks should NOT produce any data for a stopped download.
    state.push_download_chunks();
    let callbacks = state.drain_callbacks();
    assert!(callbacks.is_empty(), "stopped download should not produce chunks");
}

#[tokio::test]
async fn transfer_resume_restarts_download() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("resume.bin");
    std::fs::write(&path, b"resume data").expect("write");

    let mut fs_payload = Vec::new();
    fs_payload.extend_from_slice(&(DemonFilesystemCommand::Download as i32).to_le_bytes());
    fs_payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
    let mut state = PhantomState::default();
    execute(
        &DemonPackage::new(DemonCommand::CommandFs, 1, fs_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("download");
    state.drain_callbacks();

    let file_id = state.downloads[0].file_id;

    // Stop then resume.
    let mut stop_payload = Vec::new();
    stop_payload.extend_from_slice(&(DemonTransferCommand::Stop as i32).to_le_bytes());
    stop_payload.extend_from_slice(&(file_id as i32).to_le_bytes());
    execute(
        &DemonPackage::new(DemonCommand::CommandTransfer, 20, stop_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("stop");
    state.drain_callbacks();

    let mut resume_payload = Vec::new();
    resume_payload.extend_from_slice(&(DemonTransferCommand::Resume as i32).to_le_bytes());
    resume_payload.extend_from_slice(&(file_id as i32).to_le_bytes());
    execute(
        &DemonPackage::new(DemonCommand::CommandTransfer, 21, resume_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("resume");

    assert_eq!(state.downloads[0].state, DownloadTransferState::Running);
    state.drain_callbacks();

    // After resume, pushing chunks should produce data again.
    state.push_download_chunks();
    let callbacks = state.drain_callbacks();
    assert!(
        callbacks.iter().any(|c| matches!(c, PendingCallback::FileChunk { .. })),
        "resumed download should produce chunks"
    );
}

#[tokio::test]
async fn transfer_remove_marks_download_for_removal() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("remove.bin");
    std::fs::write(&path, vec![0u8; 1024 * 1024]).expect("write");

    let mut fs_payload = Vec::new();
    fs_payload.extend_from_slice(&(DemonFilesystemCommand::Download as i32).to_le_bytes());
    fs_payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
    let mut state = PhantomState::default();
    execute(
        &DemonPackage::new(DemonCommand::CommandFs, 1, fs_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("download");
    state.drain_callbacks();

    let file_id = state.downloads[0].file_id;

    // Remove the download.
    let mut remove_payload = Vec::new();
    remove_payload.extend_from_slice(&(DemonTransferCommand::Remove as i32).to_le_bytes());
    remove_payload.extend_from_slice(&(file_id as i32).to_le_bytes());
    execute(
        &DemonPackage::new(DemonCommand::CommandTransfer, 30, remove_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("transfer remove");

    // Should produce two callbacks: the action response and the close notification.
    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 2);

    // Push should clean it up.
    state.push_download_chunks();
    let close_callbacks = state.drain_callbacks();
    assert!(
        close_callbacks.iter().any(|c| matches!(c, PendingCallback::FileClose { .. })),
        "removed download should emit FileClose on next push"
    );
    assert!(state.downloads.is_empty());
}

#[tokio::test]
async fn transfer_stop_nonexistent_returns_not_found() {
    let mut state = PhantomState::default();
    let mut stop_payload = Vec::new();
    stop_payload.extend_from_slice(&(DemonTransferCommand::Stop as i32).to_le_bytes());
    stop_payload.extend_from_slice(&(0xDEAD_BEEF_u32 as i32).to_le_bytes());
    execute(
        &DemonPackage::new(DemonCommand::CommandTransfer, 40, stop_payload),
        &mut PhantomConfig::default(),
        &mut state,
    )
    .await
    .expect("transfer stop nonexistent");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Structured { payload, .. }] = callbacks.as_slice() else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), u32::from(DemonTransferCommand::Stop));
    assert_eq!(read_u32(payload, &mut offset), 0); // found = false
}

#[tokio::test]
async fn cat_still_returns_full_file_as_structured_callback() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("cat.txt");
    std::fs::write(&path, b"cat content").expect("write");

    let mut payload = Vec::new();
    payload.extend_from_slice(&(DemonFilesystemCommand::Cat as i32).to_le_bytes());
    payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
    let package = DemonPackage::new(DemonCommand::CommandFs, 55, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Structured { command_id, .. }] = callbacks.as_slice() else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandFs));
    // Cat should not create tracked downloads.
    assert!(state.downloads.is_empty());
}

#[tokio::test]
async fn cat_truncates_large_file_and_appends_note() {
    use super::super::CAT_SIZE_LIMIT;

    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("large.bin");
    // Write a file that exceeds the cap by one byte.
    let file_size = CAT_SIZE_LIMIT + 1;
    {
        use std::io::Write as _;
        let mut f = std::fs::File::create(&path).expect("create");
        // Write in 4 KiB chunks to avoid a single huge allocation.
        let chunk = vec![0u8; 4096];
        let mut remaining = file_size;
        while remaining >= 4096 {
            f.write_all(&chunk).expect("write chunk");
            remaining -= 4096;
        }
        if remaining > 0 {
            f.write_all(&chunk[..remaining as usize]).expect("write tail");
        }
    }

    let mut payload = Vec::new();
    payload.extend_from_slice(&(DemonFilesystemCommand::Cat as i32).to_le_bytes());
    payload.extend_from_slice(&utf16_payload(path.to_string_lossy().as_ref()));
    let package = DemonPackage::new(DemonCommand::CommandFs, 99, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Structured { payload: encoded, .. }] = callbacks.as_slice() else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    // The encoded payload must contain the truncation note.
    let note = format!(
        "\n[truncated: file is {} bytes, only first {} bytes shown]",
        file_size, CAT_SIZE_LIMIT
    );
    let note_bytes = note.as_bytes();
    let found = encoded.windows(note_bytes.len()).any(|w| w == note_bytes);
    assert!(found, "truncation note not found in encoded cat response");
}
