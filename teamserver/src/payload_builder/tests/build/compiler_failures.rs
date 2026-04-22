use super::*;

#[tokio::test]
async fn build_payload_compiler_exits_nonzero_returns_command_failed()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
    let gcc_fail = "#!/bin/sh\necho 'stub compiler error' >&2\nexit 1\n";
    let (service, listener, request) = setup_build_fixture(&temp, nasm_ok, gcc_fail)?;

    let error = service
        .build_payload(&listener, &request, None, |_| {})
        .await
        .expect_err("a compiler that exits non-zero must produce an error");

    assert!(
        matches!(error, PayloadBuildError::CommandFailed { .. }),
        "expected CommandFailed, got {error:?}"
    );
    Ok(())
}

#[tokio::test]
async fn build_payload_assembler_exits_nonzero_returns_command_failed()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let nasm_fail = "#!/bin/sh\necho 'stub assembler error' >&2\nexit 1\n";
    let gcc_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'payload' > \"$1\"; break; fi; shift; done\n";
    let (service, listener, request) = setup_build_fixture(&temp, nasm_fail, gcc_ok)?;

    let error = service
        .build_payload(&listener, &request, None, |_| {})
        .await
        .expect_err("an assembler that exits non-zero must produce an error");

    assert!(
        matches!(error, PayloadBuildError::CommandFailed { .. }),
        "expected CommandFailed, got {error:?}"
    );
    Ok(())
}

#[tokio::test]
async fn build_payload_compiler_failure_populates_diagnostics()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
    let gcc_fail = "#!/bin/sh\necho \"src/Demon.c:42:8: error: 'foo' undeclared\" >&2\nexit 1\n";
    let (service, listener, request) = setup_build_fixture(&temp, nasm_ok, gcc_fail)?;

    let error = service
        .build_payload(&listener, &request, None, |_| {})
        .await
        .expect_err("compiler failure must yield an error");

    match error {
        PayloadBuildError::CommandFailed { ref diagnostics, .. } => {
            assert_eq!(diagnostics.len(), 1, "one GCC diagnostic should be parsed");
            let d = &diagnostics[0];
            assert_eq!(d.filename, "src/Demon.c");
            assert_eq!(d.line, 42);
            assert_eq!(d.column, Some(8));
            assert_eq!(d.severity, "error");
            assert!(d.message.contains("'foo' undeclared"));
        }
        other => panic!("expected CommandFailed, got {other:?}"),
    }
    Ok(())
}
