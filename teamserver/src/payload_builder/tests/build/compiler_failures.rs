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
        PayloadBuildError::CommandFailed { ref diagnostics, ref stderr_tail, .. } => {
            assert_eq!(diagnostics.len(), 1, "one GCC diagnostic should be parsed");
            let d = &diagnostics[0];
            assert_eq!(d.filename, "src/Demon.c");
            assert_eq!(d.line, 42);
            assert_eq!(d.column, Some(8));
            assert_eq!(d.severity, "error");
            assert!(d.message.contains("'foo' undeclared"));
            assert!(
                stderr_tail.iter().any(|line| line.contains("'foo' undeclared")),
                "raw stderr tail should contain the parsed diagnostic line, got {stderr_tail:?}",
            );
        }
        other => panic!("expected CommandFailed, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn build_payload_compiler_failure_surfaces_unstructured_stderr()
-> Result<(), Box<dyn std::error::Error>> {
    // Real-world regression: the compiler prints a fatal error that does not
    // match the `filename:line:col: severity: message` pattern (e.g. linker
    // output, missing headers, or `cc1: error: ...`). Previously these lines
    // were silently dropped because `parse_compiler_diagnostic` rejected them,
    // leaving operators staring at `exit 1` with no context. The stderr_tail
    // field must capture these lines verbatim.
    let temp = TempDir::new()?;
    let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
    let gcc_fail = "#!/bin/sh\necho 'cc1: fatal error: include/windows.h: No such file or directory' >&2\necho 'compilation terminated.' >&2\nexit 1\n";
    let (service, listener, request) = setup_build_fixture(&temp, nasm_ok, gcc_fail)?;

    let error = service
        .build_payload(&listener, &request, None, |_| {})
        .await
        .expect_err("compiler failure must yield an error");

    match error {
        PayloadBuildError::CommandFailed { diagnostics, stderr_tail, .. } => {
            // Unstructured stderr lines do not produce structured diagnostics
            // under the current parser — that is the scenario this test guards.
            assert!(
                diagnostics.is_empty(),
                "unstructured stderr should not produce diagnostics, got {diagnostics:?}",
            );
            assert!(
                stderr_tail
                    .iter()
                    .any(|line| line.contains("windows.h: No such file or directory")),
                "stderr_tail must preserve raw fatal error, got {stderr_tail:?}",
            );
            assert!(
                stderr_tail.iter().any(|line| line.contains("compilation terminated")),
                "stderr_tail must include all stderr lines in order, got {stderr_tail:?}",
            );
        }
        other => panic!("expected CommandFailed, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn build_payload_stderr_tail_caps_line_count() -> Result<(), Box<dyn std::error::Error>> {
    // Guard against unbounded memory/audit-log growth: a verbose compiler run
    // can spew thousands of lines; we keep only the first MAX_STDERR_TAIL_LINES
    // because the first fatal error is what the operator needs to see.
    let temp = TempDir::new()?;
    let nasm_ok = "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf 'asm' > \"$1\"; break; fi; shift; done\n";
    // Emit 200 stderr lines, then exit 1. The tail must cap at 50.
    let gcc_fail =
        "#!/bin/sh\nfor i in $(seq 1 200); do echo \"noise line $i\" >&2; done\nexit 1\n";
    let (service, listener, request) = setup_build_fixture(&temp, nasm_ok, gcc_fail)?;

    let error = service
        .build_payload(&listener, &request, None, |_| {})
        .await
        .expect_err("compiler failure must yield an error");

    match error {
        PayloadBuildError::CommandFailed { stderr_tail, .. } => {
            assert_eq!(
                stderr_tail.len(),
                crate::payload_builder::MAX_STDERR_TAIL_LINES,
                "stderr_tail must be capped at MAX_STDERR_TAIL_LINES",
            );
            assert!(
                stderr_tail.first().is_some_and(|l| l.contains("noise line 1")),
                "first captured line should be the earliest stderr output",
            );
        }
        other => panic!("expected CommandFailed, got {other:?}"),
    }
    Ok(())
}
