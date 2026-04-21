use super::super::formats::{Architecture, OutputFormat};

/// Return the default compiler flags for the given output format.
pub(in super::super) fn default_compiler_flags(format: OutputFormat) -> Vec<&'static str> {
    let mut flags = vec![
        "-Os",
        "-fno-asynchronous-unwind-tables",
        "-masm=intel",
        "-fno-ident",
        "-fpack-struct=8",
        "-falign-functions=1",
        "-s",
        "-ffunction-sections",
        "-fdata-sections",
        "-falign-jumps=1",
        "-w",
        "-falign-labels=1",
        "-fPIC",
    ];

    if format == OutputFormat::ServiceExe {
        flags.push("-mwindows");
        flags.push("-ladvapi32");
    } else {
        flags.push("-nostdlib");
        flags.push("-mwindows");
    }

    flags.push("-Wl,-s,--no-seh,--enable-stdcall-fixup,--gc-sections");
    flags
}

/// Return the architecture- and format-specific main source and entry-point
/// arguments for the compiler invocation.
pub(in super::super) fn main_args(
    architecture: Architecture,
    format: OutputFormat,
) -> Vec<&'static str> {
    match format {
        OutputFormat::Exe => vec![
            "-D",
            "MAIN_THREADED",
            "-e",
            if architecture == Architecture::X64 { "WinMain" } else { "_WinMain" },
            "src/main/MainExe.c",
        ],
        OutputFormat::ServiceExe => vec![
            "-D",
            "MAIN_THREADED",
            "-D",
            "SVC_EXE",
            "-lntdll",
            "-e",
            if architecture == Architecture::X64 { "WinMain" } else { "_WinMain" },
            "src/main/MainSvc.c",
        ],
        OutputFormat::Dll | OutputFormat::ReflectiveDll => vec![
            "-shared",
            "-e",
            if architecture == Architecture::X64 { "DllMain" } else { "_DllMain" },
            "src/main/MainDll.c",
        ],
        // These formats never reach compile_portable_executable:
        // Shellcode and RawShellcode compile a DLL then prepend a loader binary,
        // StagedShellcode is compiled by compile_stager via its own code path.
        OutputFormat::Shellcode | OutputFormat::RawShellcode | OutputFormat::StagedShellcode => {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_args_exe_includes_main_threaded_and_entry_point() {
        let args = main_args(Architecture::X64, OutputFormat::Exe);
        assert!(args.contains(&"MAIN_THREADED"));
        assert!(args.contains(&"WinMain"));
        assert!(args.contains(&"src/main/MainExe.c"));
    }

    #[test]
    fn main_args_exe_x86_uses_underscore_prefix() {
        let args = main_args(Architecture::X86, OutputFormat::Exe);
        assert!(args.contains(&"_WinMain"));
    }

    #[test]
    fn main_args_service_exe_includes_svc_flag() {
        let args = main_args(Architecture::X64, OutputFormat::ServiceExe);
        assert!(args.contains(&"SVC_EXE"));
        assert!(args.contains(&"src/main/MainSvc.c"));
    }

    #[test]
    fn main_args_dll_uses_shared_and_dllmain() {
        let args = main_args(Architecture::X64, OutputFormat::Dll);
        assert!(args.contains(&"-shared"));
        assert!(args.contains(&"DllMain"));
        assert!(args.contains(&"src/main/MainDll.c"));
    }

    #[test]
    fn main_args_shellcode_returns_empty() {
        assert!(main_args(Architecture::X64, OutputFormat::Shellcode).is_empty());
        assert!(main_args(Architecture::X64, OutputFormat::RawShellcode).is_empty());
        assert!(main_args(Architecture::X64, OutputFormat::StagedShellcode).is_empty());
    }

    #[test]
    fn default_compiler_flags_always_includes_pic_and_optimization() {
        for format in [OutputFormat::Exe, OutputFormat::Dll, OutputFormat::ServiceExe] {
            let flags = default_compiler_flags(format);
            assert!(flags.contains(&"-Os"), "missing -Os for {format:?}");
            assert!(flags.contains(&"-fPIC"), "missing -fPIC for {format:?}");
            assert!(flags.contains(&"-mwindows"), "missing -mwindows for {format:?}");
        }
    }

    #[test]
    fn default_compiler_flags_service_exe_links_advapi32() {
        let flags = default_compiler_flags(OutputFormat::ServiceExe);
        assert!(flags.contains(&"-ladvapi32"));
        assert!(!flags.contains(&"-nostdlib"), "service exe should not use -nostdlib");
    }

    #[test]
    fn default_compiler_flags_non_service_uses_nostdlib() {
        for format in [OutputFormat::Exe, OutputFormat::Dll, OutputFormat::ReflectiveDll] {
            let flags = default_compiler_flags(format);
            assert!(flags.contains(&"-nostdlib"), "missing -nostdlib for {format:?}");
        }
    }
}
