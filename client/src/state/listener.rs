//! Listener management and payload generation dialog state.

use std::collections::BTreeMap;

use red_cell_common::operator::ListenerInfo;
use zeroize::Zeroizing;

// ── Listener dialog types ─────────────────────────────────────────────────────

/// Listener protocol selection in the Create/Edit dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListenerProtocol {
    Http,
    Https,
    Smb,
    External,
}

impl ListenerProtocol {
    pub(crate) const ALL: [Self; 4] = [Self::Http, Self::Https, Self::Smb, Self::External];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Http => "Http",
            Self::Https => "Https",
            Self::Smb => "Smb",
            Self::External => "External",
        }
    }
}

/// Whether we are creating a new listener or editing an existing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListenerDialogMode {
    Create,
    Edit,
}

/// State for the Create/Edit Listener dialog window.
#[derive(Debug, Clone)]
pub(crate) struct ListenerDialogState {
    pub(crate) mode: ListenerDialogMode,
    pub(crate) name: String,
    pub(crate) protocol: ListenerProtocol,
    // HTTP/HTTPS fields
    pub(crate) host: String,
    pub(crate) port: String,
    pub(crate) user_agent: String,
    pub(crate) headers: String,
    pub(crate) uris: String,
    pub(crate) host_header: String,
    pub(crate) proxy_enabled: bool,
    pub(crate) proxy_type: String,
    pub(crate) proxy_host: String,
    pub(crate) proxy_port: String,
    pub(crate) proxy_username: String,
    pub(crate) proxy_password: Zeroizing<String>,
    // SMB fields
    pub(crate) pipe_name: String,
    // External fields
    pub(crate) endpoint: String,
}

impl ListenerDialogState {
    pub(crate) fn new_create() -> Self {
        Self {
            mode: ListenerDialogMode::Create,
            name: String::new(),
            protocol: ListenerProtocol::Http,
            host: String::new(),
            port: String::new(),
            user_agent: String::new(),
            headers: String::new(),
            uris: String::new(),
            host_header: String::new(),
            proxy_enabled: false,
            proxy_type: "http".to_owned(),
            proxy_host: String::new(),
            proxy_port: String::new(),
            proxy_username: String::new(),
            proxy_password: Zeroizing::new(String::new()),
            pipe_name: String::new(),
            endpoint: String::new(),
        }
    }

    pub(crate) fn new_edit(name: &str, protocol: &str, info: &ListenerInfo) -> Self {
        let protocol_enum = match protocol {
            "Https" => ListenerProtocol::Https,
            "Smb" => ListenerProtocol::Smb,
            "External" => ListenerProtocol::External,
            _ => ListenerProtocol::Http,
        };
        Self {
            mode: ListenerDialogMode::Edit,
            name: name.to_owned(),
            protocol: protocol_enum,
            host: info.host_bind.clone().unwrap_or_default(),
            port: info.port_bind.clone().unwrap_or_default(),
            user_agent: info.user_agent.clone().unwrap_or_default(),
            headers: info.headers.clone().unwrap_or_default(),
            uris: info.uris.clone().unwrap_or_default(),
            host_header: info
                .extra
                .get("HostHeader")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned(),
            proxy_enabled: info.proxy_enabled.as_deref() == Some("true"),
            proxy_type: info.proxy_type.clone().unwrap_or_else(|| "http".to_owned()),
            proxy_host: info.proxy_host.clone().unwrap_or_default(),
            proxy_port: info.proxy_port.clone().unwrap_or_default(),
            proxy_username: info.proxy_username.clone().unwrap_or_default(),
            proxy_password: Zeroizing::new(info.proxy_password.clone().unwrap_or_default()),
            pipe_name: info
                .extra
                .get("PipeName")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned(),
            endpoint: info
                .extra
                .get("Endpoint")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned(),
        }
    }

    /// Build the `ListenerInfo` payload for the WebSocket message.
    pub(crate) fn to_listener_info(&self) -> ListenerInfo {
        let protocol_str = self.protocol.label().to_owned();
        let secure = matches!(self.protocol, ListenerProtocol::Https);
        let mut extra = BTreeMap::new();

        match self.protocol {
            ListenerProtocol::Http | ListenerProtocol::Https => {
                if !self.host_header.is_empty() {
                    extra.insert(
                        "HostHeader".to_owned(),
                        serde_json::Value::String(self.host_header.clone()),
                    );
                }
                ListenerInfo {
                    name: Some(self.name.clone()),
                    protocol: Some(protocol_str),
                    status: Some("Online".to_owned()),
                    host_bind: Some(self.host.clone()),
                    port_bind: Some(self.port.clone()),
                    user_agent: if self.user_agent.is_empty() {
                        None
                    } else {
                        Some(self.user_agent.clone())
                    },
                    headers: if self.headers.is_empty() {
                        None
                    } else {
                        Some(self.headers.clone())
                    },
                    uris: if self.uris.is_empty() { None } else { Some(self.uris.clone()) },
                    secure: Some(secure.to_string()),
                    proxy_enabled: Some(self.proxy_enabled.to_string()),
                    proxy_type: if self.proxy_enabled {
                        Some(self.proxy_type.clone())
                    } else {
                        None
                    },
                    proxy_host: if self.proxy_enabled {
                        Some(self.proxy_host.clone())
                    } else {
                        None
                    },
                    proxy_port: if self.proxy_enabled {
                        Some(self.proxy_port.clone())
                    } else {
                        None
                    },
                    proxy_username: if self.proxy_enabled {
                        Some(self.proxy_username.clone())
                    } else {
                        None
                    },
                    proxy_password: if self.proxy_enabled {
                        Some((*self.proxy_password).clone())
                    } else {
                        None
                    },
                    extra,
                    ..ListenerInfo::default()
                }
            }
            ListenerProtocol::Smb => {
                extra.insert(
                    "PipeName".to_owned(),
                    serde_json::Value::String(self.pipe_name.clone()),
                );
                ListenerInfo {
                    name: Some(self.name.clone()),
                    protocol: Some(protocol_str),
                    status: Some("Online".to_owned()),
                    extra,
                    ..ListenerInfo::default()
                }
            }
            ListenerProtocol::External => {
                extra.insert(
                    "Endpoint".to_owned(),
                    serde_json::Value::String(self.endpoint.clone()),
                );
                ListenerInfo {
                    name: Some(self.name.clone()),
                    protocol: Some(protocol_str),
                    status: Some("Online".to_owned()),
                    extra,
                    ..ListenerInfo::default()
                }
            }
        }
    }
}

// ── Payload dialog types ──────────────────────────────────────────────────────

/// Architecture selection for payload generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PayloadArch {
    X64,
    X86,
}

impl PayloadArch {
    pub(crate) const ALL: [Self; 2] = [Self::X64, Self::X86];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::X64 => "x64",
            Self::X86 => "x86",
        }
    }
}

/// Output format for payload generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum PayloadFormat {
    WindowsExe,
    WindowsServiceExe,
    WindowsDll,
    WindowsReflectiveDll,
    WindowsShellcode,
}

impl PayloadFormat {
    pub(crate) const ALL: [Self; 5] = [
        Self::WindowsExe,
        Self::WindowsServiceExe,
        Self::WindowsDll,
        Self::WindowsReflectiveDll,
        Self::WindowsShellcode,
    ];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::WindowsExe => "Windows Exe",
            Self::WindowsServiceExe => "Windows Service Exe",
            Self::WindowsDll => "Windows Dll",
            Self::WindowsReflectiveDll => "Windows Reflective Dll",
            Self::WindowsShellcode => "Windows Shellcode",
        }
    }
}

/// Sleep obfuscation technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SleepTechnique {
    WaitForSingleObjectEx,
    Ekko,
    Zilean,
    None,
}

impl SleepTechnique {
    pub(crate) const ALL: [Self; 4] =
        [Self::WaitForSingleObjectEx, Self::Ekko, Self::Zilean, Self::None];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::WaitForSingleObjectEx => "WaitForSingleObjectEx",
            Self::Ekko => "Ekko",
            Self::Zilean => "Zilean",
            Self::None => "None",
        }
    }
}

/// Allocation method for injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AllocMethod {
    NativeSyscall,
    Win32,
}

impl AllocMethod {
    pub(crate) const ALL: [Self; 2] = [Self::NativeSyscall, Self::Win32];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::NativeSyscall => "Native/Syscall",
            Self::Win32 => "Win32",
        }
    }
}

/// Execute method for injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecuteMethod {
    NativeSyscall,
    Win32,
}

impl ExecuteMethod {
    pub(crate) const ALL: [Self; 2] = [Self::NativeSyscall, Self::Win32];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::NativeSyscall => "Native/Syscall",
            Self::Win32 => "Win32",
        }
    }
}

/// State for the Payload generation dialog (Attack > Payload).
#[derive(Debug, Clone)]
pub(crate) struct PayloadDialogState {
    pub(crate) agent_type: String,
    pub(crate) listener: String,
    pub(crate) arch: PayloadArch,
    pub(crate) format: PayloadFormat,
    // Config
    pub(crate) sleep: String,
    pub(crate) jitter: String,
    pub(crate) indirect_syscall: bool,
    pub(crate) sleep_technique: SleepTechnique,
    // Injection
    pub(crate) alloc: AllocMethod,
    pub(crate) execute: ExecuteMethod,
    pub(crate) spawn64: String,
    pub(crate) spawn32: String,
    /// Whether a build request is currently in flight.
    pub(crate) building: bool,
}

impl PayloadDialogState {
    pub(crate) fn new() -> Self {
        Self {
            agent_type: "Demon".to_owned(),
            listener: String::new(),
            arch: PayloadArch::X64,
            format: PayloadFormat::WindowsExe,
            sleep: "2".to_owned(),
            jitter: "20".to_owned(),
            indirect_syscall: true,
            sleep_technique: SleepTechnique::WaitForSingleObjectEx,
            alloc: AllocMethod::NativeSyscall,
            execute: ExecuteMethod::NativeSyscall,
            spawn64: r"C:\Windows\System32\notepad.exe".to_owned(),
            spawn32: r"C:\Windows\SysWOW64\notepad.exe".to_owned(),
            building: false,
        }
    }

    /// Serialize the config fields into the JSON document expected by the
    /// teamserver's `BuildPayloadRequest.Config` field.
    pub(crate) fn config_json(&self) -> String {
        let config = serde_json::json!({
            "Sleep": self.sleep,
            "Jitter": self.jitter,
            "IndirectSyscall": self.indirect_syscall,
            "SleepTechnique": self.sleep_technique.label(),
            "Alloc": self.alloc.label(),
            "Execute": self.execute.label(),
            "Spawn64": self.spawn64,
            "Spawn32": self.spawn32,
        });
        config.to_string()
    }
}
