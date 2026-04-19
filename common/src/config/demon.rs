//! Demon block from the YAOTL profile (agent defaults, HKDF secrets, injection).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// One entry in the `InitSecrets` list — a versioned HKDF server secret.
///
/// Each entry pairs a 1-byte `Version` identifier with the actual `Secret`
/// string.  The version byte is sent by compatible agents (Specter / Archon)
/// in the `DEMON_INIT` envelope so the teamserver can look up the matching
/// secret and perform the correct HKDF derivation.
///
/// # Notes
///
/// Legacy Demon agents (C/ASM, frozen) do not emit a version byte and cannot
/// use versioned secrets.  Leave `InitSecrets` empty (or use the deprecated
/// single-field `InitSecret`) for pure-Demon deployments.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct VersionedInitSecret {
    /// 1-byte identifier sent by the agent in the `DEMON_INIT` envelope.
    #[serde(rename = "Version")]
    pub version: u8,
    /// Shared HKDF salt — must be at least 16 bytes (128 bits).
    ///
    /// Wrapped in [`Zeroizing`] so the secret material is overwritten in heap
    /// memory when the value is dropped.
    #[serde(
        rename = "Secret",
        deserialize_with = "crate::config::serde_helpers::deserialize_zeroizing_string"
    )]
    pub secret: Zeroizing<String>,
}

impl fmt::Debug for VersionedInitSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VersionedInitSecret")
            .field("version", &self.version)
            .field("secret", &"[redacted]")
            .finish()
    }
}

/// Demon build-time defaults and injection settings.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct DemonConfig {
    /// Beacon sleep interval.
    #[serde(rename = "Sleep", default)]
    pub sleep: Option<u64>,
    /// Beacon jitter percentage.
    #[serde(rename = "Jitter", default)]
    pub jitter: Option<u8>,
    /// Enable indirect syscall dispatch.
    #[serde(rename = "IndirectSyscall", default)]
    pub indirect_syscall: bool,
    /// Enable stack duplication.
    #[serde(rename = "StackDuplication", default)]
    pub stack_duplication: bool,
    /// Sleep obfuscation technique name.
    #[serde(rename = "SleepTechnique", default)]
    pub sleep_technique: Option<String>,
    /// Proxy loading mode.
    #[serde(rename = "ProxyLoading", default)]
    pub proxy_loading: Option<String>,
    /// AMSI/ETW patching mode.
    /// Accepts canonical ARC-01 values: "patch" | "hwbp" | "none".
    /// Legacy GUI values "Memory" and "Hardware breakpoints" are also accepted.
    /// Profile key: `AmsiEtw` (ARC-01 canonical) or `AmsiEtwPatching` (legacy).
    #[serde(rename = "AmsiEtwPatching", alias = "AmsiEtw", default)]
    pub amsi_etw_patching: Option<String>,
    /// Process injection defaults.
    #[serde(rename = "Injection", default)]
    pub injection: Option<ProcessInjectionConfig>,
    /// Named pipe used for .NET output transport.
    #[serde(rename = "DotNetNamePipe", default)]
    pub dotnet_name_pipe: Option<String>,
    /// PE/loader binary customization.
    #[serde(rename = "Binary", default)]
    pub binary: Option<BinaryConfig>,
    /// Optional shared secret for HKDF-based session key derivation (deprecated).
    ///
    /// **Deprecated in favour of `InitSecrets`.**  Use `InitSecrets` when you
    /// need zero-downtime secret rotation; this single-secret field cannot be
    /// rotated without simultaneously recompiling all agents.
    ///
    /// When set, the teamserver derives session keys via HKDF-SHA256 over
    /// agent-supplied key material and this secret, rather than using the raw
    /// agent keys directly.  No version byte is emitted by agents using this
    /// path — it is the legacy unversioned mode.  Compatible agents (Specter /
    /// Archon) must embed the same secret and perform the matching derivation.
    /// Legacy Demon agents do not support HKDF at all.
    ///
    /// Setting both `InitSecret` and `InitSecrets` is an error.
    ///
    /// Wrapped in [`Zeroizing`] so the secret material is overwritten in heap
    /// memory when the value is dropped.
    #[serde(
        rename = "InitSecret",
        default,
        deserialize_with = "crate::config::serde_helpers::deserialize_optional_zeroizing_string"
    )]
    pub init_secret: Option<Zeroizing<String>>,
    /// Versioned HKDF secrets for zero-downtime rotation.
    ///
    /// Each entry pairs a 1-byte `Version` with a `Secret` string.  Agents
    /// compiled with `InitSecrets` support send the version byte in the
    /// `DEMON_INIT` envelope; the teamserver looks up the matching entry and
    /// uses its secret for HKDF-SHA256 session key derivation.
    ///
    /// Rotation procedure:
    /// 1. Add the new version to this list.
    /// 2. Compile new agents with the new version.
    /// 3. Wait for all old agents to retire.
    /// 4. Remove the old version from this list.
    ///
    /// Setting both `InitSecret` and `InitSecrets` is an error.
    ///
    /// # Notes
    ///
    /// Legacy Demon agents (C/ASM, frozen) cannot emit a version byte and are
    /// incompatible with this field.  Document this as a Demon limitation.
    #[serde(rename = "InitSecrets", default)]
    pub init_secrets: Vec<VersionedInitSecret>,
    /// Whether to trust `X-Forwarded-For`.
    #[serde(rename = "TrustXForwardedFor", default)]
    pub trust_x_forwarded_for: bool,
    /// Explicit redirector peers or networks allowed to supply forwarded client IP headers.
    #[serde(
        rename = "TrustedProxyPeers",
        default,
        deserialize_with = "crate::config::serde_helpers::deserialize_one_or_many"
    )]
    pub trusted_proxy_peers: Vec<String>,
    /// Enable heap encryption during sleep (ARC-04).
    ///
    /// When `true` (the default), the Archon agent encrypts all agent-owned
    /// heap allocations before entering the sleep obfuscation routine and
    /// decrypts them on wake.  This prevents memory scanners from finding
    /// cleartext strings or structures while the agent is idle.
    ///
    /// HCL profile key: `HeapEnc` (boolean, default `true`).
    #[serde(rename = "HeapEnc", default = "crate::config::serde_helpers::default_true")]
    pub heap_enc: bool,
    /// Opt in to accepting legacy-CTR Demon/Archon sessions.
    ///
    /// Legacy CTR mode resets the AES-CTR keystream to block offset 0 for every packet,
    /// creating a two-time-pad vulnerability: any passive observer who captures two
    /// ciphertexts `C1` and `C2` can compute `C1 ⊕ C2 = P1 ⊕ P2` and — combined with
    /// knowledge of the public Demon protocol structure — recover both plaintexts.
    ///
    /// When `false` (the default), the teamserver **rejects** any `DEMON_INIT` that does
    /// not set the `INIT_EXT_MONOTONIC_CTR` extension flag.  Set to `true` only when you
    /// need to support unmodified Havoc Demon or Archon builds that do not negotiate
    /// monotonic CTR, and only in environments where traffic confidentiality is not a
    /// requirement.
    ///
    /// # Deprecation
    ///
    /// **This field is deprecated.  Support will be removed on 2027-01-01.**
    /// Migrate Demon/Archon agents to Specter (Windows) or Phantom (Linux) before that
    /// date.  See `docs/operator-security.md` for the migration procedure.
    /// The teamserver logs a `WARN`-level deprecation notice at startup when this flag
    /// is `true`.
    ///
    /// HCL profile key: `AllowLegacyCtr` (boolean, default `false`).
    #[serde(rename = "AllowLegacyCtr", default)]
    pub allow_legacy_ctr: bool,
    /// Job execution mode for post-exploitation commands (ARC-09).
    ///
    /// - `"thread"` (default): spawns a new OS thread per job (Demon-compatible).
    /// - `"threadpool"`: queues each job onto the NT thread pool, suppressing new
    ///   thread creation to defeat thread-count anomaly detectors.
    ///
    /// HCL profile key: `JobExecution` (string, default `"thread"`).
    #[serde(
        rename = "JobExecution",
        default = "crate::config::serde_helpers::default_job_execution"
    )]
    pub job_execution: String,
    /// Optional victim DLL name for module-stomping injection (ARC-05).
    ///
    /// When set (e.g. `"WINMM.DLL"`), Archon searches the PEB
    /// `InLoadOrderModuleList` for this module (case-insensitive) and stomps it
    /// instead of auto-selecting.  When absent, Archon picks the first suitable
    /// already-mapped module automatically.
    ///
    /// HCL profile key: `StompDll` (string, default: auto-select).
    #[serde(rename = "StompDll", default)]
    pub stomp_dll: Option<String>,
}

impl fmt::Debug for DemonConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DemonConfig")
            .field("sleep", &self.sleep)
            .field("jitter", &self.jitter)
            .field("indirect_syscall", &self.indirect_syscall)
            .field("stack_duplication", &self.stack_duplication)
            .field("sleep_technique", &self.sleep_technique)
            .field("proxy_loading", &self.proxy_loading)
            .field("amsi_etw_patching", &self.amsi_etw_patching)
            .field("injection", &self.injection)
            .field("dotnet_name_pipe", &self.dotnet_name_pipe)
            .field("binary", &self.binary)
            .field("init_secret", &self.init_secret.as_ref().map(|_| "[redacted]"))
            .field(
                "init_secrets",
                &self.init_secrets.iter().map(|v| (v.version, "[redacted]")).collect::<Vec<_>>(),
            )
            .field("trust_x_forwarded_for", &self.trust_x_forwarded_for)
            .field("trusted_proxy_peers", &self.trusted_proxy_peers)
            .field("heap_enc", &self.heap_enc)
            .field("allow_legacy_ctr", &self.allow_legacy_ctr)
            .field("job_execution", &self.job_execution)
            .field("stomp_dll", &self.stomp_dll)
            .finish()
    }
}

/// Spawn-to process defaults for injection.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ProcessInjectionConfig {
    /// 64-bit spawn-to path.
    #[serde(rename = "Spawn64", default)]
    pub spawn64: Option<String>,
    /// 32-bit spawn-to path.
    #[serde(rename = "Spawn32", default)]
    pub spawn32: Option<String>,
}

/// Binary patching options for generated payloads.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct BinaryConfig {
    /// PE header overrides.
    #[serde(rename = "Header", default)]
    pub header: Option<HeaderConfig>,
    /// Replacement strings for x64 builds.
    #[serde(rename = "ReplaceStrings-x64", default)]
    pub replace_strings_x64: BTreeMap<String, String>,
    /// Replacement strings for x86 builds.
    #[serde(rename = "ReplaceStrings-x86", default)]
    pub replace_strings_x86: BTreeMap<String, String>,
}

/// PE header customization options.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct HeaderConfig {
    /// DOS header magic for x64 payloads.
    #[serde(rename = "MagicMz-x64", default)]
    pub magic_mz_x64: Option<String>,
    /// DOS header magic for x86 payloads.
    #[serde(rename = "MagicMz-x86", default)]
    pub magic_mz_x86: Option<String>,
    /// Forced compile timestamp.
    #[serde(rename = "CompileTime", default)]
    pub compile_time: Option<String>,
    /// Image size override for x64 payloads.
    #[serde(rename = "ImageSize-x64", default)]
    pub image_size_x64: Option<u32>,
    /// Image size override for x86 payloads.
    #[serde(rename = "ImageSize-x86", default)]
    pub image_size_x86: Option<u32>,
}
