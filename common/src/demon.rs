//! Havoc Demon binary protocol types and serializers.

use thiserror::Error;

/// Transport magic value used by Havoc Demon packets.
pub const DEMON_MAGIC_VALUE: u32 = 0xDEAD_BEEF;

/// Minimum number of bytes required to begin parsing a [`DemonEnvelope`].
///
/// A valid envelope must contain at least the 4-byte `Size` field before any
/// further decoding can proceed.  Buffers shorter than this value are rejected
/// by [`DemonEnvelope::from_bytes`] before any arithmetic is attempted.
pub const MIN_ENVELOPE_SIZE: usize = 4;

macro_rules! protocol_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($variant:ident = $value:expr,)+
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(u32)]
        $vis enum $name {
            $($variant = $value,)+
        }

        impl From<$name> for u32 {
            fn from(value: $name) -> Self {
                value as u32
            }
        }

        impl core::convert::TryFrom<u32> for $name {
            type Error = DemonProtocolError;

            fn try_from(value: u32) -> Result<Self, Self::Error> {
                match value {
                    $($value => Ok(Self::$variant),)+
                    _ => Err(DemonProtocolError::UnknownEnumValue {
                        kind: stringify!($name),
                        value,
                    }),
                }
            }
        }
    };
}

/// Errors returned while encoding or decoding Demon protocol values.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DemonProtocolError {
    /// The provided byte buffer does not contain enough data for the requested field.
    #[error("buffer too short while reading {context}: expected {expected} bytes, got {actual}")]
    BufferTooShort {
        /// Description of the field being decoded.
        context: &'static str,
        /// Minimum number of bytes needed.
        expected: usize,
        /// Actual remaining bytes.
        actual: usize,
    },
    /// The provided packet length exceeds what fits in the 32-bit wire format.
    #[error("length overflow while encoding {context}: {length} bytes")]
    LengthOverflow {
        /// Description of the field being encoded.
        context: &'static str,
        /// Length that could not fit in `u32`.
        length: usize,
    },
    /// The Demon transport magic value did not match the Havoc protocol constant.
    #[error("invalid Demon magic value: expected 0x{expected:08x}, got 0x{actual:08x}")]
    InvalidMagic {
        /// Expected magic value.
        expected: u32,
        /// Observed magic value.
        actual: u32,
    },
    /// The declared packet size did not match the provided byte buffer.
    #[error("invalid Demon packet size: declared {declared} bytes, actual {actual} bytes")]
    SizeMismatch {
        /// Declared size from the header.
        declared: u32,
        /// Actual size from the buffer.
        actual: usize,
    },
    /// An integer value did not map to a known Havoc enum discriminant.
    #[error("unknown {kind} value: {value}")]
    UnknownEnumValue {
        /// Protocol enum type.
        kind: &'static str,
        /// Unknown raw wire value.
        value: u32,
    },
}

protocol_enum! {
    /// Top-level Havoc Demon command identifiers.
    pub enum DemonCommand {
        CommandGetJob = 1,
        CommandNoJob = 10,
        CommandSleep = 11,
        CommandProcList = 12,
        CommandFs = 15,
        CommandInlineExecute = 20,
        CommandJob = 21,
        CommandInjectDll = 22,
        CommandInjectShellcode = 24,
        CommandSpawnDll = 26,
        CommandProcPpidSpoof = 27,
        CommandToken = 40,
        DemonInfo = 89,
        CommandOutput = 90,
        CommandError = 91,
        CommandExit = 92,
        CommandKillDate = 93,
        BeaconOutput = 94,
        DemonInit = 99,
        CommandCheckin = 100,
        CommandProc = 0x1010,
        CommandPsImport = 0x1011,
        CommandAssemblyInlineExecute = 0x2001,
        CommandAssemblyListVersions = 0x2003,
        CommandNet = 2100,
        CommandConfig = 2500,
        CommandScreenshot = 2510,
        CommandPivot = 2520,
        CommandTransfer = 2530,
        CommandSocket = 2540,
        CommandKerberos = 2550,
        CommandMemFile = 2560,
        CommandPackageDropped = 2570,
        CommandHarvest = 2580,
        CommandPersist = 3000,
    }
}

protocol_enum! {
    /// Demon callback identifiers emitted by object files and agent tasks.
    pub enum DemonCallback {
        Output = 0x00,
        File = 0x02,
        FileWrite = 0x08,
        FileClose = 0x09,
        ErrorMessage = 0x0d,
        OutputOem = 0x1e,
        OutputUtf8 = 0x20,
    }
}

protocol_enum! {
    /// Callback-specific error classes carried inside error callback payloads.
    pub enum DemonCallbackError {
        Win32 = 0x01,
        Coffee = 0x02,
        Token = 0x03,
    }
}

protocol_enum! {
    /// Configuration option identifiers used by the Demon implant.
    pub enum DemonConfigKey {
        ImplantSpfThreadStart = 3,
        ImplantVerbose = 4,
        ImplantSleepTechnique = 5,
        ImplantCoffeeThreaded = 6,
        ImplantCoffeeVeh = 7,
        MemoryAlloc = 101,
        MemoryExecute = 102,
        InjectTechnique = 150,
        InjectSpoofAddr = 151,
        InjectSpawn64 = 152,
        InjectSpawn32 = 153,
        KillDate = 154,
        WorkingHours = 155,
    }
}

protocol_enum! {
    /// Network discovery subcommands for `COMMAND_NET`.
    pub enum DemonNetCommand {
        Domain = 1,
        Logons = 2,
        Sessions = 3,
        Computer = 4,
        DcList = 5,
        Share = 6,
        LocalGroup = 7,
        Group = 8,
        Users = 9,
    }
}

protocol_enum! {
    /// Pivot subcommands for SMB pivots.
    pub enum DemonPivotCommand {
        List = 1,
        SmbConnect = 10,
        SmbDisconnect = 11,
        SmbCommand = 12,
    }
}

protocol_enum! {
    /// Informational event identifiers emitted by the Demon implant.
    pub enum DemonInfoClass {
        MemAlloc = 10,
        MemExec = 11,
        MemProtect = 12,
        ProcCreate = 21,
    }
}

protocol_enum! {
    /// Job management subcommands for `COMMAND_JOB`.
    pub enum DemonJobCommand {
        List = 1,
        Suspend = 2,
        Resume = 3,
        KillRemove = 4,
        Died = 5,
    }
}

protocol_enum! {
    /// Transfer subcommands for `COMMAND_TRANSFER`.
    pub enum DemonTransferCommand {
        List = 0,
        Stop = 1,
        Resume = 2,
        Remove = 3,
    }
}

protocol_enum! {
    /// Process management subcommands for `COMMAND_PROC`.
    pub enum DemonProcessCommand {
        Modules = 2,
        Grep = 3,
        Create = 4,
        Memory = 6,
        Kill = 7,
    }
}

protocol_enum! {
    /// Token manipulation subcommands for `COMMAND_TOKEN`.
    pub enum DemonTokenCommand {
        Impersonate = 1,
        Steal = 2,
        List = 3,
        PrivsGetOrList = 4,
        Make = 5,
        GetUid = 6,
        Revert = 7,
        Remove = 8,
        Clear = 9,
        FindTokens = 10,
    }
}

protocol_enum! {
    /// Filesystem subcommands for `COMMAND_FS`.
    pub enum DemonFilesystemCommand {
        Dir = 1,
        Download = 2,
        Upload = 3,
        Cd = 4,
        Remove = 5,
        Mkdir = 6,
        Copy = 7,
        Move = 8,
        GetPwd = 9,
        Cat = 10,
    }
}

protocol_enum! {
    /// Socket subcommands for `COMMAND_SOCKET`.
    pub enum DemonSocketCommand {
        ReversePortForwardAdd = 0x00,
        ReversePortForwardAddLocal = 0x01,
        ReversePortForwardList = 0x02,
        ReversePortForwardClear = 0x03,
        ReversePortForwardRemove = 0x04,
        SocksProxyAdd = 0x05,
        SocksProxyList = 0x06,
        SocksProxyRemove = 0x07,
        SocksProxyClear = 0x08,
        Open = 0x10,
        Read = 0x11,
        Write = 0x12,
        Close = 0x13,
        Connect = 0x14,
    }
}

protocol_enum! {
    /// Socket type identifiers used by reverse tunnel tasks.
    pub enum DemonSocketType {
        ReversePortForward = 0x1,
        ReverseProxy = 0x2,
        Client = 0x3,
    }
}

protocol_enum! {
    /// Socket error identifiers.
    pub enum DemonSocketError {
        AlreadyBound = 0x1,
    }
}

protocol_enum! {
    /// Kerberos subcommands for `COMMAND_KERBEROS`.
    pub enum DemonKerberosCommand {
        Luid = 0x0,
        Klist = 0x1,
        Purge = 0x2,
        Ptt = 0x3,
    }
}

protocol_enum! {
    /// CoffeeLdr execution flags.
    pub enum DemonCoffeeLdrFlag {
        NonThreaded = 0,
        Threaded = 1,
        Default = 2,
    }
}

protocol_enum! {
    /// Injection mode identifiers.
    pub enum DemonInjectWay {
        Spawn = 0,
        Inject = 1,
        Execute = 2,
    }
}

protocol_enum! {
    /// Remote thread creation strategies.
    pub enum DemonThreadMethod {
        Default = 0,
        CreateRemoteThread = 1,
        NtCreateThreadEx = 2,
        NtQueueApcThread = 3,
    }
}

protocol_enum! {
    /// Windows impersonation levels encoded in token tasks.
    pub enum DemonSecurityLevel {
        Anonymous = 0x0,
        Identification = 0x1,
        Impersonation = 0x2,
        Delegation = 0x3,
    }
}

protocol_enum! {
    /// Windows token type values.
    pub enum DemonTokenType {
        Primary = 1,
        Impersonation = 2,
    }
}

protocol_enum! {
    /// Injection error codes surfaced by process injection tasks.
    pub enum DemonInjectError {
        Success = 0,
        Failed = 1,
        InvalidParam = 2,
        ProcessArchMismatch = 3,
    }
}

protocol_enum! {
    /// Phantom-specific persistence method selectors.
    ///
    /// Interpreted only by the Phantom Linux agent; Demon/Archon return a
    /// not-supported error for `CommandPersist`.
    pub enum PhantomPersistMethod {
        Cron = 1,
        SystemdUser = 2,
        ShellRc = 3,
    }
}

protocol_enum! {
    /// Operation selector for `CommandPersist` payloads (install or remove).
    pub enum PhantomPersistOp {
        Install = 0,
        Remove = 1,
    }
}

/// Fixed-size Demon transport header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DemonHeader {
    /// Packet size excluding the size field itself.
    pub size: u32,
    /// Protocol magic value.
    pub magic: u32,
    /// Agent identifier.
    pub agent_id: u32,
}

impl DemonHeader {
    /// Serialized header length in bytes.
    pub const SERIALIZED_LEN: usize = 12;

    /// Construct a header for the provided payload length.
    pub fn new(agent_id: u32, payload_len: usize) -> Result<Self, DemonProtocolError> {
        let size = payload_len.checked_add(8).ok_or(DemonProtocolError::LengthOverflow {
            context: "Demon header payload",
            length: payload_len,
        })?;
        let size = u32::try_from(size).map_err(|_| DemonProtocolError::LengthOverflow {
            context: "Demon header payload",
            length: payload_len,
        })?;

        Ok(Self { size, magic: DEMON_MAGIC_VALUE, agent_id })
    }

    /// Serialize the header to its big-endian wire format.
    pub fn to_bytes(self) -> [u8; Self::SERIALIZED_LEN] {
        let mut bytes = [0_u8; Self::SERIALIZED_LEN];
        bytes[..4].copy_from_slice(&self.size.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.magic.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.agent_id.to_be_bytes());
        bytes
    }

    /// Parse a header from its big-endian wire format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DemonProtocolError> {
        if bytes.len() < Self::SERIALIZED_LEN {
            return Err(DemonProtocolError::BufferTooShort {
                context: "Demon header",
                expected: Self::SERIALIZED_LEN,
                actual: bytes.len(),
            });
        }

        let size = u32::from_be_bytes(bytes[0..4].try_into().map_err(|_| {
            DemonProtocolError::BufferTooShort {
                context: "Demon packet size",
                expected: 4,
                actual: bytes.len(),
            }
        })?);
        let magic = u32::from_be_bytes(bytes[4..8].try_into().map_err(|_| {
            DemonProtocolError::BufferTooShort {
                context: "Demon packet magic",
                expected: 4,
                actual: bytes.len().saturating_sub(4),
            }
        })?);
        if magic != DEMON_MAGIC_VALUE {
            return Err(DemonProtocolError::InvalidMagic {
                expected: DEMON_MAGIC_VALUE,
                actual: magic,
            });
        }

        let agent_id = u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| {
            DemonProtocolError::BufferTooShort {
                context: "Demon packet agent id",
                expected: 4,
                actual: bytes.len().saturating_sub(8),
            }
        })?);

        Ok(Self { size, magic, agent_id })
    }
}

/// Full transport packet consisting of a big-endian header and raw payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemonEnvelope {
    /// Fixed transport header.
    pub header: DemonHeader,
    /// Raw packet payload following the 12-byte header.
    pub payload: Vec<u8>,
}

impl DemonEnvelope {
    /// Create a transport packet for an agent and payload.
    pub fn new(agent_id: u32, payload: Vec<u8>) -> Result<Self, DemonProtocolError> {
        let header = DemonHeader::new(agent_id, payload.len())?;
        Ok(Self { header, payload })
    }

    /// Serialize the packet to the wire format used by the Demon transport.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(DemonHeader::SERIALIZED_LEN + self.payload.len());
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Parse a transport packet from the wire format used by the Demon transport.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DemonProtocolError> {
        if bytes.len() < MIN_ENVELOPE_SIZE {
            return Err(DemonProtocolError::BufferTooShort {
                context: "DemonEnvelope",
                expected: MIN_ENVELOPE_SIZE,
                actual: bytes.len(),
            });
        }
        let header = DemonHeader::from_bytes(bytes)?;
        let declared =
            usize::try_from(header.size).map_err(|_| DemonProtocolError::SizeMismatch {
                declared: header.size,
                actual: bytes.len().saturating_sub(4),
            })?;
        let actual = bytes.len().saturating_sub(4);
        if declared != actual {
            return Err(DemonProtocolError::SizeMismatch { declared: header.size, actual });
        }

        Ok(Self { header, payload: bytes[DemonHeader::SERIALIZED_LEN..].to_vec() })
    }
}

/// A single task or callback unit encoded inside a Demon message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemonPackage {
    /// Raw top-level command identifier.
    pub command_id: u32,
    /// Request identifier associated with the command.
    pub request_id: u32,
    /// Raw payload bytes for the command.
    pub payload: Vec<u8>,
}

impl DemonPackage {
    /// Construct a package for a typed command.
    pub fn new(command: DemonCommand, request_id: u32, payload: Vec<u8>) -> Self {
        Self { command_id: command.into(), request_id, payload }
    }

    /// Return the typed command identifier if the raw ID is known.
    pub fn command(&self) -> Result<DemonCommand, DemonProtocolError> {
        self.command_id.try_into()
    }

    /// Total encoded size of the package in bytes.
    pub fn encoded_len(&self) -> usize {
        12 + self.payload.len()
    }

    /// Validate that a payload length fits in the wire format's `u32` field.
    fn checked_payload_len(len: usize) -> Result<u32, DemonProtocolError> {
        u32::try_from(len).map_err(|_| DemonProtocolError::LengthOverflow {
            context: "Demon package payload",
            length: len,
        })
    }

    /// Serialize the package using Havoc's little-endian package format.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DemonProtocolError> {
        let payload_len = Self::checked_payload_len(self.payload.len())?;

        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(&self.command_id.to_le_bytes());
        bytes.extend_from_slice(&self.request_id.to_le_bytes());
        bytes.extend_from_slice(&payload_len.to_le_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    /// Parse a single package from bytes, requiring an exact-length buffer.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DemonProtocolError> {
        let (package, consumed) = Self::parse_from(bytes)?;
        if consumed != bytes.len() {
            return Err(DemonProtocolError::SizeMismatch {
                declared: u32::try_from(consumed).unwrap_or(u32::MAX),
                actual: bytes.len(),
            });
        }
        Ok(package)
    }

    fn parse_from(bytes: &[u8]) -> Result<(Self, usize), DemonProtocolError> {
        let mut offset = 0_usize;
        let command_id = read_u32_le(bytes, &mut offset, "Demon package command id")?;
        let request_id = read_u32_le(bytes, &mut offset, "Demon package request id")?;
        let payload_len_u32 = read_u32_le(bytes, &mut offset, "Demon package payload length")?;
        let payload_len =
            usize::try_from(payload_len_u32).map_err(|_| DemonProtocolError::BufferTooShort {
                context: "Demon package payload",
                expected: usize::MAX,
                actual: bytes.len().saturating_sub(offset),
            })?;
        let payload = read_vec(bytes, &mut offset, payload_len, "Demon package payload")?;

        Ok((Self { command_id, request_id, payload }, offset))
    }
}

/// Sequence of little-endian packages carried by a single Demon request or response body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DemonMessage {
    /// Packages encoded in transmission order.
    pub packages: Vec<DemonPackage>,
}

impl DemonMessage {
    /// Construct a message from pre-built packages.
    pub fn new(packages: Vec<DemonPackage>) -> Self {
        Self { packages }
    }

    /// Serialize the message to the Havoc package stream format.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DemonProtocolError> {
        let total_len = self.packages.iter().map(DemonPackage::encoded_len).sum();
        let mut bytes = Vec::with_capacity(total_len);
        for package in &self.packages {
            bytes.extend_from_slice(&package.to_bytes()?);
        }
        Ok(bytes)
    }

    /// Parse a package stream until the buffer is exhausted.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DemonProtocolError> {
        let mut offset = 0_usize;
        let mut packages = Vec::new();

        while offset < bytes.len() {
            let (package, consumed) = DemonPackage::parse_from(&bytes[offset..])?;
            packages.push(package);
            offset += consumed;
        }

        Ok(Self { packages })
    }
}

fn read_u32_le(
    bytes: &[u8],
    offset: &mut usize,
    context: &'static str,
) -> Result<u32, DemonProtocolError> {
    let remaining = bytes.len().saturating_sub(*offset);
    if remaining < 4 {
        return Err(DemonProtocolError::BufferTooShort { context, expected: 4, actual: remaining });
    }

    let value = u32::from_le_bytes(bytes[*offset..*offset + 4].try_into().map_err(|_| {
        DemonProtocolError::BufferTooShort { context, expected: 4, actual: remaining }
    })?);
    *offset += 4;
    Ok(value)
}

fn read_vec(
    bytes: &[u8],
    offset: &mut usize,
    len: usize,
    context: &'static str,
) -> Result<Vec<u8>, DemonProtocolError> {
    let remaining = bytes.len().saturating_sub(*offset);
    if remaining < len {
        return Err(DemonProtocolError::BufferTooShort {
            context,
            expected: len,
            actual: remaining,
        });
    }

    let value = bytes[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{
        DEMON_MAGIC_VALUE, DemonCallback, DemonCommand, DemonEnvelope, DemonHeader,
        DemonInjectError, DemonMessage, DemonPackage, DemonProtocolError, DemonSocketCommand,
        DemonSocketType, DemonTransferCommand, MIN_ENVELOPE_SIZE,
    };

    #[test]
    fn demon_header_round_trip_preserves_big_endian_wire_format() {
        let header = DemonHeader::new(0x1122_3344, 5).expect("header construction should succeed");
        let bytes = header.to_bytes();

        assert_eq!(
            bytes,
            [0x00, 0x00, 0x00, 0x0d, 0xde, 0xad, 0xbe, 0xef, 0x11, 0x22, 0x33, 0x44,]
        );

        let parsed = DemonHeader::from_bytes(&bytes).expect("header decoding should succeed");

        assert_eq!(parsed, header);
        assert_eq!(parsed.magic, DEMON_MAGIC_VALUE);
    }

    #[test]
    fn demon_envelope_round_trip_preserves_payload() {
        let envelope = DemonEnvelope::new(0xaabb_ccdd, vec![0x10, 0x20, 0x30])
            .expect("envelope construction should succeed");
        let bytes = envelope.to_bytes();

        let parsed = DemonEnvelope::from_bytes(&bytes).expect("envelope decoding should succeed");

        assert_eq!(parsed, envelope);
    }

    #[test]
    fn demon_package_round_trip_uses_little_endian_layout() {
        let package =
            DemonPackage::new(DemonCommand::CommandCheckin, 0x0102_0304, vec![0xaa, 0xbb, 0xcc]);
        let bytes = package.to_bytes().expect("package encoding should succeed");

        assert_eq!(
            bytes,
            [
                0x64, 0x00, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01, 0x03, 0x00, 0x00, 0x00, 0xaa, 0xbb,
                0xcc,
            ]
        );

        let parsed = DemonPackage::from_bytes(&bytes).expect("package decoding should succeed");

        assert_eq!(parsed, package);
        assert_eq!(
            parsed.command().expect("command id should be recognized"),
            DemonCommand::CommandCheckin
        );
    }

    #[test]
    fn demon_message_round_trip_preserves_multiple_packages() {
        let message = DemonMessage::new(vec![
            DemonPackage::new(DemonCommand::CommandGetJob, 1, Vec::new()),
            DemonPackage::new(DemonCommand::CommandSocket, 2, vec![0xde, 0xad, 0xbe, 0xef]),
        ]);

        let bytes = message.to_bytes().expect("message encoding should succeed");
        let parsed = DemonMessage::from_bytes(&bytes).expect("message decoding should succeed");

        assert_eq!(parsed, message);
    }

    #[test]
    fn demon_message_round_trip_preserves_empty_stream() {
        let message = DemonMessage::new(Vec::new());

        let bytes = message.to_bytes().expect("empty message should encode");
        let parsed = DemonMessage::from_bytes(&bytes).expect("empty message should decode");

        assert!(bytes.is_empty());
        assert_eq!(parsed, message);
    }

    #[test]
    fn demon_header_accepts_maximum_wire_payload_length() {
        let header = DemonHeader::new(0xface_cafe, u32::MAX as usize - 8)
            .expect("largest wire-representable payload should fit");

        assert_eq!(header.size, u32::MAX);
        assert_eq!(header.agent_id, 0xface_cafe);
    }

    #[test]
    fn demon_header_rejects_payload_length_overflow() {
        let error = DemonHeader::new(7, u32::MAX as usize - 7)
            .expect_err("payload larger than wire format must fail");

        assert_eq!(
            error,
            DemonProtocolError::LengthOverflow {
                context: "Demon header payload",
                length: u32::MAX as usize - 7,
            }
        );
    }

    #[test]
    fn demon_envelope_rejects_declared_size_mismatch() {
        let error = DemonEnvelope::from_bytes(&[
            0x00, 0x00, 0x00, 0x08, 0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 0x56, 0x78, 0xaa,
        ])
        .expect_err("mismatched transport size must fail");

        assert_eq!(error, DemonProtocolError::SizeMismatch { declared: 8, actual: 9 });
    }

    #[test]
    fn demon_package_round_trip_supports_empty_payload() {
        let package = DemonPackage::new(DemonCommand::CommandNoJob, 99, Vec::new());

        let bytes = package.to_bytes().expect("package should encode");
        let parsed = DemonPackage::from_bytes(&bytes).expect("package should decode");

        assert_eq!(bytes.len(), 12);
        assert_eq!(parsed, package);
    }

    #[test]
    fn demon_package_encoded_len_reports_header_size_for_empty_payload() {
        let package = DemonPackage::new(DemonCommand::CommandNoJob, 99, Vec::new());

        assert_eq!(package.encoded_len(), 12);
    }

    #[test]
    fn demon_package_encoded_len_matches_encoded_buffer_for_non_empty_payload() {
        let package =
            DemonPackage::new(DemonCommand::CommandCheckin, 0x1234_5678, vec![0xaa, 0xbb, 0xcc]);

        let bytes = package.to_bytes().expect("package should encode");

        assert_eq!(package.encoded_len(), bytes.len());
        assert_eq!(package.encoded_len(), 12 + package.payload.len());
    }

    #[test]
    fn demon_package_encoded_len_matches_large_payload_and_message_aggregation() {
        let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let package = DemonPackage::new(DemonCommand::CommandSocket, 0x0bad_f00d, payload.clone());
        let message = DemonMessage::new(vec![
            DemonPackage::new(DemonCommand::CommandGetJob, 7, Vec::new()),
            package.clone(),
        ]);

        let package_bytes = package.to_bytes().expect("package should encode");
        let message_bytes = message.to_bytes().expect("message should encode");
        let expected_message_len: usize =
            message.packages.iter().map(DemonPackage::encoded_len).sum();

        assert_eq!(package.encoded_len(), 12 + payload.len());
        assert_eq!(package.encoded_len(), package_bytes.len());
        assert_eq!(message_bytes.len(), expected_message_len);
    }

    #[test]
    fn demon_package_rejects_trailing_bytes() {
        let bytes =
            [0x5c, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 0x01, 0x00, 0x00, 0x00, 0xaa, 0xbb];

        let error = DemonPackage::from_bytes(&bytes).expect_err("trailing bytes must be rejected");

        assert_eq!(error, DemonProtocolError::SizeMismatch { declared: 13, actual: 14 });
    }

    #[test]
    fn demon_message_rejects_truncated_second_package() {
        let first = DemonPackage::new(DemonCommand::CommandNoJob, 1, Vec::new())
            .to_bytes()
            .expect("first package should encode");
        let second = [0x64, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xaa];
        let mut bytes = first;
        bytes.extend_from_slice(&second);

        let error =
            DemonMessage::from_bytes(&bytes).expect_err("truncated package stream must fail");

        assert_eq!(
            error,
            DemonProtocolError::BufferTooShort {
                context: "Demon package payload",
                expected: 2,
                actual: 1,
            }
        );
    }

    #[test]
    fn rejects_invalid_magic_value() {
        let bytes = [0x00, 0x00, 0x00, 0x08, 0xde, 0xad, 0xbe, 0xee, 0x00, 0x00, 0x00, 0x01];

        let error = DemonHeader::from_bytes(&bytes).expect_err("invalid magic must be rejected");

        assert_eq!(
            error,
            DemonProtocolError::InvalidMagic { expected: DEMON_MAGIC_VALUE, actual: 0xdead_beee }
        );
    }

    #[test]
    fn rejects_truncated_package_payload() {
        let bytes =
            [0x5a, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 0x04, 0x00, 0x00, 0x00, 0xaa, 0xbb];

        let error = DemonPackage::from_bytes(&bytes).expect_err("truncated payload must fail");

        assert_eq!(
            error,
            DemonProtocolError::BufferTooShort {
                context: "Demon package payload",
                expected: 4,
                actual: 2,
            }
        );
    }

    #[test]
    fn demon_header_rejects_buffer_shorter_than_header() {
        let error = DemonHeader::from_bytes(&[0u8; 4])
            .expect_err("buffer shorter than 12 bytes must be rejected");

        assert_eq!(
            error,
            DemonProtocolError::BufferTooShort { context: "Demon header", expected: 12, actual: 4 }
        );
    }

    #[test]
    fn demon_header_from_bytes_accepts_oversized_buffer() {
        let header = DemonHeader::new(0x1122_3344, 5).expect("header construction should succeed");
        let mut bytes = header.to_bytes().to_vec();
        // Append trailing garbage — from_bytes must still parse the header.
        bytes.extend_from_slice(&[0xFF; 32]);

        let parsed =
            DemonHeader::from_bytes(&bytes).expect("oversized buffer must still parse header");
        assert_eq!(parsed, header);
    }

    #[test]
    fn demon_envelope_rejects_buffer_shorter_than_header() {
        let error = DemonEnvelope::from_bytes(&[0u8; 8])
            .expect_err("buffer shorter than 12 bytes must be rejected");

        assert_eq!(
            error,
            DemonProtocolError::BufferTooShort { context: "Demon header", expected: 12, actual: 8 }
        );
    }

    #[test]
    fn demon_envelope_rejects_empty_buffer() {
        let error =
            DemonEnvelope::from_bytes(&[]).expect_err("empty buffer must be rejected early");

        assert_eq!(
            error,
            DemonProtocolError::BufferTooShort {
                context: "DemonEnvelope",
                expected: MIN_ENVELOPE_SIZE,
                actual: 0,
            }
        );
    }

    #[test]
    fn demon_envelope_rejects_one_byte_buffer() {
        let error =
            DemonEnvelope::from_bytes(&[0xde]).expect_err("1-byte buffer must be rejected early");

        assert_eq!(
            error,
            DemonProtocolError::BufferTooShort {
                context: "DemonEnvelope",
                expected: MIN_ENVELOPE_SIZE,
                actual: 1,
            }
        );
    }

    #[test]
    fn demon_envelope_rejects_two_byte_buffer() {
        let error = DemonEnvelope::from_bytes(&[0xde, 0xad])
            .expect_err("2-byte buffer must be rejected early");

        assert_eq!(
            error,
            DemonProtocolError::BufferTooShort {
                context: "DemonEnvelope",
                expected: MIN_ENVELOPE_SIZE,
                actual: 2,
            }
        );
    }

    #[test]
    fn demon_envelope_rejects_three_byte_buffer() {
        let error = DemonEnvelope::from_bytes(&[0xde, 0xad, 0xbe])
            .expect_err("3-byte buffer must be rejected early");

        assert_eq!(
            error,
            DemonProtocolError::BufferTooShort {
                context: "DemonEnvelope",
                expected: MIN_ENVELOPE_SIZE,
                actual: 3,
            }
        );
    }

    #[test]
    fn demon_package_rejects_buffer_too_short_for_command_id() {
        let error = DemonPackage::from_bytes(&[0u8; 2])
            .expect_err("buffer shorter than 4 bytes must be rejected");

        assert_eq!(
            error,
            DemonProtocolError::BufferTooShort {
                context: "Demon package command id",
                expected: 4,
                actual: 2,
            }
        );
    }

    #[test]
    fn demon_package_rejects_buffer_too_short_for_request_id() {
        for actual in 1..=3 {
            let bytes = vec![0u8; 4 + actual];
            let error = DemonPackage::from_bytes(&bytes)
                .expect_err("buffer shorter than 8 bytes must reject request id parsing");

            assert_eq!(
                error,
                DemonProtocolError::BufferTooShort {
                    context: "Demon package request id",
                    expected: 4,
                    actual,
                }
            );
        }
    }

    #[test]
    fn demon_package_rejects_buffer_too_short_for_payload_length() {
        for actual in 1..=3 {
            let bytes = vec![0u8; 8 + actual];
            let error = DemonPackage::from_bytes(&bytes)
                .expect_err("buffer shorter than 12 bytes must reject payload length parsing");

            assert_eq!(
                error,
                DemonProtocolError::BufferTooShort {
                    context: "Demon package payload length",
                    expected: 4,
                    actual,
                }
            );
        }
    }

    #[test]
    fn enum_conversions_match_havoc_constants() {
        assert_eq!(u32::from(DemonCommand::DemonInit), 99);
        assert_eq!(u32::from(DemonCommand::CommandKerberos), 2550);
        assert_eq!(u32::from(DemonCallback::File), 0x02);
        assert_eq!(u32::from(DemonTransferCommand::Remove), 3);
        assert_eq!(u32::from(DemonSocketCommand::Connect), 0x14);
        assert_eq!(u32::from(DemonSocketType::Client), 0x3);
        assert_eq!(u32::from(DemonInjectError::ProcessArchMismatch), 3);
    }

    #[test]
    fn enum_try_from_rejects_unknown_values() {
        let error =
            DemonCommand::try_from(0xffff_ffff).expect_err("unknown command should be rejected");

        assert_eq!(
            error,
            DemonProtocolError::UnknownEnumValue { kind: "DemonCommand", value: 0xffff_ffff }
        );
    }

    #[test]
    fn demon_package_command_returns_error_for_unrecognized_command_id() {
        let package = DemonPackage { command_id: 0xffff_ffff, request_id: 1, payload: vec![] };
        let bytes = package.to_bytes().expect("package encoding should succeed");
        let parsed = DemonPackage::from_bytes(&bytes).expect("package decoding should succeed");

        let result = parsed.command();

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(DemonProtocolError::UnknownEnumValue { kind: "DemonCommand", value: 0xffff_ffff })
        ));
    }

    #[test]
    fn demon_package_to_bytes_rejects_payload_length_overflow() {
        // We cannot allocate a >4 GiB Vec in CI, so test the extracted helper
        // directly with a length that exceeds u32::MAX.
        let overflow_len = u32::MAX as usize + 1;
        let error = DemonPackage::checked_payload_len(overflow_len)
            .expect_err("payload length exceeding u32::MAX must fail");

        assert_eq!(
            error,
            DemonProtocolError::LengthOverflow {
                context: "Demon package payload",
                length: overflow_len,
            }
        );
    }

    #[test]
    fn demon_package_checked_payload_len_accepts_max_u32() {
        // u32::MAX itself must be accepted — only values above it overflow.
        let len = u32::MAX as usize;
        let result = DemonPackage::checked_payload_len(len);
        assert_eq!(result.unwrap(), u32::MAX);
    }

    // ── Golden-vector tests ────────────────────────────────────────────────
    //
    // These tests verify decoding and re-encoding of hand-constructed byte
    // sequences that match the original Havoc Demon binary protocol layout.
    // They pin the on-wire format so that internal refactors cannot silently
    // drift from Havoc compatibility.

    /// Golden vector: DemonEnvelope carrying a two-package DemonMessage.
    ///
    /// Wire layout (41 bytes total):
    ///   Header (12 bytes, big-endian):
    ///     size    = 0x00000025 (37 = 29 payload + 8)
    ///     magic   = 0xDEADBEEF
    ///     agent_id= 0xCAFEBABE
    ///   Package 1 (12 bytes, little-endian): CommandGetJob(1), req=0, 0-byte payload
    ///   Package 2 (17 bytes, little-endian): CommandOutput(90), req=0x42, 5-byte payload "Hello"
    #[test]
    fn golden_vector_envelope_with_two_packages() {
        #[rustfmt::skip]
        let wire: &[u8] = &[
            // -- DemonHeader (big-endian) --
            0x00, 0x00, 0x00, 0x25, // size = 37
            0xDE, 0xAD, 0xBE, 0xEF, // magic
            0xCA, 0xFE, 0xBA, 0xBE, // agent_id
            // -- Package 1: CommandGetJob --
            0x01, 0x00, 0x00, 0x00, // command_id = 1 (LE)
            0x00, 0x00, 0x00, 0x00, // request_id = 0 (LE)
            0x00, 0x00, 0x00, 0x00, // payload_len = 0 (LE)
            // -- Package 2: CommandOutput --
            0x5A, 0x00, 0x00, 0x00, // command_id = 90 (LE)
            0x42, 0x00, 0x00, 0x00, // request_id = 0x42 (LE)
            0x05, 0x00, 0x00, 0x00, // payload_len = 5 (LE)
            0x48, 0x65, 0x6C, 0x6C, 0x6F, // "Hello"
        ];

        // Decode envelope.
        let envelope = DemonEnvelope::from_bytes(wire).expect("golden vector must decode");
        assert_eq!(envelope.header.magic, DEMON_MAGIC_VALUE);
        assert_eq!(envelope.header.agent_id, 0xCAFE_BABE);

        // Decode packages from the envelope payload.
        let message =
            DemonMessage::from_bytes(&envelope.payload).expect("packages must decode from payload");
        assert_eq!(message.packages.len(), 2, "expected exactly two packages");

        let pkg1 = &message.packages[0];
        assert_eq!(pkg1.command().expect("should recognize"), DemonCommand::CommandGetJob);
        assert_eq!(pkg1.request_id, 0);
        assert!(pkg1.payload.is_empty());

        let pkg2 = &message.packages[1];
        assert_eq!(pkg2.command().expect("should recognize"), DemonCommand::CommandOutput);
        assert_eq!(pkg2.request_id, 0x42);
        assert_eq!(pkg2.payload, b"Hello");

        // Re-encode and compare byte-for-byte.
        let reencoded = envelope.to_bytes();
        assert_eq!(reencoded.as_slice(), wire, "re-encoded envelope must match golden vector");
    }

    /// Golden vector: single-package envelope with CommandExit.
    ///
    /// Wire layout (28 bytes total):
    ///   Header (12 bytes, big-endian):
    ///     size    = 0x00000018 (24 = 16 payload + 8)
    ///     magic   = 0xDEADBEEF
    ///     agent_id= 0x00001337
    ///   Package (16 bytes, little-endian):
    ///     CommandExit(92), req=0xFF, 4-byte payload: exit_method=2 (LE)
    #[test]
    fn golden_vector_single_package_command_exit() {
        #[rustfmt::skip]
        let wire: &[u8] = &[
            // -- DemonHeader (big-endian) --
            0x00, 0x00, 0x00, 0x18, // size = 24
            0xDE, 0xAD, 0xBE, 0xEF, // magic
            0x00, 0x00, 0x13, 0x37, // agent_id
            // -- Package: CommandExit --
            0x5C, 0x00, 0x00, 0x00, // command_id = 92 (LE)
            0xFF, 0x00, 0x00, 0x00, // request_id = 0xFF (LE)
            0x04, 0x00, 0x00, 0x00, // payload_len = 4 (LE)
            0x02, 0x00, 0x00, 0x00, // exit_method = 2 (LE, process exit)
        ];

        let envelope = DemonEnvelope::from_bytes(wire).expect("golden vector must decode");
        assert_eq!(envelope.header.agent_id, 0x0000_1337);

        let message = DemonMessage::from_bytes(&envelope.payload).expect("packages must decode");
        assert_eq!(message.packages.len(), 1);

        let pkg = &message.packages[0];
        assert_eq!(pkg.command().expect("should recognize"), DemonCommand::CommandExit);
        assert_eq!(pkg.request_id, 0xFF);
        assert_eq!(pkg.payload, [0x02, 0x00, 0x00, 0x00]);

        let reencoded = envelope.to_bytes();
        assert_eq!(reencoded.as_slice(), wire, "re-encoded envelope must match golden vector");
    }

    /// Golden vector: multi-package message stream ordering.
    ///
    /// Verifies that DemonMessage preserves the exact package order from
    /// the wire, which matters for command dispatch sequencing.
    #[test]
    fn golden_vector_message_stream_ordering() {
        #[rustfmt::skip]
        let packages_wire: &[u8] = &[
            // Package 1: CommandCheckin(100), req=1, empty
            0x64, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            // Package 2: CommandGetJob(1), req=2, empty
            0x01, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            // Package 3: CommandNoJob(10), req=3, empty
            0x0A, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let message = DemonMessage::from_bytes(packages_wire).expect("message must decode");
        assert_eq!(message.packages.len(), 3, "expected exactly three packages");

        // Verify ordering is preserved.
        assert_eq!(message.packages[0].command().expect("cmd"), DemonCommand::CommandCheckin);
        assert_eq!(message.packages[0].request_id, 1);

        assert_eq!(message.packages[1].command().expect("cmd"), DemonCommand::CommandGetJob);
        assert_eq!(message.packages[1].request_id, 2);

        assert_eq!(message.packages[2].command().expect("cmd"), DemonCommand::CommandNoJob);
        assert_eq!(message.packages[2].request_id, 3);

        // Re-encode and verify byte-for-byte.
        let reencoded = message.to_bytes().expect("message must encode");
        assert_eq!(
            reencoded.as_slice(),
            packages_wire,
            "re-encoded message must match golden vector"
        );
    }

    /// Verify that `DemonPackage::from_bytes` safely rejects a payload_len of
    /// `u32::MAX` (4 GiB) without attempting the allocation. The `read_vec`
    /// length check must fire before any `Vec::with_capacity` or `to_vec` call.
    #[test]
    fn demon_package_rejects_u32_max_payload_len_without_allocating() {
        #[rustfmt::skip]
        let bytes: [u8; 12] = [
            0x01, 0x00, 0x00, 0x00, // command_id = 1 (LE)
            0x02, 0x00, 0x00, 0x00, // request_id = 2 (LE)
            0xFF, 0xFF, 0xFF, 0xFF, // payload_len = u32::MAX (LE)
        ];

        let error = DemonPackage::from_bytes(&bytes)
            .expect_err("u32::MAX payload_len with no trailing data must fail");

        assert_eq!(
            error,
            DemonProtocolError::BufferTooShort {
                context: "Demon package payload",
                expected: u32::MAX as usize,
                actual: 0,
            }
        );
    }
}
