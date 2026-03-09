//! Havoc Demon binary protocol types and serializers.

use thiserror::Error;

/// Transport magic value used by Havoc Demon packets.
pub const DEMON_MAGIC_VALUE: u32 = 0xDEAD_BEEF;

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

    /// Serialize the package using Havoc's little-endian package format.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DemonProtocolError> {
        let payload_len =
            u32::try_from(self.payload.len()).map_err(|_| DemonProtocolError::LengthOverflow {
                context: "Demon package payload",
                length: self.payload.len(),
            })?;

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
        DEMON_MAGIC_VALUE, DemonCallback, DemonCommand, DemonEnvelope, DemonHeader, DemonMessage,
        DemonPackage, DemonProtocolError,
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
    fn enum_conversions_match_havoc_constants() {
        assert_eq!(u32::from(DemonCommand::DemonInit), 99);
        assert_eq!(u32::from(DemonCommand::CommandKerberos), 2550);
        assert_eq!(u32::from(DemonCallback::File), 0x02);
    }
}
