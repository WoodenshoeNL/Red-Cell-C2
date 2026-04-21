//! Havoc Demon protocol enum definitions.

use super::DemonProtocolError;

macro_rules! protocol_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $( $(#[$var_meta:meta])* $variant:ident = $value:expr, )+
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(u32)]
        $vis enum $name {
            $( $(#[$var_meta])* $variant = $value, )+
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
