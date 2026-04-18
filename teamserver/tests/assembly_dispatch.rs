//! Integration tests for Demon assembly / BOF / `ps_import` callback dispatch.
//!
//! These tests are serialized under cargo-nextest via `.config/nextest.toml` (filter
//! `binary(assembly_dispatch)`, test group `assembly-dispatch-serial`) to avoid intermittent
//! `ENOENT` when nextest execs this integration test binary under heavy parallel workspace runs.
//!
//! Modules:
//! - `helpers`        — shared test harness, payload builders, and server boot utilities
//! - `bof`            — BOF (Beacon Object File) inline-execute callback tests
//! - `inline_execute` — `CommandAssemblyInlineExecute` and `CommandAssemblyListVersions` tests
//! - `ps_import`      — `CommandPsImport` callback tests

mod common;

#[path = "assembly_dispatch/helpers.rs"]
mod helpers;

#[path = "assembly_dispatch/bof.rs"]
mod bof;
#[path = "assembly_dispatch/inline_execute.rs"]
mod inline_execute;
#[path = "assembly_dispatch/ps_import.rs"]
mod ps_import;
