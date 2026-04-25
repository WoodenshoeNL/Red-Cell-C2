//! Command handler modules for `red-cell-cli`.
//!
//! Each subcommand lives in its own module.  Modules are added here as
//! downstream issues are implemented.

pub mod agent;
pub mod audit;
pub mod listener;
pub mod login;
pub mod loot;
pub mod operator;
pub mod payload;
pub mod profile;
pub mod session;
pub mod status;
pub(crate) mod types;
