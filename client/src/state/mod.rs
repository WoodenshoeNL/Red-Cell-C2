//! UI state types for the Red Cell operator client.
//!
//! This module holds all the persistent state structs, enums, and dialog state
//! types that drive the egui interface.  None of these types perform I/O or
//! networking — they are plain data containers updated by the render loop.

pub(crate) mod agent;
pub(crate) mod listener;
pub(crate) mod session;

pub(crate) use agent::*;
pub(crate) use listener::*;
pub(crate) use session::*;
