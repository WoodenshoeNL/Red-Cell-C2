//! Pure helper functions shared across panel modules.
//!
//! These are stateless, standalone functions used by both the panel render
//! implementations and the task builder modules.  They carry no UI side-effects
//! on their own — they format data, filter slices, or perform simple file I/O.

pub(crate) mod clipboard;
pub(crate) mod format;
pub(crate) mod ui;

pub(crate) use clipboard::*;
pub(crate) use format::*;
pub(crate) use ui::*;
