//! Test suite for `dispatch::network`.
//!
//! Submodules mirror the implementation layout: domain commands in `domain`,
//! session/user commands in `sessions`, share/group commands in `groups`,
//! error paths in `errors`, and utility helpers in `util`.

mod common;
mod domain;
mod errors;
mod groups;
mod sessions;
mod util;
