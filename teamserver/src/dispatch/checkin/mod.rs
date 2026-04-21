mod handler;
mod parse;
mod validate;

pub(super) use handler::handle_checkin;
pub(super) use parse::decode_working_hours;

// Flatten the dispatch-level namespace so submodules can reach shared helpers
// via `super::Foo` rather than long `super::super::` paths.  Mirrors the same
// pattern used in `dispatch/mod.rs` for its own child modules.
#[allow(unused_imports)]
use super::util::{basename, process_arch_label, windows_arch_label, windows_version_label};
#[allow(unused_imports)]
use super::{CallbackParser, CommandDispatchError, parse_optional_kill_date};

#[cfg(test)]
mod tests;
