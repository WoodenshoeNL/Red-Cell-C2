//! Command handler methods for `SocketState`.
//!
//! This is a child module of `socket_state`, giving nested handler modules
//! access to `SocketState`'s private fields while keeping each concern focused.

#[path = "command_handlers/rportfwd_handlers.rs"]
mod rportfwd_handlers;
#[path = "command_handlers/socket_io_handlers.rs"]
mod socket_io_handlers;
#[path = "command_handlers/socks_handlers.rs"]
mod socks_handlers;
