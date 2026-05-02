//! Shared application state for the Red Cell teamserver.

mod router;
mod state;
#[cfg(test)]
mod test_state;

pub use router::build_router;
pub use state::TeamserverState;

#[cfg(test)]
pub(crate) use test_state::build_test_state;

#[cfg(test)]
mod router_tests;
