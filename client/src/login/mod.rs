mod state;
mod types;
mod ui;

pub use state::LoginState;
pub use types::{TlsFailure, TlsFailureKind};
// LoginAction and render_login_dialog are only used by the binary target (app.rs, login_flow.rs),
// not by the lib target — suppress the unused-import lint that fires on the lib check.
#[allow(unused_imports)]
pub(crate) use types::LoginAction;
#[allow(unused_imports)]
pub(crate) use ui::render_login_dialog;
