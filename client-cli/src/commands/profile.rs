//! Handler for `red-cell-cli profile validate`.

use std::path::Path;

use serde::Serialize;

use crate::error::{EXIT_GENERAL, EXIT_SUCCESS};
use crate::output::{OutputFormat, TextRender, print_error, print_success};

/// Individual validation error with an optional line reference.
#[derive(Debug, Serialize)]
struct ValidationEntry {
    message: String,
}

/// Output for a valid profile.
#[derive(Debug, Serialize)]
struct ValidResult {
    ok: bool,
}

impl TextRender for ValidResult {
    fn render_text(&self) -> String {
        "profile is valid".to_owned()
    }
}

/// Output for a profile with errors.
#[derive(Debug, Serialize)]
struct InvalidResult {
    ok: bool,
    errors: Vec<ValidationEntry>,
}

impl TextRender for InvalidResult {
    fn render_text(&self) -> String {
        let mut out = String::from("profile validation failed:\n");
        for entry in &self.errors {
            out.push_str("  - ");
            out.push_str(&entry.message);
            out.push('\n');
        }
        out
    }
}

/// Validate a YAOTL profile file locally (no server connection needed).
pub fn validate_local(path: &Path, fmt: &OutputFormat) -> i32 {
    let profile = match red_cell_common::config::Profile::from_file(path) {
        Ok(p) => p,
        Err(e) => {
            let errors = vec![ValidationEntry { message: e.to_string() }];
            let result = InvalidResult { ok: false, errors };
            match print_success(fmt, &result) {
                Ok(()) => return EXIT_GENERAL,
                Err(e) => {
                    print_error(&e).ok();
                    return e.exit_code();
                }
            }
        }
    };

    match profile.validate() {
        Ok(()) => match print_success(fmt, &ValidResult { ok: true }) {
            Ok(()) => EXIT_SUCCESS,
            Err(e) => {
                print_error(&e).ok();
                e.exit_code()
            }
        },
        Err(validation_err) => {
            let errors = validation_err
                .errors
                .into_iter()
                .map(|message| ValidationEntry { message })
                .collect();
            let result = InvalidResult { ok: false, errors };
            match print_success(fmt, &result) {
                Ok(()) => EXIT_GENERAL,
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    #[test]
    fn valid_profile_returns_success() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("good.yaotl");
        let mut f = std::fs::File::create(&path).expect("create");
        write!(
            f,
            r#"
Teamserver {{
    Host = "0.0.0.0"
    Port = 40056
}}

Operators {{
    user "admin" {{
        Password = "secret123"
    }}
}}

Listeners {{}}

Demon {{
    Sleep  = 2
    Jitter = 10
}}
"#
        )
        .expect("write");
        drop(f);

        let code = validate_local(&path, &OutputFormat::Json);
        assert_eq!(code, EXIT_SUCCESS);
    }

    #[test]
    fn invalid_profile_returns_general_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.yaotl");
        let mut f = std::fs::File::create(&path).expect("create");
        write!(
            f,
            r#"
Teamserver {{
    Host = ""
    Port = 0
}}

Operators {{}}

Listeners {{}}

Demon {{
    Sleep  = 2
    Jitter = 10
}}
"#
        )
        .expect("write");
        drop(f);

        let code = validate_local(&path, &OutputFormat::Json);
        assert_eq!(code, EXIT_GENERAL);
    }

    #[test]
    fn missing_file_returns_general_error() {
        let path = Path::new("/tmp/does-not-exist-red-cell-test.yaotl");
        let code = validate_local(path, &OutputFormat::Json);
        assert_eq!(code, EXIT_GENERAL);
    }

    #[test]
    fn parse_error_returns_general_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("malformed.yaotl");
        std::fs::write(&path, "this is not valid HCL {{{{").expect("write");

        let code = validate_local(&path, &OutputFormat::Json);
        assert_eq!(code, EXIT_GENERAL);
    }

    #[test]
    fn valid_result_text_render() {
        let result = ValidResult { ok: true };
        assert_eq!(result.render_text(), "profile is valid");
    }

    #[test]
    fn invalid_result_text_render() {
        let result = InvalidResult {
            ok: false,
            errors: vec![
                ValidationEntry { message: "Host must not be empty".to_owned() },
                ValidationEntry { message: "Port must be > 0".to_owned() },
            ],
        };
        let text = result.render_text();
        assert!(text.contains("Host must not be empty"));
        assert!(text.contains("Port must be > 0"));
    }
}
