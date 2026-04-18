mod login;
mod rbac;
mod session;

use red_cell_common::config::Profile;

pub(crate) fn profile() -> Profile {
    Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }

        Operators {
          user "operator" {
            Password = "password1234"
            Role = "Operator"
          }
          user "admin" {
            Password = "adminpw"
            Role = "Admin"
          }
          user "analyst" {
            Password = "readonly"
            Role = "Analyst"
          }
        }

        Demon {}
        "#,
    )
    .expect("test profile should parse")
}
