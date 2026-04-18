//! Tests for operator configuration parsing and role defaults.

use super::super::*;

#[test]
fn parses_operator_roles_and_defaults_missing_roles_to_admin() {
    let profile = Profile::parse(
        r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "admin" {
                Password = "adminpw"
              }

              user "operator" {
                Password = "operatorpw"
                Role = "Operator"
              }

              user "analyst" {
                Password = "analystpw"
                Role = "analyst"
              }
            }

            Demon {}
            "#,
    )
    .expect("profile with roles should parse");

    assert_eq!(profile.operators.users["admin"].role, OperatorRole::Admin);
    assert_eq!(profile.operators.users["operator"].role, OperatorRole::Operator);
    assert_eq!(profile.operators.users["analyst"].role, OperatorRole::Analyst);
}
