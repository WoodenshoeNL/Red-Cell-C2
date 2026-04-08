use red_cell::database::{PersistedOperator, TeamserverError};
use red_cell_common::config::OperatorRole;

#[path = "database_common.rs"]
mod database_common;
use database_common::test_database;

#[tokio::test]
async fn operator_repository_supports_runtime_operator_crud_queries() -> Result<(), TeamserverError>
{
    let database = test_database().await?;
    let repository = database.operators();
    let operator = PersistedOperator {
        username: "trinity".to_owned(),
        password_verifier: "abc123".to_owned(),
        role: OperatorRole::Analyst,
    };

    repository.create(&operator).await?;

    assert_eq!(repository.get("trinity").await?, Some(operator.clone()));
    assert_eq!(repository.list().await?, vec![operator]);

    Ok(())
}

#[tokio::test]
async fn operator_repository_rejects_duplicate_usernames_without_mutating_existing_row()
-> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.operators();
    let original = PersistedOperator {
        username: "trinity".to_owned(),
        password_verifier: "abc123".to_owned(),
        role: OperatorRole::Analyst,
    };
    let duplicate = PersistedOperator {
        username: original.username.clone(),
        password_verifier: "def456".to_owned(),
        role: OperatorRole::Operator,
    };

    repository.create(&original).await?;

    let error =
        repository.create(&duplicate).await.expect_err("duplicate operator insert should fail");

    assert!(matches!(error, TeamserverError::Database(_)));
    let TeamserverError::Database(sqlx::Error::Database(database_error)) = &error else {
        panic!("expected sqlite database error for duplicate operator insert");
    };
    assert_eq!(database_error.code().as_deref(), Some("1555"));
    assert!(
        database_error
            .message()
            .contains("UNIQUE constraint failed: ts_runtime_operators.username")
    );

    assert_eq!(repository.get(&original.username).await?, Some(original.clone()));
    assert_eq!(repository.list().await?, vec![original]);

    Ok(())
}

#[tokio::test]
async fn operator_repository_updates_password_verifier_for_existing_runtime_operator()
-> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.operators();
    let operator = PersistedOperator {
        username: "trinity".to_owned(),
        password_verifier: "abc123".to_owned(),
        role: OperatorRole::Analyst,
    };

    repository.create(&operator).await?;
    repository.update_password_verifier(&operator.username, "updated-verifier").await?;

    assert_eq!(
        repository.get(&operator.username).await?,
        Some(PersistedOperator {
            username: operator.username,
            password_verifier: "updated-verifier".to_owned(),
            role: operator.role,
        })
    );

    Ok(())
}

#[tokio::test]
async fn operator_repository_update_password_verifier_is_a_noop_for_missing_operator()
-> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.operators();
    let existing = PersistedOperator {
        username: "neo".to_owned(),
        password_verifier: "keep-me".to_owned(),
        role: OperatorRole::Operator,
    };

    repository.create(&existing).await?;
    repository.update_password_verifier("missing", "new-verifier").await?;

    assert_eq!(repository.get("missing").await?, None);
    assert_eq!(repository.get(&existing.username).await?, Some(existing.clone()));
    assert_eq!(repository.list().await?, vec![existing]);

    Ok(())
}

#[tokio::test]
async fn operator_get_with_unsupported_role_returns_error() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.operators();

    let operator = PersistedOperator {
        username: "bad-role-user".to_owned(),
        password_verifier: "dummy-verifier".to_owned(),
        role: OperatorRole::Admin,
    };
    repository.create(&operator).await?;

    sqlx::query("UPDATE ts_runtime_operators SET role = 'Superuser' WHERE username = ?")
        .bind(&operator.username)
        .execute(database.pool())
        .await
        .expect("raw SQL update must succeed");

    let result = repository.get(&operator.username).await;
    assert!(result.is_err(), "get() must fail on unsupported operator role 'Superuser'");
    let err = result.expect_err("expected Err");
    assert!(
        matches!(&err, TeamserverError::InvalidPersistedValue { field, .. } if *field == "ts_runtime_operators.role"),
        "expected InvalidPersistedValue for role, got: {err:?}",
    );

    Ok(())
}

#[tokio::test]
async fn operator_list_with_unsupported_role_returns_error() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.operators();

    let operator = PersistedOperator {
        username: "bad-role-list".to_owned(),
        password_verifier: "dummy-verifier".to_owned(),
        role: OperatorRole::Operator,
    };
    repository.create(&operator).await?;

    sqlx::query("UPDATE ts_runtime_operators SET role = 'Root' WHERE username = ?")
        .bind(&operator.username)
        .execute(database.pool())
        .await
        .expect("raw SQL update must succeed");

    let result = repository.list().await;
    assert!(result.is_err(), "list() must fail on unsupported operator role 'Root'");
    let err = result.expect_err("expected Err");
    assert!(
        matches!(&err, TeamserverError::InvalidPersistedValue { field, .. } if *field == "ts_runtime_operators.role"),
        "expected InvalidPersistedValue for role, got: {err:?}",
    );

    Ok(())
}

#[tokio::test]
async fn operator_create_after_pool_close_returns_connection_error() -> Result<(), TeamserverError>
{
    let database = test_database().await?;
    let operators = database.operators();

    let operator = PersistedOperator {
        username: "neo".to_owned(),
        password_verifier: "xyz".to_owned(),
        role: OperatorRole::Operator,
    };

    operators.create(&operator).await?;
    database.close().await;

    let err = operators
        .create(&PersistedOperator {
            username: "morpheus".to_owned(),
            password_verifier: "abc".to_owned(),
            role: OperatorRole::Admin,
        })
        .await
        .expect_err("operator create after close should fail");

    assert!(matches!(err, TeamserverError::Database(_)));

    Ok(())
}
