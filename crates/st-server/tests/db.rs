//! Database integration tests. Require Postgres: `make test-db` starts one and sets
//! `DATABASE_URL` (superuser). Each test gets a fresh database with migrations applied.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::json;
use sqlx::PgPool;
use st_server::audit::{self, ActorType, AuditEvent, VerifyError};

fn event(action: &str) -> AuditEvent {
    AuditEvent {
        actor_type: ActorType::User,
        actor_id: "4f1c2d1e-0000-0000-0000-000000000001".into(),
        action: action.into(),
        target_type: Some("secret".into()),
        target_id: Some("s-1".into()),
        ip: Some("2001:db8::1".parse().unwrap()),
        request_id: Some("req-1".into()),
        details: json!({ "name": "prod-aws", "nested": { "b": 2, "a": [1, true, null] } }),
    }
}

async fn record(pool: &PgPool, ev: &AuditEvent) -> i64 {
    let mut tx = pool.begin().await.unwrap();
    let id = audit::record(&mut tx, ev).await.unwrap();
    tx.commit().await.unwrap();
    id
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn audit_chain_verifies(pool: PgPool) {
    assert_eq!(audit::verify_chain(&pool).await.unwrap().rows, 0);
    for a in ["secret.create", "secret.update", "auth.login"] {
        record(&pool, &event(a)).await;
    }
    record(&pool, &AuditEvent::system("db.migrate")).await;
    let report = audit::verify_chain(&pool).await.unwrap();
    assert_eq!(report.rows, 4);
    assert_eq!(report.head.map(|h| h.len()), Some(64));
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn audit_detects_tampering(pool: PgPool) {
    record(&pool, &event("secret.create")).await;
    let victim = record(&pool, &event("secret.delete")).await;
    record(&pool, &event("auth.logout")).await;

    // An attacker with owner privileges rewrites history.
    sqlx::query("UPDATE audit_log SET action = 'secret.view' WHERE id = $1").bind(victim).execute(&pool).await.unwrap();

    match audit::verify_chain(&pool).await {
        Err(VerifyError::Broken { id, .. }) => assert_eq!(id, victim),
        other => panic!("expected broken chain, got {other:?}"),
    }
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn audit_detects_deleted_middle_row(pool: PgPool) {
    record(&pool, &event("a.one")).await;
    let middle = record(&pool, &event("a.two")).await;
    let last = record(&pool, &event("a.three")).await;
    sqlx::query("DELETE FROM audit_log WHERE id = $1").bind(middle).execute(&pool).await.unwrap();
    match audit::verify_chain(&pool).await {
        Err(VerifyError::Broken { id, .. }) => assert_eq!(id, last),
        other => panic!("expected broken chain, got {other:?}"),
    }
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn audit_rolls_back_with_transaction(pool: PgPool) {
    let mut tx = pool.begin().await.unwrap();
    audit::record(&mut tx, &event("secret.create")).await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(audit::verify_chain(&pool).await.unwrap().rows, 0);
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn audit_rejects_bad_details(pool: PgPool) {
    let mut tx = pool.begin().await.unwrap();
    let not_object = AuditEvent::system("x").details(json!([1, 2]));
    assert!(matches!(audit::record(&mut tx, &not_object).await, Err(audit::AuditError::DetailsNotObject)));
    let huge = AuditEvent::system("x").details(json!({ "blob": "a".repeat(audit::MAX_DETAILS_BYTES) }));
    assert!(matches!(audit::record(&mut tx, &huge).await, Err(audit::AuditError::DetailsTooLarge)));
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn audit_chain_is_linear_under_concurrency(pool: PgPool) {
    let tasks: Vec<_> = (0..24)
        .map(|i| {
            let pool = pool.clone();
            tokio::spawn(async move { record(&pool, &event(&format!("concurrent.{i}"))).await })
        })
        .collect();
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(audit::verify_chain(&pool).await.unwrap().rows, 24);
}

/// The runtime role may append to the audit log but never rewrite or delete it.
#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn runtime_role_cannot_modify_audit_log(pool: PgPool) {
    let role_exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'st_app')")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(role_exists, "role st_app missing: run tests via `make test-db` (init script creates it)");

    let id = record(&pool, &event("secret.create")).await;
    let mut conn = pool.acquire().await.unwrap();
    sqlx::query("SET ROLE st_app").execute(&mut *conn).await.unwrap();

    // Allowed: read + append.
    sqlx::query("SELECT count(*) FROM audit_log").execute(&mut *conn).await.unwrap();

    for stmt in ["UPDATE audit_log SET action = 'x' WHERE id = $1", "DELETE FROM audit_log WHERE id = $1"] {
        let err = sqlx::query(stmt).bind(id).execute(&mut *conn).await.unwrap_err();
        let code = err.as_database_error().and_then(sqlx::error::DatabaseError::code).map(std::borrow::Cow::into_owned);
        assert_eq!(code.as_deref(), Some("42501"), "{stmt} must be denied, got {err}");
    }
    let err = sqlx::query("TRUNCATE audit_log").execute(&mut *conn).await.unwrap_err();
    assert_eq!(err.as_database_error().and_then(sqlx::error::DatabaseError::code).as_deref(), Some("42501"));

    // Migration bookkeeping is off limits too.
    let err = sqlx::query("SELECT * FROM _sqlx_migrations").execute(&mut *conn).await.unwrap_err();
    assert_eq!(err.as_database_error().and_then(sqlx::error::DatabaseError::code).as_deref(), Some("42501"));

    sqlx::query("RESET ROLE").execute(&mut *conn).await.unwrap();
}

#[sqlx::test(migrator = "st_server::db::MIGRATOR")]
async fn schema_constraints_protect_hint_policy(pool: PgPool) {
    let fp = vec![7u8; 32];
    // Low-entropy types may not carry hints.
    let err = sqlx::query(
        "INSERT INTO secrets (name, type, owner, fingerprint, pepper_version, hint_prefix, value_length)
         VALUES ('pw', 'password', 'me', $1, 1, 'AKIA', 20)",
    )
    .bind(&fp)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(err.as_database_error().and_then(sqlx::error::DatabaseError::code).as_deref(), Some("23514"));

    // Length without prefix is rejected.
    let err = sqlx::query(
        "INSERT INTO secrets (name, type, owner, fingerprint, pepper_version, value_length)
         VALUES ('k', 'api_key', 'me', $1, 1, 20)",
    )
    .bind(&fp)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(err.as_database_error().and_then(sqlx::error::DatabaseError::code).as_deref(), Some("23514"));

    // Same fingerprint + version twice is a conflict.
    for name in ["a", "b"] {
        let r = sqlx::query(
            "INSERT INTO secrets (name, type, owner, fingerprint, pepper_version) VALUES ($1, 'token', 'me', $2, 1)",
        )
        .bind(name)
        .bind(&fp)
        .execute(&pool)
        .await;
        if name == "b" {
            assert_eq!(
                r.unwrap_err().as_database_error().and_then(sqlx::error::DatabaseError::code).as_deref(),
                Some("23505")
            );
        }
    }
}
