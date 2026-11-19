use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use sqlx::PgPool;
use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;

/// Migrations embedded at compile time from `/migrations`.
pub static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

pub async fn connect(url: &SecretString, max_connections: u32) -> Result<PgPool, sqlx::Error> {
    pool_options(max_connections).connect(url.expose_secret()).await
}

/// Pool that connects on first use (lets the API start while the DB is still booting;
/// `/readyz` reports the real state).
pub fn connect_lazy(url: &SecretString, max_connections: u32) -> Result<PgPool, sqlx::Error> {
    pool_options(max_connections).connect_lazy(url.expose_secret())
}

fn pool_options(max_connections: u32) -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Duration::from_secs(600))
}

/// Highest successfully applied migration version, `None` on a fresh database.
pub async fn applied_version(pool: &PgPool) -> Result<Option<i64>, sqlx::Error> {
    let exists: bool = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL").fetch_one(pool).await?;
    if !exists {
        return Ok(None);
    }
    sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations WHERE success").fetch_one(pool).await
}
