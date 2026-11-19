//! Tamper-evident audit log.
//!
//! Every row stores `hash = SHA-256(AUDIT_DOMAIN || prev_hash || canonical(row))`.
//! Inserts are serialized with a transaction-scoped advisory lock, so the chain is
//! linear even under concurrency. The runtime DB role cannot UPDATE/DELETE rows
//! (see migration 0001); `verify_chain` detects edits made with owner privileges.
//!
//! Limitation: deleting the newest rows (tail truncation) is not detectable from the
//! chain alone; periodically export the head hash out of band (planned: alert channel).
//!
//! `details` must not contain secret values. Prefer strings, integers and booleans:
//! floats may not round-trip byte-identically through `jsonb`.

use std::fmt::Write as _;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Postgres, Transaction};

const AUDIT_DOMAIN: &[u8] = b"secrettrace/audit/v1\0";
/// Advisory lock key ("STAUDIT").
const AUDIT_LOCK_KEY: i64 = 0x0053_5441_5544_4954;
const VERIFY_BATCH: i64 = 1000;
pub const MAX_DETAILS_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    User,
    Token,
    System,
}

impl ActorType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Token => "token",
            Self::System => "system",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub actor_type: ActorType,
    pub actor_id: String,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub ip: Option<IpAddr>,
    pub request_id: Option<String>,
    pub details: Value,
}

impl AuditEvent {
    #[must_use]
    pub fn system(action: impl Into<String>) -> Self {
        Self {
            actor_type: ActorType::System,
            actor_id: "system".into(),
            action: action.into(),
            target_type: None,
            target_id: None,
            ip: None,
            request_id: None,
            details: Value::Object(serde_json::Map::new()),
        }
    }

    #[must_use]
    pub fn target(mut self, kind: impl Into<String>, id: impl Into<String>) -> Self {
        self.target_type = Some(kind.into());
        self.target_id = Some(id.into());
        self
    }

    #[must_use]
    pub fn details(mut self, details: Value) -> Self {
        self.details = details;
        self
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit details exceed {MAX_DETAILS_BYTES} bytes")]
    DetailsTooLarge,
    #[error("audit details must be a JSON object")]
    DetailsNotObject,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// Append an event. Must run inside the transaction of the action being audited, so
/// the action and its audit record commit or roll back together.
pub async fn record(tx: &mut Transaction<'_, Postgres>, event: &AuditEvent) -> Result<i64, AuditError> {
    if !event.details.is_object() {
        return Err(AuditError::DetailsNotObject);
    }
    let mut details_canon = String::new();
    canonical_json(&event.details, &mut details_canon);
    if details_canon.len() > MAX_DETAILS_BYTES {
        return Err(AuditError::DetailsTooLarge);
    }

    sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(AUDIT_LOCK_KEY).execute(&mut **tx).await?;
    let prev: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetch_optional(&mut **tx).await?;

    let ts = now_micros();
    let row = CanonicalRow {
        ts,
        actor_type: event.actor_type.as_str(),
        actor_id: &event.actor_id,
        action: &event.action,
        target_type: event.target_type.as_deref(),
        target_id: event.target_id.as_deref(),
        ip: event.ip.map(|ip| ip.to_string()),
        request_id: event.request_id.as_deref(),
        details: &event.details,
    };
    let hash = chain_hash(prev.as_deref(), &row);

    let id: i64 = sqlx::query_scalar(
        "INSERT INTO audit_log
           (ts, actor_type, actor_id, action, target_type, target_id, ip, request_id, details, prev_hash, hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7::inet, $8, $9, $10, $11)
         RETURNING id",
    )
    .bind(ts)
    .bind(row.actor_type)
    .bind(row.actor_id)
    .bind(row.action)
    .bind(row.target_type)
    .bind(row.target_id)
    .bind(row.ip.as_deref())
    .bind(row.request_id)
    .bind(row.details)
    .bind(prev.as_deref())
    .bind(hash.as_slice())
    .fetch_one(&mut **tx)
    .await?;
    Ok(id)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub rows: u64,
    pub head: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("audit chain broken at row id {id}: {reason}")]
    Broken { id: i64, reason: &'static str },
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

#[derive(sqlx::FromRow)]
struct StoredRow {
    id: i64,
    ts: DateTime<Utc>,
    actor_type: String,
    actor_id: String,
    action: String,
    target_type: Option<String>,
    target_id: Option<String>,
    ip: Option<String>,
    request_id: Option<String>,
    details: Value,
    prev_hash: Option<Vec<u8>>,
    hash: Vec<u8>,
}

/// Recompute the whole chain. Reads in batches to bound memory.
pub async fn verify_chain(pool: &PgPool) -> Result<VerifyReport, VerifyError> {
    let mut last_id = 0_i64;
    let mut prev: Option<Vec<u8>> = None;
    let mut rows = 0_u64;

    loop {
        let batch: Vec<StoredRow> = sqlx::query_as(
            "SELECT id, ts, actor_type, actor_id, action, target_type, target_id,
                    host(ip) AS ip, request_id, details, prev_hash, hash
             FROM audit_log WHERE id > $1 ORDER BY id LIMIT $2",
        )
        .bind(last_id)
        .bind(VERIFY_BATCH)
        .fetch_all(pool)
        .await?;
        if batch.is_empty() {
            break;
        }

        for r in batch {
            if r.prev_hash != prev {
                return Err(VerifyError::Broken { id: r.id, reason: "prev_hash does not link to previous row" });
            }
            let row = CanonicalRow {
                ts: r.ts,
                actor_type: &r.actor_type,
                actor_id: &r.actor_id,
                action: &r.action,
                target_type: r.target_type.as_deref(),
                target_id: r.target_id.as_deref(),
                ip: r.ip.clone(),
                request_id: r.request_id.as_deref(),
                details: &r.details,
            };
            if chain_hash(prev.as_deref(), &row).as_slice() != r.hash.as_slice() {
                return Err(VerifyError::Broken { id: r.id, reason: "row content does not match its hash" });
            }
            last_id = r.id;
            prev = Some(r.hash);
            rows += 1;
        }
    }

    Ok(VerifyReport { rows, head: prev.map(hex::encode) })
}

struct CanonicalRow<'a> {
    ts: DateTime<Utc>,
    actor_type: &'a str,
    actor_id: &'a str,
    action: &'a str,
    target_type: Option<&'a str>,
    target_id: Option<&'a str>,
    ip: Option<String>,
    request_id: Option<&'a str>,
    details: &'a Value,
}

fn chain_hash(prev: Option<&[u8]>, row: &CanonicalRow<'_>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(AUDIT_DOMAIN);
    h.update(prev.unwrap_or(&[0u8; 32]));

    // Length-prefixed fields: unambiguous without relying on any serializer's layout.
    let ts = row.ts.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
    let mut details = String::new();
    canonical_json(row.details, &mut details);
    let fields: [Option<&str>; 9] = [
        Some(&ts),
        Some(row.actor_type),
        Some(row.actor_id),
        Some(row.action),
        row.target_type,
        row.target_id,
        row.ip.as_deref(),
        row.request_id,
        Some(&details),
    ];
    for field in fields {
        match field {
            None => h.update([0u8]),
            Some(s) => {
                h.update([1u8]);
                h.update((s.len() as u64).to_be_bytes());
                h.update(s.as_bytes());
            }
        }
    }
    h.finalize().into()
}

/// JSON with object keys sorted bytewise, independent of `serde_json` feature flags and
/// of `jsonb` key ordering.
fn canonical_json(v: &Value, out: &mut String) {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                canonical_json(&map[k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_json(item, out);
            }
            out.push(']');
        }
        scalar => {
            let _ = write!(out, "{scalar}");
        }
    }
}

/// Postgres stores microseconds; truncate so the hashed value equals the stored one.
fn now_micros() -> DateTime<Utc> {
    let now = Utc::now();
    DateTime::from_timestamp_micros(now.timestamp_micros()).unwrap_or(now)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn canonical_json_sorts_keys_recursively() {
        let mut a = String::new();
        let mut b = String::new();
        canonical_json(&json!({"b": 1, "a": {"y": [1, {"d": 1, "c": 2}], "x": "s"}}), &mut a);
        canonical_json(&json!({"a": {"x": "s", "y": [1, {"c": 2, "d": 1}]}, "b": 1}), &mut b);
        assert_eq!(a, b);
        assert_eq!(a, r#"{"a":{"x":"s","y":[1,{"c":2,"d":1}]},"b":1}"#);
    }

    fn row<'a>(details: &'a Value, target: Option<&'a str>) -> CanonicalRow<'a> {
        CanonicalRow {
            ts: DateTime::from_timestamp_micros(1_700_000_000_123_456).unwrap_or_default(),
            actor_type: "user",
            actor_id: "u1",
            action: "secret.create",
            target_type: target,
            target_id: None,
            ip: Some("10.0.0.1".into()),
            request_id: None,
            details,
        }
    }

    #[test]
    fn hash_covers_every_field_and_previous_hash() {
        let d = json!({"k": "v"});
        let base = chain_hash(None, &row(&d, None));
        assert_ne!(base, chain_hash(Some(&[1u8; 32]), &row(&d, None)));
        assert_ne!(base, chain_hash(None, &row(&json!({"k": "w"}), None)));
        // None vs empty string must differ.
        assert_ne!(base, chain_hash(None, &row(&d, Some(""))));
    }
}
