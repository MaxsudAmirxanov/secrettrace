//! Allow-rule evaluation for locations.
//!
//! A rule allows a location when every field it sets matches: `source_type` exactly,
//! `uri_pattern` against the location URI, `path_pattern` against `locator.path`,
//! `environment` exactly. The rule with the lowest id wins, so `allow_rule_id` is stable.
//! A rule with `environment` set never matches a location without one.

use std::collections::HashMap;

use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

use super::{Glob, GlobError};
use crate::model::SourceType;

/// A rule with its patterns parsed once.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub id: i64,
    pub source_type: Option<SourceType>,
    pub uri: Glob,
    pub path: Option<Glob>,
    pub environment: Option<String>,
}

impl CompiledRule {
    pub fn compile(
        id: i64,
        source_type: Option<SourceType>,
        uri_pattern: &str,
        path_pattern: Option<&str>,
        environment: Option<&str>,
    ) -> Result<Self, GlobError> {
        Ok(Self {
            id,
            source_type,
            uri: Glob::parse(uri_pattern)?,
            path: path_pattern.map(Glob::parse).transpose()?,
            environment: environment.map(str::to_owned),
        })
    }

    #[must_use]
    pub fn matches(&self, s: &Subject<'_>) -> bool {
        self.source_type.is_none_or(|t| t == s.source_type)
            && self.uri.matches(s.uri)
            && self.path.as_ref().is_none_or(|p| p.matches(s.path))
            && self.environment.as_deref().is_none_or(|e| s.environment == Some(e))
    }
}

/// The parts of a location that rules look at.
#[derive(Debug, Clone, Copy)]
pub struct Subject<'a> {
    pub source_type: SourceType,
    pub uri: &'a str,
    pub path: &'a str,
    pub environment: Option<&'a str>,
}

/// Id of the first (lowest-id) rule allowing the location, if any.
#[must_use]
pub fn first_match(rules: &[CompiledRule], s: &Subject<'_>) -> Option<i64> {
    rules.iter().filter(|r| r.matches(s)).map(|r| r.id).min()
}

/// Rules of the given secrets, compiled. Patterns were validated on save; one that no
/// longer parses (e.g. after a grammar change) is skipped and logged by id, never applied.
pub async fn load_rules(
    conn: &mut PgConnection,
    secret_ids: &[Uuid],
) -> Result<HashMap<Uuid, Vec<CompiledRule>>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, secret_id, source_type, uri_pattern, path_pattern, environment
         FROM secret_allow_rules WHERE secret_id = ANY($1) ORDER BY id",
    )
    .bind(secret_ids)
    .fetch_all(conn)
    .await?;
    let mut map: HashMap<Uuid, Vec<CompiledRule>> = HashMap::new();
    for row in rows {
        let id: i64 = row.try_get("id")?;
        let compiled = CompiledRule::compile(
            id,
            row.try_get("source_type")?,
            row.try_get::<&str, _>("uri_pattern")?,
            row.try_get::<Option<&str>, _>("path_pattern")?,
            row.try_get::<Option<&str>, _>("environment")?,
        );
        match compiled {
            Ok(rule) => map.entry(row.try_get("secret_id")?).or_default().push(rule),
            Err(e) => tracing::warn!(rule_id = id, error = %e, "skipping allow rule that does not parse"),
        }
    }
    Ok(map)
}

/// Recompute `is_allowed` / `allow_rule_id` of every location of a secret, e.g. after its
/// rules were replaced. Run it in the same transaction as the rule change. Returns how
/// many locations changed state.
pub async fn reevaluate(conn: &mut PgConnection, secret_id: Uuid) -> Result<u64, sqlx::Error> {
    let rules = load_rules(conn, &[secret_id]).await?.remove(&secret_id).unwrap_or_default();
    // Ordered locking: concurrent writers of the same rows take locks in the same order.
    let rows = sqlx::query(
        "SELECT id, source_type, uri, coalesce(locator->>'path', '') AS path, environment, allow_rule_id
         FROM locations WHERE secret_id = $1 ORDER BY id FOR UPDATE",
    )
    .bind(secret_id)
    .fetch_all(&mut *conn)
    .await?;

    let mut ids = Vec::new();
    let mut allowed = Vec::new();
    let mut rule_ids: Vec<Option<i64>> = Vec::new();
    for row in &rows {
        let subject = Subject {
            source_type: row.try_get("source_type")?,
            uri: row.try_get("uri")?,
            path: row.try_get("path")?,
            environment: row.try_get("environment")?,
        };
        // Every row goes in: the UPDATE skips unchanged ones, and this also repairs rows
        // whose `is_allowed` disagrees with `allow_rule_id`.
        let rule = first_match(&rules, &subject);
        ids.push(row.try_get::<Uuid, _>("id")?);
        allowed.push(rule.is_some());
        rule_ids.push(rule);
    }
    if ids.is_empty() {
        return Ok(0);
    }
    let result = sqlx::query(
        "UPDATE locations l SET is_allowed = u.allowed, allow_rule_id = u.rule_id
         FROM UNNEST($1::uuid[], $2::bool[], $3::bigint[]) AS u(id, allowed, rule_id)
         WHERE l.id = u.id AND (l.is_allowed, l.allow_rule_id) IS DISTINCT FROM (u.allowed, u.rule_id)",
    )
    .bind(&ids)
    .bind(&allowed)
    .bind(&rule_ids)
    .execute(conn)
    .await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: i64, ty: Option<SourceType>, uri: &str, path: Option<&str>, env: Option<&str>) -> CompiledRule {
        CompiledRule::compile(id, ty, uri, path, env).unwrap_or_else(|e| panic!("{e}"))
    }

    fn subject<'a>(path: &'a str, env: Option<&'a str>) -> Subject<'a> {
        Subject { source_type: SourceType::GitRepo, uri: "https://git.example/infra/app", path, environment: env }
    }

    #[test]
    fn all_set_fields_must_match() {
        let r = rule(1, Some(SourceType::GitRepo), "https://git.example/infra/**", Some("deploy/**"), Some("prod"));
        assert!(r.matches(&subject("deploy/k8s/secret.yaml", Some("prod"))));
        assert!(!r.matches(&subject("deploy/k8s/secret.yaml", Some("dev"))));
        assert!(!r.matches(&subject("deploy/k8s/secret.yaml", None)), "env rule needs an env");
        assert!(!r.matches(&subject("src/main.rs", Some("prod"))));
        let fs = Subject { source_type: SourceType::Filesystem, ..subject("deploy/x", Some("prod")) };
        assert!(!r.matches(&fs));
        let any = rule(2, None, "**", None, None);
        assert!(any.matches(&fs));
    }

    #[test]
    fn lowest_id_wins() {
        let rules = [rule(9, None, "**", None, None), rule(3, None, "https://git.example/**", None, None)];
        assert_eq!(first_match(&rules, &subject("a", None)), Some(3));
        assert_eq!(first_match(&rules[..0], &subject("a", None)), None);
    }

    #[test]
    fn single_star_stays_in_one_segment() {
        let r = rule(1, None, "https://git.example/infra/*", Some("*.env"), None);
        assert!(r.matches(&subject("prod.env", None)));
        assert!(!r.matches(&subject("config/prod.env", None)));
    }
}
