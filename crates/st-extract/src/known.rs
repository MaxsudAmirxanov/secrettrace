//! Vendor credential formats with a fixed public structure.
//!
//! Patterns match the token body only; token boundaries are checked separately
//! (the `regex` crate has no look-around), so `xAKIA…` or an over-long run is rejected.

use std::sync::LazyLock;

use regex::Regex;
use st_core::SecretType;

use crate::Emitter;
use crate::candidate::{Detector, Hit};

/// Characters that continue a token: a match touching one of them on either side is
/// a fragment of something longer and is ignored.
#[derive(Debug, Clone, Copy)]
enum Class {
    Alnum,
    /// Alphanumerics and `_`.
    Word,
    /// Alphanumerics, `_` and `-`.
    WordDash,
}

impl Class {
    const fn contains(self, c: char) -> bool {
        match self {
            Self::Alnum => c.is_ascii_alphanumeric(),
            Self::Word => c.is_ascii_alphanumeric() || c == '_',
            Self::WordDash => c.is_ascii_alphanumeric() || c == '_' || c == '-',
        }
    }
}

#[derive(Debug)]
pub struct Rule {
    pub id: &'static str,
    ty: SecretType,
    pattern: &'static str,
    class: Class,
    /// Reject matches without a digit (cuts prose and identifiers for loose prefixes).
    needs_digit: bool,
}

const fn rule(id: &'static str, ty: SecretType, pattern: &'static str, class: Class) -> Rule {
    Rule { id, ty, pattern, class, needs_digit: false }
}

const fn rule_digit(id: &'static str, ty: SecretType, pattern: &'static str, class: Class) -> Rule {
    Rule { id, ty, pattern, class, needs_digit: true }
}

use Class::{Alnum, Word, WordDash};
use SecretType::{ApiKey, PrivateKey, Token};

/// Order matters: on identical spans the earlier (more specific) rule wins.
pub const RULES: &[Rule] = &[
    rule("aws_access_key_id", ApiKey, r"(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}", Alnum),
    rule("github_fine_grained_pat", Token, r"github_pat_[A-Za-z0-9_]{50,255}", Word),
    rule("github_token", Token, r"gh[pousr]_[A-Za-z0-9]{36,251}", Word),
    rule("gitlab_token", Token, r"gl(?:pat|ptt|rt|dt|cbt|ft|imt|soat|agent)-[A-Za-z0-9_\-]{20,255}", WordDash),
    rule("slack_token", Token, r"xox[abposre]-[A-Za-z0-9\-]{10,250}", WordDash),
    rule("slack_app_token", Token, r"xapp-[0-9]-[A-Za-z0-9\-]{10,250}", WordDash),
    rule(
        "slack_webhook",
        Token,
        r"https://hooks\.slack\.com/services/T[A-Z0-9]{6,12}/B[A-Z0-9]{6,12}/[A-Za-z0-9]{20,32}",
        Alnum,
    ),
    rule("stripe_key", ApiKey, r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,247}", Word),
    rule("stripe_webhook_secret", Token, r"whsec_[A-Za-z0-9+/]{32,128}", Word),
    rule("google_api_key", ApiKey, r"AIza[0-9A-Za-z_\-]{35}", WordDash),
    rule("google_oauth_client_secret", Token, r"GOCSPX-[0-9A-Za-z_\-]{28}", WordDash),
    rule("anthropic_api_key", ApiKey, r"sk-ant-(?:api|admin|oat)[0-9]{2}-[A-Za-z0-9_\-]{80,128}", WordDash),
    rule_digit("openai_api_key", ApiKey, r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,200}", WordDash),
    rule("npm_token", Token, r"npm_[A-Za-z0-9]{36}", Word),
    rule("pypi_token", Token, r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,255}", WordDash),
    rule("sendgrid_api_key", ApiKey, r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}", WordDash),
    rule_digit("twilio_api_key", ApiKey, r"SK[0-9a-f]{32}", Alnum),
    rule("digitalocean_token", Token, r"do[opr]_v1_[a-f0-9]{64}", Word),
    rule("vault_token", Token, r"hv[sb]\.[A-Za-z0-9_\-]{24,255}", WordDash),
    rule("huggingface_token", Token, r"hf_[A-Za-z]{34}", Word),
    rule("shopify_token", Token, r"shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}", Word),
    rule("telegram_bot_token", Token, r"[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}", WordDash),
    rule("age_secret_key", PrivateKey, r"AGE-SECRET-KEY-1[0-9A-Z]{58}", WordDash),
    rule("jwt", Token, r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*", WordDash),
];

#[allow(clippy::expect_used)] // static patterns, every one compiled by tests
static COMPILED: LazyLock<Vec<Regex>> =
    LazyLock::new(|| RULES.iter().map(|r| Regex::new(r.pattern).expect("valid known-format pattern")).collect());

fn bounded(text: &str, start: usize, end: usize, class: Class) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(|c| class.contains(c)) && !after.is_some_and(|c| class.contains(c))
}

pub(crate) fn scan(text: &str, em: &mut Emitter<'_, '_>) {
    for (rule, re) in RULES.iter().zip(COMPILED.iter()) {
        for m in re.find_iter(text) {
            if !bounded(text, m.start(), m.end(), rule.class) {
                continue;
            }
            if rule.needs_digit && !m.as_str().bytes().any(|b| b.is_ascii_digit()) {
                continue;
            }
            em.emit(&Hit::new(m.range(), rule.ty, Detector::Known).rule(rule.id), m.as_str());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_patterns_compile_and_ids_are_unique() {
        assert_eq!(COMPILED.len(), RULES.len());
        let mut ids: Vec<_> = RULES.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), RULES.len());
    }

    #[test]
    fn boundaries() {
        let key = "AKIAIOSFODNN7EXAMPLE";
        assert!(bounded(key, 0, key.len(), Alnum));
        let prefixed = format!("x{key}");
        assert!(!bounded(&prefixed, 1, prefixed.len(), Alnum));
        let quoted = format!("\"{key}\"");
        assert!(bounded(&quoted, 1, quoted.len() - 1, Alnum));
    }
}
