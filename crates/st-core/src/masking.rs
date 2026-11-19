//! Human-readable masked representation built **only** from stored hints,
//! never from a value. Safe to show in UI, alerts and logs.

use crate::Hints;

const BULLETS: &str = "••••••••";

#[must_use]
pub fn mask(hints: &Hints) -> String {
    match (hints.prefix.as_deref(), hints.suffix.as_deref()) {
        (Some(p), Some(s)) => format!("{p}…{s}"),
        (Some(p), None) => format!("{p}…"),
        // Validation forbids a suffix without a prefix; stay conservative anyway.
        (None, _) => BULLETS.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks() {
        let full = Hints { prefix: Some("ghp_".into()), suffix: Some("Q2X7".into()), length: Some(40) };
        assert_eq!(mask(&full), "ghp_…Q2X7");
        let prefix_only = Hints { prefix: Some("AKIA".into()), suffix: None, length: Some(20) };
        assert_eq!(mask(&prefix_only), "AKIA…");
        assert_eq!(mask(&Hints::default()), "••••••••");
        let suffix_only = Hints { prefix: None, suffix: Some("abcd".into()), length: None };
        assert_eq!(mask(&suffix_only), "••••••••");
    }
}
