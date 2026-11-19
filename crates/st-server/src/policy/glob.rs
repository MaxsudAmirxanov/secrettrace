//! Minimal, predictable glob syntax for allow-rules:
//!
//! | token | matches |
//! |---|---|
//! | `**/` | empty, or any sequence ending in `/` (`a/**/b` matches `a/b` and `a/x/y/b`) |
//! | `**`  | any sequence, including `/` |
//! | `*`   | any sequence without `/` |
//! | `?`   | one character except `/` |
//! | `\x`  | the literal character `x` |
//!
//! Everything else is literal and case-sensitive. Matching is a linear-space DP
//! (no regex, no exponential backtracking), bounded by pattern/text length limits.

use std::fmt;

pub const MAX_PATTERN_LEN: usize = 512;
pub const MAX_TEXT_LEN: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Literal(char),
    AnyChar,
    Star,
    DoubleStar,
    /// `**/`: empty or any sequence ending with `/`.
    DoubleStarSlash,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Glob {
    source: String,
    tokens: Vec<Token>,
}

impl fmt::Debug for Glob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Glob({:?})", self.source)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GlobError {
    #[error("pattern is empty")]
    Empty,
    #[error("pattern is longer than {MAX_PATTERN_LEN} bytes")]
    TooLong,
    #[error("pattern contains control characters")]
    ControlChar,
    #[error("pattern ends with an unfinished escape `\\`")]
    DanglingEscape,
}

impl Glob {
    pub fn parse(pattern: &str) -> Result<Self, GlobError> {
        if pattern.is_empty() {
            return Err(GlobError::Empty);
        }
        if pattern.len() > MAX_PATTERN_LEN {
            return Err(GlobError::TooLong);
        }
        if pattern.chars().any(char::is_control) {
            return Err(GlobError::ControlChar);
        }
        let mut tokens = Vec::new();
        let mut chars = pattern.chars().peekable();
        while let Some(c) = chars.next() {
            let token = match c {
                '\\' => Token::Literal(chars.next().ok_or(GlobError::DanglingEscape)?),
                '?' => Token::AnyChar,
                '*' if chars.peek() == Some(&'*') => {
                    chars.next();
                    // Collapse runs like `***` into one `**`.
                    while chars.peek() == Some(&'*') {
                        chars.next();
                    }
                    if chars.peek() == Some(&'/') {
                        chars.next();
                        Token::DoubleStarSlash
                    } else {
                        Token::DoubleStar
                    }
                }
                '*' => Token::Star,
                other => Token::Literal(other),
            };
            tokens.push(token);
        }
        Ok(Self { source: pattern.to_owned(), tokens })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.source
    }

    #[must_use]
    pub fn matches(&self, text: &str) -> bool {
        if text.len() > MAX_TEXT_LEN {
            return false;
        }
        let text: Vec<char> = text.chars().collect();
        // prev[j]: tokens[..i] match text[..j]
        let mut prev = vec![false; text.len() + 1];
        prev[0] = true;
        for token in &self.tokens {
            let mut cur = vec![false; text.len() + 1];
            match token {
                Token::Star | Token::DoubleStar => {
                    let crosses_slash = matches!(token, Token::DoubleStar);
                    cur[0] = prev[0];
                    for j in 1..=text.len() {
                        cur[j] = prev[j] || (cur[j - 1] && (crosses_slash || text[j - 1] != '/'));
                    }
                }
                Token::DoubleStarSlash => {
                    let mut reachable = false; // some prev[k] with k < j
                    cur[0] = prev[0];
                    for j in 1..=text.len() {
                        reachable |= prev[j - 1];
                        cur[j] = prev[j] || (reachable && text[j - 1] == '/');
                    }
                }
                Token::AnyChar => {
                    for j in 1..=text.len() {
                        cur[j] = prev[j - 1] && text[j - 1] != '/';
                    }
                }
                Token::Literal(c) => {
                    for j in 1..=text.len() {
                        cur[j] = prev[j - 1] && text[j - 1] == *c;
                    }
                }
            }
            prev = cur;
        }
        prev[text.len()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(p: &str, t: &str) -> bool {
        Glob::parse(p).map(|g| g.matches(t)).unwrap_or(false)
    }

    #[test]
    fn literals_and_wildcards() {
        assert!(m("git@github.com:me/infra.git", "git@github.com:me/infra.git"));
        assert!(!m("git@github.com:me/infra.git", "git@github.com:me/infra.gi"));
        assert!(m("git@github.com:me/*", "git@github.com:me/infra.git"));
        assert!(!m("git@github.com:me/*", "git@github.com:me/a/b.git"));
        assert!(m("git@github.com:me/**", "git@github.com:me/a/b.git"));
        assert!(m("k8s/**/secret.yaml", "k8s/prod/eu/secret.yaml"));
        assert!(m("k8s/**/secret.yaml", "k8s/secret.yaml"));
        assert!(!m("k8s/**/secret.yaml", "k8s/xsecret.yaml"));
        assert!(m("**/.env", ".env"));
        assert!(m("**/.env", "svc/api/.env"));
        assert!(!m("**/.env", "svc/api.env"));
        assert!(m("host:web-0?", "host:web-01"));
        assert!(!m("host:web-0?", "host:web-0/"));
        assert!(m("*", ""));
        assert!(m("**", "any/thing/at/all"));
        assert!(!m("a", "A"), "case-sensitive");
    }

    #[test]
    fn escapes() {
        assert!(m(r"file\*.env", "file*.env"));
        assert!(!m(r"file\*.env", "fileX.env"));
        assert!(m(r"a\\b", r"a\b"));
    }

    #[test]
    fn no_pathological_blowup() {
        let pattern = "*a".repeat(100) + "b";
        let text = "a".repeat(4000);
        assert!(!m(&pattern, &text));
    }

    #[test]
    fn parse_errors() {
        assert_eq!(Glob::parse(""), Err(GlobError::Empty));
        assert_eq!(Glob::parse("abc\\"), Err(GlobError::DanglingEscape));
        assert_eq!(Glob::parse("a\nb"), Err(GlobError::ControlChar));
        assert_eq!(Glob::parse(&"a".repeat(513)), Err(GlobError::TooLong));
    }
}
