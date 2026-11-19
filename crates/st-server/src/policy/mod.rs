//! Allow rules: glob patterns and their evaluation against locations.

pub mod allow;
pub mod glob;

pub use allow::{CompiledRule, Subject, first_match, load_rules, reevaluate};
pub use glob::{Glob, GlobError};
