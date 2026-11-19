//! Allow-rule evaluation (matching is wired into ingest in stage 8).

pub mod glob;

pub use glob::{Glob, GlobError};
