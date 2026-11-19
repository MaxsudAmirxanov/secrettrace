//! Structured logging.
//!
//! Rules enforced by convention and tests elsewhere:
//! * secrets are typed (`SecretString`, `Zeroizing`, `Digest`, `Fingerprint`) and their
//!   `Debug` output is redacted or truncated;
//! * request bodies, query strings and auth headers are never logged (see `app.rs`);
//! * filter via `ST_LOG` (default `info`).

use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

use crate::config::LogFormat;

const DEFAULT_FILTER: &str = "info,sqlx=warn,tower_http=info";

pub fn init(format: LogFormat) {
    let filter = EnvFilter::try_from_env("ST_LOG").unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER));
    let registry = tracing_subscriber::registry().with(filter);
    let result = match format {
        LogFormat::Json => registry
            .with(tracing_subscriber::fmt::layer().json().flatten_event(true).with_current_span(true))
            .try_init(),
        LogFormat::Pretty => registry.with(tracing_subscriber::fmt::layer().compact()).try_init(),
    };
    // A second init (e.g. in tests) is harmless.
    drop(result);
}
