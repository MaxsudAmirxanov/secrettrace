//! Extractors whose rejections are RFC 7807 problems instead of axum's plain text.

use axum::extract::FromRequest;
use axum::extract::FromRequestParts;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};

use crate::error::ApiError;

/// JSON body. Malformed JSON → 400, schema violations → 422, oversized → 413.
#[derive(Debug, FromRequest)]
#[from_request(via(axum::Json), rejection(ApiError))]
pub struct ApiJson<T>(pub T);

#[derive(Debug, FromRequestParts)]
#[from_request(via(axum::extract::Query), rejection(ApiError))]
pub struct ApiQuery<T>(pub T);

#[derive(Debug, FromRequestParts)]
#[from_request(via(axum::extract::Path), rejection(ApiError))]
pub struct ApiPath<T>(pub T);

impl From<JsonRejection> for ApiError {
    fn from(r: JsonRejection) -> Self {
        match r {
            // serde names the field and the expected type, but also quotes the offending input
            // (`unknown variant `…``, `invalid type: string "…"`); that input may be a secret
            // sent by mistake, so it is cut out before the message reaches client or logs.
            JsonRejection::JsonDataError(e) => Self::Unprocessable(redact_input(&e.body_text())),
            JsonRejection::JsonSyntaxError(_) => Self::BadRequest("request body is not valid JSON".into()),
            JsonRejection::MissingJsonContentType(_) => Self::UnsupportedMediaType,
            JsonRejection::BytesRejection(e) if e.status() == axum::http::StatusCode::PAYLOAD_TOO_LARGE => {
                Self::PayloadTooLarge
            }
            other => Self::BadRequest(other.body_text()),
        }
    }
}

impl From<QueryRejection> for ApiError {
    fn from(r: QueryRejection) -> Self {
        Self::BadRequest(r.body_text())
    }
}

impl From<PathRejection> for ApiError {
    fn from(_: PathRejection) -> Self {
        Self::NotFound
    }
}

/// How serde quotes submitted input, and what to keep of it.
#[derive(Clone, Copy)]
enum Quote {
    /// A backticked value up to "`, expected" or "`, there are no": drop the value.
    Backticked,
    /// `string "value"` or an integer up to ", expected": keep only the kind word.
    Kind,
    /// Anything up to ", expected": drop it.
    Value,
}

const QUOTED_INPUT: &[(&str, Quote)] = &[
    ("unknown variant `", Quote::Backticked),
    ("unknown field `", Quote::Backticked),
    ("invalid type: ", Quote::Kind),
    ("invalid value: ", Quote::Value),
];

/// What axum puts before the `path: message` part of a JSON data error.
const PATH_PREFIX: &str = "into the target type: ";

/// Where the field path of a serde error ends and the message begins.
const MESSAGE_STARTS: &[&str] = &[
    ": unknown field `",
    ": unknown variant `",
    ": invalid type: ",
    ": invalid value: ",
    ": invalid length ",
    ": missing field `",
    ": duplicate field `",
];

/// Replace input echoed in a serde error with `…`, keeping the expected type or variants
/// and the parts of the field path that are schema field names. The path itself can carry
/// input: the unknown key of an `unknown field` error, map keys (`stats.<key>`).
fn redact_input(message: &str) -> String {
    let message = redact_path(message);
    let mut out = String::with_capacity(message.len());
    let mut rest = message.as_str();
    loop {
        let next = QUOTED_INPUT.iter().filter_map(|&(m, q)| rest.find(m).map(|i| (i, m, q))).min_by_key(|&(i, ..)| i);
        let Some((i, marker, quote)) = next else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..i + marker.len()]);
        let after = &rest[i + marker.len()..];
        let end = match quote {
            Quote::Backticked => ["`, expected", "`, there are no"].iter().filter_map(|e| after.find(e)).min(),
            Quote::Kind | Quote::Value => after.find(", expected"),
        };
        let Some(end) = end else {
            out.push('…');
            return out;
        };
        match quote {
            Quote::Kind => {
                let kind =
                    after[..end].split_whitespace().next().filter(|w| w.bytes().all(|b| b.is_ascii_alphabetic()));
                out.push_str(kind.unwrap_or("…"));
            }
            Quote::Backticked | Quote::Value => out.push('…'),
        }
        rest = &after[end..];
    }
}

fn redact_path(message: &str) -> String {
    let start = message.find(PATH_PREFIX).map_or(0, |i| i + PATH_PREFIX.len());
    let Some((end, marker)) =
        MESSAGE_STARTS.iter().filter_map(|m| message[start..].find(m).map(|i| (start + i, *m))).min_by_key(|&(i, _)| i)
    else {
        return message.to_owned();
    };
    let path = &message[start..end];
    let mut segments: Vec<String> =
        path.split('.').map(|seg| if is_field_segment(seg) { seg.to_owned() } else { "…".to_owned() }).collect();
    if marker == ": unknown field `"
        && let Some(last) = segments.last_mut()
    {
        // The last segment is the unknown key itself.
        "…".clone_into(last);
    }
    format!("{}{}{}", &message[..start], segments.join("."), &message[end..])
}

/// A struct field name, optionally indexed: `findings[3]`, `allow_rules`, `[0]`.
fn is_field_segment(seg: &str) -> bool {
    let name_end = seg.find('[').unwrap_or(seg.len());
    let (name, indices) = seg.split_at(name_end);
    let name_ok = name.is_empty() && !indices.is_empty()
        || (1..=32).contains(&name.len())
            && name.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
            && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    let indices_ok = indices.split_inclusive(']').all(|ix| {
        ix.strip_prefix('[')
            .and_then(|i| i.strip_suffix(']'))
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    });
    name_ok && indices_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echoed_input_is_redacted() {
        let cases = [
            (
                "Failed to deserialize the JSON body into the target type: findings[0].detector: unknown variant \
                 `ghp_SECRET`, expected one of `known`, `pem` at line 1 column 40",
                "Failed to deserialize the JSON body into the target type: findings[0].detector: unknown variant \
                 `…`, expected one of `known`, `pem` at line 1 column 40",
            ),
            (
                "source: unknown field `hunter2`, expected `type` or `uri`",
                "…: unknown field `…`, expected `type` or `uri`",
            ),
            ("x: unknown variant `s3cr3t`, there are no variants", "x: unknown variant `…`, there are no variants"),
            (
                "findings[1].line: invalid type: string \"p@ssw0rd\", expected u32 at line 1 column 9",
                "findings[1].line: invalid type: string, expected u32 at line 1 column 9",
            ),
            ("a: invalid type: integer `-5`, expected u32", "a: invalid type: integer, expected u32"),
            ("a: invalid value: integer `-5`, expected u32", "a: invalid value: …, expected u32"),
            ("a: invalid length 0, expected 32 bytes", "a: invalid length 0, expected 32 bytes"),
            ("a: unknown variant `never closed", "a: unknown variant `…"),
            ("a: invalid type: string \"x, b: invalid type: string \"y", "a: invalid type: …"),
            ("missing field `digest` at line 1 column 2", "missing field `digest` at line 1 column 2"),
            (
                "into the target type: MARKER_q7Zx: unknown field `…`, expected one of `owner`",
                "into the target type: …: unknown field `…`, expected one of `owner`",
            ),
            (
                "into the target type: source.hunter2: unknown field `hunter2`, expected `type`",
                "into the target type: source.…: unknown field `…`, expected `type`",
            ),
            (
                "into the target type: stats.ghp_AbC9: invalid type: string \"x\", expected u64",
                "into the target type: stats.…: invalid type: string, expected u64",
            ),
            (
                "into the target type: findings[12].line: invalid type: string \"x\", expected u32",
                "into the target type: findings[12].line: invalid type: string, expected u32",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(redact_input(input), expected);
        }
    }

    #[test]
    fn field_segments() {
        for ok in ["findings[3]", "allow_rules", "[0]", "a[1][2]", "line"] {
            assert!(is_field_segment(ok), "{ok}");
        }
        for bad in ["ghp_AbC", "", "a[]", "a[x]", "hunter 2", "x]"] {
            assert!(!is_field_segment(bad), "{bad}");
        }
    }

    #[test]
    fn real_serde_errors_do_not_echo_input() {
        #[derive(Debug, serde::Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "snake_case")]
        #[allow(dead_code)]
        enum Kind {
            Known,
            Pem,
        }
        #[derive(Debug, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct Body {
            kind: Kind,
            line: Option<u32>,
        }
        for body in [
            r#"{"kind":"ghp_LEAKED123"}"#,
            r#"{"kind":"pem","line":"ghp_LEAKED123"}"#,
            r#"{"kind":"pem","ghp_LEAKED123":1}"#,
            r#"{"kind":"pem","line":-1}"#,
        ] {
            let err = serde_json::from_str::<Body>(body).err().map(|e| e.to_string()).unwrap_or_default();
            assert!(!err.is_empty(), "{body} must fail");
            let redacted = redact_input(&err);
            assert!(!redacted.contains("LEAKED") && !redacted.contains("-1"), "{err} → {redacted}");
        }
    }
}
