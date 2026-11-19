//! Cross-implementation test vectors (`testdata/digest_vectors.json`).
//! The same file is consumed by the web client tests so browser-side registration
//! and Rust scanners always agree.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde::Deserialize;
use st_core::{Hints, SecretType, digest_normalized, normalize, prepare};

#[derive(Deserialize)]
struct File {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    #[serde(rename = "type")]
    secret_type: SecretType,
    raw: String,
    canonical: String,
    digest: String,
    hints: Hints,
}

#[test]
fn shared_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/digest_vectors.json");
    let file: File = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert!(!file.vectors.is_empty());

    for v in &file.vectors {
        let canonical = normalize(v.secret_type, &v.raw).unwrap();
        assert_eq!(canonical.as_str(), v.canonical, "canonical for {:?}", v.raw);
        assert_eq!(digest_normalized(&canonical).to_hex(), v.digest, "digest for {:?}", v.raw);

        let (digest, hints) = prepare(v.secret_type, &v.raw).unwrap();
        assert_eq!(digest.to_hex(), v.digest);
        assert_eq!(hints, v.hints, "hints for {:?}", v.raw);
    }
}
