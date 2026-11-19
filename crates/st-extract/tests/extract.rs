//! End-to-end extraction over realistic documents. Every fixture secret is synthetic
//! and assembled at runtime, so the repository itself stays clean for secret scanners.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use st_core::{Digest, SecretType, prepare};
use st_extract::{Candidate, Confidence, Config, Detector, Encoding, Extraction, Extractor, known_rules};

fn digest(ty: SecretType, value: &str) -> Digest {
    prepare(ty, value).expect("fixture value is valid").0
}

fn extract(text: &str) -> Extraction {
    Extractor::default().extract(text)
}

/// The candidate carrying `value`'s digest, asserting it was found.
fn found<'a>(ex: &'a Extraction, ty: SecretType, value: &str) -> &'a Candidate {
    let d = digest(ty, value);
    ex.candidates.iter().find(|c| c.digest == d).unwrap_or_else(|| {
        let summary: Vec<_> = ex.candidates.iter().map(|c| (c.detector, c.span.line, c.key.clone())).collect();
        panic!("{value:?} not found; candidates: {summary:?}")
    })
}

fn not_found(ex: &Extraction, ty: SecretType, value: &str) {
    let d = digest(ty, value);
    assert!(!ex.candidates.iter().any(|c| c.digest == d), "{value:?} unexpectedly found");
}

/// Deterministic filler so fixtures look random without being real credentials.
struct Gen(u64);

impl Gen {
    fn chars(&mut self, alphabet: &str, n: usize) -> String {
        let a: Vec<char> = alphabet.chars().collect();
        (0..n)
            .map(|_| {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                a[usize::try_from(self.0 % a.len() as u64).unwrap()]
            })
            .collect()
    }
}

const ALNUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const UPPER_DIGITS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const HEX: &str = "0123456789abcdef";
const URLSAFE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

fn aws_key() -> String {
    ["AK", "IA", "Z7X2Q4W8E6R1T3Y5"].concat()
}

fn pem(label: &str, g: &mut Gen) -> String {
    let body = g.chars(ALNUM, 64 * 3);
    let lines: Vec<&str> = (0..3).map(|i| &body[i * 64..(i + 1) * 64]).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

#[test]
fn every_known_rule_has_a_working_sample() {
    let mut g = Gen(0x5eed);
    let samples: Vec<(&str, String)> = vec![
        ("aws_access_key_id", aws_key()),
        ("github_fine_grained_pat", format!("github_pat_{}", g.chars(ALNUM, 82))),
        ("github_token", format!("gh{}_{}", "p", g.chars(ALNUM, 36))),
        ("gitlab_token", format!("glpat-{}", g.chars(ALNUM, 20))),
        ("slack_token", format!("xoxb-{}-{}", g.chars("0123456789", 12), g.chars(ALNUM, 24))),
        ("slack_app_token", format!("xapp-1-A{}-{}", g.chars(UPPER_DIGITS, 10), g.chars(HEX, 64))),
        (
            "slack_webhook",
            format!(
                "https://hooks.slack.com/services/T{}/B{}/{}",
                g.chars(UPPER_DIGITS, 8),
                g.chars(UPPER_DIGITS, 10),
                g.chars(ALNUM, 24)
            ),
        ),
        ("stripe_key", format!("sk_{}_{}", "live", g.chars(ALNUM, 24))),
        ("stripe_webhook_secret", format!("whsec_{}", g.chars(ALNUM, 32))),
        ("google_api_key", format!("AI{}{}", "za", g.chars(URLSAFE, 35))),
        ("google_oauth_client_secret", format!("GOCSPX-{}", g.chars(URLSAFE, 28))),
        ("anthropic_api_key", format!("sk-ant-api03-{}", g.chars(URLSAFE, 95))),
        ("openai_api_key", format!("sk-proj-{}9", g.chars(ALNUM, 40))),
        ("npm_token", format!("npm_{}", g.chars(ALNUM, 36))),
        ("pypi_token", format!("pypi-AgEIcHlwaS5vcmc{}", g.chars(URLSAFE, 60))),
        ("sendgrid_api_key", format!("SG.{}.{}", g.chars(URLSAFE, 22), g.chars(URLSAFE, 43))),
        ("twilio_api_key", format!("SK0{}", g.chars(HEX, 31))),
        ("digitalocean_token", format!("dop_v1_{}", g.chars(HEX, 64))),
        ("vault_token", format!("hvs.{}", g.chars(URLSAFE, 90))),
        ("huggingface_token", format!("hf_{}", g.chars("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 34))),
        ("shopify_token", format!("shpat_{}", g.chars(HEX, 32))),
        ("telegram_bot_token", format!("{}:AA{}", g.chars("123456789", 9), g.chars(URLSAFE, 33))),
        ("age_secret_key", format!("AGE-SECRET-KEY-1{}", g.chars(UPPER_DIGITS, 58))),
        ("jwt", format!("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.{}", g.chars(URLSAFE, 43))),
    ];
    let mut covered: Vec<&str> = samples.iter().map(|(id, _)| *id).collect();
    covered.sort_unstable();
    let mut all = known_rules();
    all.sort_unstable();
    assert_eq!(covered, all, "every rule needs a sample");

    for (id, sample) in &samples {
        let text = format!("value: {sample}\n");
        let ex = extract(&text);
        let d = digest(SecretType::Token, sample);
        let c = ex.candidates.iter().find(|c| c.digest == d).unwrap_or_else(|| panic!("{id}: {sample} not found"));
        assert_eq!(c.rule, Some(*id), "{sample}");
        assert_eq!(c.detector, Detector::Known);
        assert_eq!(c.confidence, Confidence::High);
        assert_eq!(&text[c.span.start..c.span.end], sample.as_str());

        // Glued to a longer token, it is a fragment and must not be reported as that rule.
        let glued = format!("value: Z{sample}Z\n");
        let ex = extract(&glued);
        assert!(!ex.candidates.iter().any(|c| c.rule == Some(*id) && c.digest == d), "{id} glued");
    }
}

#[test]
fn dotenv_file() {
    let aws = aws_key();
    let text = format!(
        "# app settings\n\
         DB_PASSWORD=hunter2hunter2\n\
         export API_TOKEN=\"tok-3c1b9e0f-plain\"\n\
         AWS_ACCESS_KEY_ID={aws}\n\
         AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n\
         DATABASE_URL=postgres://app:p%40ss%2Fw0rd@db.internal:5432/app?sslmode=require\n\
         EMPTY=\n\
         FROM_ENV=${{SECRET_FROM_VAULT}}\n\
         SMTP_PASSWORD=   \n"
    );
    let ex = extract(&text);
    assert!(!ex.truncated);

    let c = found(&ex, SecretType::Password, "hunter2hunter2");
    assert_eq!(
        (c.detector, c.secret_type, c.key.as_deref()),
        (Detector::KeyValue, SecretType::Password, Some("DB_PASSWORD"))
    );
    assert_eq!((c.span.line, c.span.column), (2, 13));
    assert_eq!(&text[c.span.start..c.span.end], "hunter2hunter2");
    assert_eq!(c.masked, "••••••••");

    let c = found(&ex, SecretType::Token, "tok-3c1b9e0f-plain");
    assert_eq!(c.key.as_deref(), Some("API_TOKEN"));

    let c = found(&ex, SecretType::ApiKey, &aws);
    assert_eq!((c.rule, c.masked.as_str()), (Some("aws_access_key_id"), "AKIA…"));

    let c = found(&ex, SecretType::ApiKey, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    assert_eq!((c.detector, c.secret_type), (Detector::KeyValue, SecretType::ApiKey));

    let url = "postgres://app:p%40ss%2Fw0rd@db.internal:5432/app?sslmode=require";
    let c = found(&ex, SecretType::DbConnectionString, url);
    // The URL detector runs before key=value, so it names the candidate.
    assert_eq!((c.detector, c.secret_type), (Detector::Url, SecretType::DbConnectionString));
    let c = found(&ex, SecretType::Password, "p@ss/w0rd");
    assert_eq!((c.detector, c.encodings.as_slice()), (Detector::UrlPassword, [Encoding::Percent].as_slice()));
    found(&ex, SecretType::Password, "p%40ss%2Fw0rd");

    not_found(&ex, SecretType::Token, "${SECRET_FROM_VAULT}");
}

#[test]
fn kubernetes_secret_with_nested_encodings() {
    let mut g = Gen(7);
    let key_pem = pem("RSA PRIVATE KEY", &mut g);
    let config_json = r#"{"db":{"host":"db","password":"n3st3d-Passw0rd"}}"#;
    let text = format!(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\ndata:\n  password: {}\n  config.json: {}\n  tls.key: {}\nstringData:\n  api-key: \"plainApiKeyValue123\"\n",
        B64.encode("hunter2hunter2"),
        B64.encode(config_json),
        B64.encode(&key_pem),
    );
    let ex = extract(&text);

    let c = found(&ex, SecretType::Password, "hunter2hunter2");
    assert_eq!((c.key.as_deref(), c.encodings.as_slice()), (Some("password"), [Encoding::Base64].as_slice()));
    assert_eq!(c.span.line, 6);

    let c = found(&ex, SecretType::Password, "n3st3d-Passw0rd");
    assert_eq!(c.encodings, [Encoding::Base64]);
    assert_eq!(c.key.as_deref(), Some("password"));
    assert_eq!(c.span.line, 7, "span points at the encoded container");

    let c = found(&ex, SecretType::PrivateKey, &key_pem);
    assert_eq!(
        (c.detector, c.secret_type, c.encodings.as_slice()),
        (Detector::Pem, SecretType::PrivateKey, [Encoding::Base64].as_slice())
    );
    assert_eq!(c.span.line, 8);

    found(&ex, SecretType::ApiKey, "plainApiKeyValue123");
}

#[test]
fn docker_config_and_http_headers() {
    let mut g = Gen(11);
    let ghp = format!("gh{}_{}", "p", g.chars(ALNUM, 36));
    let docker =
        format!(r#"{{"auths":{{"registry.example.com":{{"auth":"{}"}}}}}}"#, B64.encode("deploy:R3gistry-Passw0rd"));
    let log = format!(
        "{docker}\n+ curl -H \"Authorization: Bearer {ghp}\" https://api.example.com\n+ curl -H 'Authorization: Basic {}' https://x\n",
        B64.encode("ci:Basic-Passw0rd!")
    );
    let ex = extract(&log);

    let c = found(&ex, SecretType::Password, "R3gistry-Passw0rd");
    assert_eq!((c.detector, c.encodings.as_slice()), (Detector::BasicAuth, [Encoding::Base64].as_slice()));
    let c = found(&ex, SecretType::Token, &ghp);
    assert_eq!(c.rule, Some("github_token"), "known format wins over the header detector");
    let c = found(&ex, SecretType::Password, "Basic-Passw0rd!");
    assert_eq!(c.detector, Detector::BasicAuth);
    assert_eq!(c.span.line, 3);
}

#[test]
fn source_code_and_tool_formats() {
    let text = r#"
conn = psycopg2.connect("dbname=app password=codePassw0rd host=db")
if (password == "cmpPassw0rd") { login() }
const cfg = { clientSecret: 'cl1ent-s3cret-value', timeout: 30 };
mysql --user root --password 'flagPassw0rd' app
<connection><password>xmlPassw0rd</password></connection>
machine git.example.com login bot password netrcPassw0rd
Server=sql;User Id=sa;Password=AdoNetPassw0rd;Encrypt=true
jdbc:postgresql://svc:jdbcPassw0rd@db:5432/app
password = os.environ["DB_PASSWORD"]
token: {{ .Values.token }}
"#;
    let ex = extract(text);
    for (value, line) in [
        ("codePassw0rd", 2),
        ("cmpPassw0rd", 3),
        ("flagPassw0rd", 5),
        ("xmlPassw0rd", 6),
        ("netrcPassw0rd", 7),
        ("AdoNetPassw0rd", 8),
        ("jdbcPassw0rd", 9),
    ] {
        let c = found(&ex, SecretType::Password, value);
        assert_eq!(c.span.line, line, "{value}");
    }
    found(&ex, SecretType::Token, "cl1ent-s3cret-value");
    found(&ex, SecretType::DbConnectionString, "jdbc:postgresql://svc:jdbcPassw0rd@db:5432/app");
    found(&ex, SecretType::DbConnectionString, "postgresql://svc:jdbcPassw0rd@db:5432/app");
    not_found(&ex, SecretType::Password, "os.environ[");
    let typed = extract("pub database_password: SecretString,\n");
    let c = found(&typed, SecretType::Password, "SecretString");
    assert_eq!(c.confidence, Confidence::Low, "identifier-like values are digested but not trusted");
    not_found(&ex, SecretType::Token, "{{ .Values.token }}");
}

#[test]
fn escaped_json_and_pem_variants() {
    let mut g = Gen(23);
    let key = pem("PRIVATE KEY", &mut g);
    let escaped_key = key.replace('\n', "\\n");
    let sa = format!(
        r#"{{"type":"service_account","private_key_id":"0a1b2c","private_key":"{escaped_key}","client_email":"svc@example.iam"}}"#
    );
    let log_line = r#"{"level":"info","body":"{\"user\":\"bob\",\"password\":\"escPassw0rd\"}"}"#;
    let cert = pem("CERTIFICATE", &mut g);
    let yaml = format!("tls:\n  key: |\n{}", key.lines().map(|l| ["    ", l, "\n"].concat()).collect::<String>());
    let ssh = format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{} ops@bastion", g.chars(ALNUM, 43));
    let text = [sa.as_str(), log_line, &cert, &yaml, &ssh].join("\n");
    let ex = extract(&text);

    let hits: Vec<_> = ex.candidates.iter().filter(|c| c.digest == digest(SecretType::PrivateKey, &key)).collect();
    assert_eq!(hits.len(), 2, "escaped JSON and indented YAML copies, each reported once");
    assert!(hits.iter().all(|c| c.detector == Detector::Pem && c.confidence == Confidence::High));

    let c = found(&ex, SecretType::Password, "escPassw0rd");
    assert_eq!(c.encodings, [Encoding::JsonString]);
    assert_eq!(c.span.line, 2);

    let c = found(&ex, SecretType::Certificate, &cert);
    assert_eq!((c.secret_type, c.confidence), (SecretType::Certificate, Confidence::Low));
    let c = found(&ex, SecretType::SshKey, &ssh);
    assert_eq!(c.detector, Detector::SshPublicKey);

    // `private_key_id` is metadata, not a secret.
    assert!(!ex.candidates.iter().any(|c| c.key.as_deref() == Some("private_key_id")));
}

#[test]
fn context_free_random_tokens() {
    let text = "x = \"Zq8vN3kLmP0rT5wY2bC7dF1g\"\nhash 3f9a1c0e7b2d4a6f8e0c1b3d5f7a9c2e\nhttps://hooks.example.com/hook/Q7mZ2xK9pL4vB8nR1tY6\n";
    let ex = extract(text);
    for v in ["Zq8vN3kLmP0rT5wY2bC7dF1g", "3f9a1c0e7b2d4a6f8e0c1b3d5f7a9c2e", "Q7mZ2xK9pL4vB8nR1tY6"] {
        let c = found(&ex, SecretType::Other, v);
        assert_eq!((c.detector, c.confidence), (Detector::HighEntropy, Confidence::Low), "{v}");
    }

    let off = Extractor::new(Config { entropy: false, ..Config::default() }).extract(text);
    assert!(off.candidates.is_empty());
}

#[test]
fn prose_and_ordinary_config_are_quiet() {
    let text = "The password reset flow sends a token by email.\n\
                timeout: 30\nretries=5\nlog_level: debug\nname = \"payments-service\"\n\
                password_min_length = 12\ntoken_uri: https://oauth2.example.com/token\n";
    let ex = extract(text);
    assert!(ex.candidates.is_empty(), "{:?}", ex.candidates);
}

#[test]
fn output_never_contains_plaintext_or_digests() {
    let mut g = Gen(99);
    let ghp = format!("gh{}_{}", "p", g.chars(ALNUM, 36));
    let text = format!("DB_PASSWORD=hunter2hunter2\nGITHUB_TOKEN={ghp}\nurl=redis://:r3dis-Passw0rd@cache:6379\n");
    let ex = extract(&text);
    assert!(ex.candidates.len() >= 3);
    let json = serde_json::to_string(&ex.candidates).unwrap();
    let debug = format!("{:?}", ex.candidates);
    for leak in ["hunter2hunter2", ghp.as_str(), &ghp[4..20], "r3dis-Passw0rd"] {
        assert!(!json.contains(leak), "JSON leaks {leak}");
        assert!(!debug.contains(leak), "Debug leaks {leak}");
    }
    let d = digest(SecretType::Password, "hunter2hunter2").to_hex();
    assert!(!json.contains(&d) && !debug.contains(&d), "digest leaked");
    assert!(!json.contains("\"digest\""));
    let c = found(&ex, SecretType::Token, &ghp);
    assert_eq!(c.masked, format!("ghp_…{}", &ghp[ghp.len() - 4..]));
}

#[test]
fn limits_are_enforced() {
    let many: String = (0..100).fold(String::new(), |mut acc, i| {
        use std::fmt::Write as _;
        let _ = writeln!(acc, "password{i}=value-number-{i:04}");
        acc
    });
    let ex = Extractor::new(Config { max_candidates: 10, ..Config::default() }).extract(&many);
    assert_eq!(ex.candidates.len(), 10);
    assert!(ex.truncated);

    let ex = Extractor::new(Config { max_input_bytes: 40, ..Config::default() }).extract(&many);
    assert!(ex.truncated);
    assert!(ex.candidates.iter().all(|c| c.span.end <= 40));

    // Base64 nested five times is only unwrapped up to max_depth.
    let mut nested = "password=deepPassw0rd".to_owned();
    for _ in 0..5 {
        nested = B64.encode(nested);
    }
    let ex = Extractor::new(Config { max_depth: 3, ..Config::default() }).extract(&nested);
    not_found(&ex, SecretType::Password, "deepPassw0rd");
    let ex = Extractor::new(Config { max_depth: 5, ..Config::default() }).extract(&nested);
    let c = found(&ex, SecretType::Password, "deepPassw0rd");
    assert_eq!(c.encodings, [Encoding::Base64; 5]);
}

#[test]
fn pathological_inputs_finish_quickly() {
    let inputs = [
        "a".repeat(1 << 20),
        "password=".repeat(100_000),
        "\"\\".repeat(200_000),
        "-----BEGIN PRIVATE KEY-----\n".repeat(20_000),
        "x://u:p@".repeat(50_000),
        format!("{{\"a\":\"{}\"}}", "\\\"".repeat(200_000)),
        "QUFBQUFB".repeat(100_000),
    ];
    let start = std::time::Instant::now();
    for input in &inputs {
        let ex = extract(input);
        assert!(ex.candidates.len() <= Config::default().max_candidates);
    }
    // Generous bound for unoptimized CI builds; the point is "linear", not a benchmark.
    assert!(start.elapsed() < std::time::Duration::from_secs(60), "took {:?}", start.elapsed());
}

#[test]
fn random_inputs_never_panic_and_spans_are_valid() {
    const PIECES: &[&str] = &[
        "password",
        "=",
        ":",
        "\"",
        "'",
        "\\",
        "\\\"",
        "%",
        "%4",
        "%41",
        "://",
        "@",
        "-----BEGIN ",
        "-----END ",
        "PRIVATE KEY-----",
        "AKIA",
        "ghp_",
        "eyJ",
        ".",
        "\n",
        " ",
        "é",
        "😀",
        "==",
        "QUJD",
        "Basic ",
        "Bearer ",
        "<password>",
        "</password>",
        "--token ",
        "\\n",
        "\\u00",
        "aGVsbG8gd29ybGQ=",
        "${X}",
        "{{",
        "Zq8vN3kLmP0rT5wY",
    ];
    let mut g = Gen(0xdead_beef);
    for _ in 0..2_000 {
        let n = usize::try_from(g.0 % 40).unwrap() + 1;
        let mut text = String::new();
        for _ in 0..n {
            let idx = g.chars("0123456789abcdefghijklmnopqrstuvwxyz", 1);
            let i = usize::from(idx.as_bytes()[0]) % PIECES.len();
            text.push_str(PIECES[i]);
        }
        let ex = extract(&text);
        for c in &ex.candidates {
            assert!(c.span.start <= c.span.end && c.span.end <= text.len());
            assert!(text.is_char_boundary(c.span.start) && text.is_char_boundary(c.span.end));
        }
    }
}
