//! The bearer token opens `/metrics` and nothing else, so a boot demands one only while
//! `/metrics` is gated. Each boot here stops at the first check after the token gate, a lifetime
//! above the ceiling, so reaching that refusal is proof the gate let the boot through.

#![allow(clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::Command;

const LIST_KEY_HEX: &str = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";
const PAST_THE_GATE: &str = "session_ttl_secs 3601";

/// One PPOI block with no token source at all, `global` appended to `[global]`.
fn tokenless_config(dir: &Path, global: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    let body = format!(
        r#"
[global]
bind = "127.0.0.1:0"
chain_id = 1
mirror_endpoint = "http://127.0.0.1:1"
session_ttl_secs = 3601
{global}

[[instance]]
id = "ppoi-paths-0"
role = "live"
encoder = "per-list-path10"
list_key = "{LIST_KEY_HEX}"
data_dir = "{data_dir}/ppoi-paths-0"
data_source = {{ kind = "mirror", list_key = "{LIST_KEY_HEX}", block = 0 }}
"#,
        data_dir = dir.display()
    );
    std::fs::write(&path, body).expect("write config");
    path
}

/// The binary's refusal, with no token in its environment.
fn boot_refusal(config: &Path, extra: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_raven-railgun"))
        .args(["serve-production", "--config"])
        .arg(config)
        .args(extra)
        .env_remove("RAVEN_BEARER_TOKEN")
        .output()
        .expect("run raven-railgun");
    assert!(!output.status.success(), "the fixture must not serve");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_public_metrics_endpoint_boots_with_no_bearer_token() {
    for (global, extra) in [
        ("metrics_public = true", &[][..]),
        ("", &["--metrics-public"][..]),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let stderr = boot_refusal(&tokenless_config(dir.path(), global), extra);
        assert!(
            stderr.contains(PAST_THE_GATE) && !stderr.contains("no bearer token"),
            "public /metrics ({global:?} {extra:?}) must boot past the token gate: {stderr}"
        );
        assert!(
            !dir.path().join("ppoi-paths-0").exists(),
            "a store was opened"
        );
    }
}

#[test]
fn a_gated_metrics_endpoint_refuses_to_boot_with_no_bearer_token() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stderr = boot_refusal(&tokenless_config(dir.path(), ""), &[]);
    for needle in [
        "no bearer token",
        "[global].token",
        "[global].token_file",
        "RAVEN_BEARER_TOKEN",
        "metrics_public",
    ] {
        assert!(
            stderr.contains(needle),
            "the refusal must name {needle}: {stderr}"
        );
    }
    assert!(!stderr.contains(PAST_THE_GATE), "{stderr}");
    assert!(
        !dir.path().join("ppoi-paths-0").exists(),
        "a store was opened"
    );
}
