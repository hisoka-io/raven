//! A config key is applied or refused by name; none is accepted and dropped.

#![allow(clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::Path;
use std::process::Command;

use raven_railgun_cli::rpc_pool_array_config::RpcEndpointArrayConfig;
use raven_railgun_cli::serve_production_multi::load_options_from_toml;

const LIST_KEY: &str = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";

/// Every table the loader declares, each with a `#@<table>@` slot for an injected line.
fn multi_instance_config() -> String {
    format!(
        r#"
#@top@
[global]
bind = "127.0.0.1:0"
token = "unknown-key-test-token-padded-long"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"
#@global@

[auto_spawn]
enabled = true
data_dir_template = "/tmp/raven-unused/commit-tree-{{tree_number}}"
encoder = "per-node"
scheme_tag = "test"
#@auto_spawn@

[rpc_pool]
urls = ["http://127.0.0.1:1"]
#@rpc_pool@

[[instance_template]]
template_id = "chain"
encoder = "per-node"
data_dir_template = "/tmp/raven-unused/template-{{tree_number}}"
#@instance_template@

[[instance]]
id = "commit-tree-0"
role = "live"
encoder = "per-node"
tree_number = 0
data_dir = "/tmp/raven-unused/commit-tree-0"
#@instance@
[instance.data_source]
kind = "indexer"
#@indexer@
[instance.data_source.filter]
tree_number = 0
#@filter@

[[instance]]
id = "ppoi-paths-0"
role = "live"
encoder = "per-list-path10"
list_key = "{LIST_KEY}"
data_dir = "/tmp/raven-unused/ppoi-paths-0"
[instance.data_source]
kind = "mirror"
list_key = "{LIST_KEY}"
block = 0
#@mirror@
"#
    )
}

fn load(body: &str) -> anyhow::Result<()> {
    // NamedTempFile is 0600, which the inline token requires.
    let mut file = tempfile::NamedTempFile::new().expect("tempfile");
    file.write_all(body.as_bytes()).expect("write config");
    load_options_from_toml(file.path()).map(|_| ())
}

/// Every case is tried before any is reported, so one run lists every table that leaks.
fn assert_each_refused_by_name(
    base: &str,
    cases: &[(&str, &str, &str)],
    load_body: impl Fn(&str) -> Result<(), String>,
) {
    let mut leaks = Vec::new();
    for (slot, line, key) in cases {
        assert_eq!(base.matches(slot).count(), 1, "slot {slot} must be unique");
        match load_body(&base.replace(slot, line)) {
            Ok(()) => leaks.push(format!("`{line}` was accepted")),
            Err(message) if !message.contains(&format!("`{key}`")) => {
                leaks.push(format!("`{line}` was refused without naming it: {message}"));
            }
            Err(_) => {}
        }
    }
    assert!(leaks.is_empty(), "{}", leaks.join("\n"));
}

#[test]
fn the_slotted_fixture_itself_loads() {
    load(&multi_instance_config()).expect("a fixture that does not load proves nothing below");
}

#[test]
fn a_misspelt_key_is_refused_by_name_in_every_table() {
    let cases = [
        ("#@top@", "[globl]\nbind = \"127.0.0.1:0\"", "globl"),
        ("#@global@", "poll_interval_secs = 1", "poll_interval_secs"),
        (
            "#@global@",
            "tree_fill_treshold = 0.95",
            "tree_fill_treshold",
        ),
        ("#@auto_spawn@", "cooldown_secs = 300", "cooldown_secs"),
        ("#@rpc_pool@", "cooldown_seconds = 30", "cooldown_seconds"),
        ("#@instance_template@", "max_instances = 8", "max_instances"),
        ("#@instance@", "record_bytes = 512", "record_bytes"),
        ("#@indexer@", "tree = 0", "tree"),
        ("#@filter@", "tree_num = 0", "tree_num"),
        ("#@mirror@", "blok = 0", "blok"),
    ];
    assert_each_refused_by_name(&multi_instance_config(), &cases, |body| {
        load(body).map_err(|err| format!("{err:#}"))
    });
}

const BOOTSTRAP_RPC_POOL: &str = r#"
#@top@
[[rpc_endpoint]]
url = "http://127.0.0.1:1"
rps = 10
burst = 20
#@rpc_endpoint@

[rpc_pool]
strategy = "round-robin"
#@rpc_pool@

[ws_endpoints]
urls = []
#@ws_endpoints@
"#;

#[test]
fn the_bootstrap_rpc_pool_file_refuses_a_misspelt_key_in_every_table() {
    RpcEndpointArrayConfig::load_from_str(BOOTSTRAP_RPC_POOL)
        .expect("a fixture that does not load proves nothing below");
    let cases = [
        ("#@top@", "[rpc_pol]\nstrategy = \"round-robin\"", "rpc_pol"),
        ("#@rpc_endpoint@", "rate = 10", "rate"),
        ("#@rpc_pool@", "cooldown_secs = 30", "cooldown_secs"),
        ("#@ws_endpoints@", "url = \"ws://127.0.0.1:1\"", "url"),
    ];
    assert_each_refused_by_name(BOOTSTRAP_RPC_POOL, &cases, |body| {
        RpcEndpointArrayConfig::load_from_str(body)
            .map(|_| ())
            .map_err(|err| err.to_string())
    });
}

/// Reaps at teardown only, so a boot that never ends cannot outlive the test.
struct Reap(std::process::Child);

impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A PPOI-only fleet: nothing indexes a commit tree, so nothing reads a WebSocket endpoint.
fn mirror_only_config(data_dir: &Path) -> String {
    format!(
        r#"
[global]
bind = "127.0.0.1:0"
token = "unknown-key-test-token-padded-long"
chain_id = 1
mirror_endpoint = "http://127.0.0.1:1"

[[instance]]
id = "ppoi-paths-0"
role = "live"
encoder = "per-list-path10"
list_key = "{LIST_KEY}"
data_dir = "{}"
[instance.data_source]
kind = "mirror"
list_key = "{LIST_KEY}"
block = 0
"#,
        data_dir.display()
    )
}

/// Allowed beside `--config`, so it must reach the boot: over a fleet with no chain reader the
/// boot refuses it by name, before any store opens or any request leaves.
#[test]
fn the_ws_endpoint_flag_beside_config_reaches_the_boot() {
    let data = tempfile::tempdir().expect("tempdir");
    let body = mirror_only_config(&data.path().join("ppoi-paths-0"));
    load(&body).expect("a fixture that does not load proves nothing below");
    // NamedTempFile is 0600, which the inline token requires.
    let mut file = tempfile::NamedTempFile::new().expect("tempfile");
    file.write_all(body.as_bytes()).expect("write config");

    let mut child = Reap(
        Command::new(env!("CARGO_BIN_EXE_raven-railgun"))
            .args(["serve-production", "--config"])
            .arg(file.path())
            .args(["--ws-endpoint", "ws://127.0.0.1:1"])
            .env_remove("RAVEN_BEARER_TOKEN")
            .env_remove("RAVEN_RPC_URL")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn raven-railgun"),
    );
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.0.try_wait().expect("poll raven-railgun") {
            break status;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "booted as if --ws-endpoint were absent"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let mut stderr = String::new();
    std::io::Read::read_to_string(
        &mut child.0.stderr.take().expect("piped stderr"),
        &mut stderr,
    )
    .expect("read stderr");
    assert_eq!(status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("a WebSocket endpoint is set (`--ws-endpoint`"),
        "the boot must refuse the flag it was handed: {stderr}"
    );
}

#[test]
fn the_shipped_examples_use_only_declared_keys() {
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples");
    let ppoi = std::fs::read_to_string(examples.join("mainnet-ppoi.toml"))
        .expect("read PPOI example")
        .replace("REPLACE_ME", "unknown-key-test-token-padded-long");
    load(&ppoi).expect("PPOI example");

    let mainnet = std::fs::read_to_string(examples.join("mainnet-6-instance.toml"))
        .expect("read mainnet example")
        .replace("REPLACE_ME", "unknown-key-test-token-padded-long");
    load(&mainnet).expect("mainnet example");

    let rpc_pool =
        std::fs::read_to_string(examples.join("rpc-pool.example.toml")).expect("read rpc pool");
    load(&format!("{mainnet}\n{rpc_pool}")).expect("mainnet example with the rpc-pool table");
}
