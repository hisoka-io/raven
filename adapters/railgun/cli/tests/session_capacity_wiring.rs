//! What an uncredentialed caller can hold on a running server is what the operator configured:
//! packing-key seats per instance and their lifetime. Each bound is asserted over HTTP against a
//! server booted from `[global]` keys, for every store the server opens, auto-spawned ones
//! included.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::too_many_lines
)]

use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use raven_inspire::inspiring::{ClientPackingKeys, PackParams};
use raven_inspire::math::GaussianSampler;
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::ServerCrs;
use raven_railgun_cli::serve_production_multi::{
    build_http_config as build_multi_http_config, load_options_from_toml,
    run_with_listener as run_multi, BootstrapObserver, BootstrapView, MultiServeOptions,
    SessionCapacity,
};
use raven_railgun_core::{CommitmentLeaf, RailgunEvent};
use raven_railgun_engine::session_pool::SessionStoreLimits;
use raven_railgun_http::{read_versioned, write_versioned, HttpConfig, InstanceParams};
use raven_railgun_indexer::IndexerMessage;
use serde_json::Value;

const TOKEN: &str = "session-capacity-wiring-token-padded";
const BOOT_INSTANCE: &str = "commit-tree-0";
const SPAWNED_TREE_INSTANCE: &str = "commit-tree-1";
/// The smallest cell a leaf-keyed encoder accepts, at the narrowest legal row.
const CELL_ROWS: usize = 65_536;
const ROW_BYTES: usize = 32;

const SEATS: usize = 3;
const TTL_SECS: u64 = 600;

const LIMIT_FLAGS: [(&str, &str); 4] = [
    ("--max-sessions-per-instance", "64"),
    ("--session-ttl-secs", "3600"),
    ("--session-lru-cap", "10000"),
    ("--max-concurrent-handshakes", "2"),
];

fn configured_limits() -> String {
    format!(
        "max_sessions_per_instance = {SEATS}\n\
         session_ttl_secs = {TTL_SECS}\n"
    )
}

/// One per-leaf-bc instance, plus whatever `extra_global` and `tail` add.
fn multi_config(dir: &Path, extra_global: &str, tail: &str) -> tempfile::NamedTempFile {
    let dir = dir.display();
    let mut file = tempfile::NamedTempFile::new().expect("config file");
    write!(
        file,
        r#"
[global]
bind = "127.0.0.1:0"
token = "{TOKEN}"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"
record_size = {ROW_BYTES}
use_flock = false
trust_proxy_header = true
trusted_proxy_cidrs = ["127.0.0.1/32"]
{extra_global}
[[instance]]
id = "{BOOT_INSTANCE}"
role = "live"
encoder = "per-leaf-bc"
tree_number = 0
record_size = {ROW_BYTES}
entries = {CELL_ROWS}
data_dir = "{dir}/{BOOT_INSTANCE}"
data_source = {{ kind = "indexer", filter = {{ tree_number = 0 }} }}
{tail}
"#
    )
    .expect("write config");
    file.flush().expect("flush config");
    file
}

fn spawn_template(dir: &Path) -> String {
    let dir = dir.display();
    format!(
        r#"
[auto_spawn]
enabled = true
data_dir_template = "{dir}/commit-tree-{{tree_number}}"
encoder = "per-leaf-bc"
entries = {CELL_ROWS}
entry_bytes = {ROW_BYTES}
"#
    )
}

fn assert_documented_defaults(config: &HttpConfig, path: &str) {
    let demo = HttpConfig::demo(TOKEN);
    let pairs = [
        (
            "max_sessions_per_instance",
            config.max_sessions_per_instance,
            64,
        ),
        ("session_lru_cap", config.session_lru_cap, 10_000),
        (
            "max_concurrent_handshakes",
            config.max_concurrent_handshakes,
            2,
        ),
    ];
    for (key, value, documented) in pairs {
        assert_eq!(value, documented, "{path}: {key} moved off its default");
    }
    assert_eq!(config.session_ttl_secs, 3600, "{path}: session_ttl_secs");
    assert_eq!(
        config.session_store_limits(),
        demo.session_store_limits(),
        "{path}: an unconfigured store must open at the compiled limits"
    );
    assert_eq!(
        demo.session_store_limits(),
        SessionStoreLimits::default(),
        "the HTTP defaults and the store defaults are one pair"
    );
}

fn raven_railgun(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_raven-railgun"))
        .args(args)
        .env_remove("RAVEN_BEARER_TOKEN")
        .env_remove("RAVEN_RPC_URL")
        .output()
        .expect("run raven-railgun")
}

#[test]
fn unset_keys_keep_the_documented_defaults() {
    let dir = tempfile::tempdir().expect("tempdir");
    let options = load_options_from_toml(multi_config(dir.path(), "", "").path()).expect("load");
    assert_eq!(options.session_capacity, SessionCapacity::default());
    assert_documented_defaults(&build_multi_http_config(&options), "multi-instance");
}

/// The file is the one source for these bounds; the binary takes no flag for any of them.
#[test]
fn no_limit_flag_is_accepted_beside_a_config_file() {
    for (flag, value) in LIMIT_FLAGS {
        let output = raven_railgun(&["serve-production", "--config", "unused.toml", flag, value]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "{flag} was accepted beside --config"
        );
        assert!(
            stderr.contains("unexpected argument"),
            "{flag} must be refused as an unknown argument: {stderr}"
        );
    }
}

/// The lifetime ceiling is enforced before any store opens: a
/// refused config leaves no data_dir behind, through the library boot and the binary alike.
#[tokio::test]
async fn a_lifetime_above_the_ceiling_is_refused_before_any_store_opens() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = multi_config(dir.path(), "session_ttl_secs = 3601\n", "");
    let options = load_options_from_toml(config.path())
        .expect("the key is declared; its value is what is refused");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let error = run_multi(options, listener, std::future::pending())
        .await
        .expect_err("a 3601 s lifetime must refuse the multi-instance boot");
    assert!(
        format!("{error:#}").contains("session_ttl_secs 3601"),
        "{error:#}"
    );
    assert!(
        !dir.path().join(BOOT_INSTANCE).exists(),
        "a store was opened"
    );

    let output = raven_railgun(&[
        "serve-production",
        "--config",
        config.path().to_str().expect("utf-8 config path"),
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "the binary booted at 3601 s");
    assert!(stderr.contains("session_ttl_secs 3601"), "{stderr}");
    assert!(
        !dir.path().join(BOOT_INSTANCE).exists(),
        "the binary opened a store"
    );
}

/// Packing keys a wallet would upload to `instance`, derived from the parameters it serves.
/// `pack` caches the packing table, the costly part, across instances that share its shape.
async fn packing_keys(
    client: &reqwest::Client,
    base: &str,
    instance: &str,
    pack: &mut Option<(usize, PackParams)>,
) -> Vec<u8> {
    let body = client
        .get(format!("{base}/v1/instance/{instance}/params"))
        .send()
        .await
        .expect("params request")
        .error_for_status()
        .expect("params status")
        .bytes()
        .await
        .expect("params body");
    let params: InstanceParams = read_versioned(&body).expect("decode params");
    let crs = ServerCrs::from_versioned_bytes(&params.crs_bincode).expect("decode crs");
    let mut sampler = GaussianSampler::with_seed(crs.params.sigma, 41);
    let secret = RlweSecretKey::generate(&crs.params, &mut sampler);
    let columns = crs.inspiring_num_columns;
    if pack.as_ref().is_none_or(|(cached, _)| *cached != columns) {
        let built = PackParams::try_new(&crs.params, columns).expect("pack params");
        *pack = Some((columns, built));
    }
    let (_, table) = pack.as_ref().expect("cached above");
    let keys = ClientPackingKeys::generate(&secret, table, crs.inspiring_w_seed, &mut sampler);
    write_versioned(&keys).expect("serialize keys")
}

/// No `Authorization`: the route is public, which is why its bounds matter.
async fn establish(
    client: &reqwest::Client,
    base: &str,
    instance: &str,
    identity: usize,
    keys: &[u8],
) -> (reqwest::StatusCode, Option<u64>) {
    let response = client
        .post(format!("{base}/v1/instance/{instance}/session"))
        .header("content-type", "application/octet-stream")
        .header("x-raven-client-id", format!("{:032x}", 0xc000 + identity))
        .body(keys.to_vec())
        .send()
        .await
        .expect("session request");
    let status = response.status();
    let expires = if status.is_success() {
        let body: Value = response.json().await.expect("session body");
        body.get("expires_at_unix_secs").and_then(Value::as_u64)
    } else {
        None
    };
    (status, expires)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

/// `SEATS` distinct identities are seated for `TTL_SECS`, and the next one is refused.
async fn assert_configured_seats(
    client: &reqwest::Client,
    base: &str,
    instance: &str,
    pack: &mut Option<(usize, PackParams)>,
) {
    let keys = packing_keys(client, base, instance, pack).await;
    for identity in 0..SEATS {
        let before = unix_now();
        let (status, expires) = establish(client, base, instance, identity, &keys).await;
        let after = unix_now();
        assert_eq!(
            status,
            reqwest::StatusCode::OK,
            "{instance}: seat {identity} of {SEATS} must be admitted"
        );
        // The server stamps its clock somewhere inside the request, so a slow establish
        // widens the window instead of failing it.
        let expires = expires.expect("expiry");
        assert!(
            (before + TTL_SECS..=after + TTL_SECS).contains(&expires),
            "{instance}: a seat must live the configured {TTL_SECS} s: expires at {expires}, \
             requested between {before} and {after}"
        );
    }
    let (status, _) = establish(client, base, instance, SEATS, &keys).await;
    assert_eq!(
        status,
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "{instance}: identity {} must find the configured {SEATS}-seat pool full, not the \
         compiled 64-seat one",
        SEATS + 1
    );
}

async fn wait_for_observer(
    observer: &BootstrapObserver,
    server: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
) -> BootstrapView {
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        if let Some(view) = observer.lock().clone() {
            return view;
        }
        if server.is_finished() {
            match server.await {
                Ok(Ok(())) => panic!("server returned before publishing its bootstrap"),
                Ok(Err(error)) => panic!("bootstrap failed: {error:#}"),
                Err(join) => panic!("server task panicked: {join}"),
            }
        }
        assert!(Instant::now() < deadline, "bootstrap never finished");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Polls `path` until it answers 200: the listener serves only once the whole boot is done,
/// and an auto-spawned instance is routable only once it is registered.
async fn wait_for_ok(client: &reqwest::Client, url: &str, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        if client
            .get(url)
            .bearer_auth(TOKEN)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            return;
        }
        assert!(Instant::now() < deadline, "{what} never answered {url}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

struct MultiServer {
    base: String,
    view: BootstrapView,
    server: tokio::task::JoinHandle<anyhow::Result<()>>,
    stop: tokio::sync::oneshot::Sender<()>,
}

async fn boot_multi(config: &Path) -> MultiServer {
    let mut options: MultiServeOptions = load_options_from_toml(config).expect("load");
    options.skip_chain_workers = true;
    options.skip_mirror_workers = true;
    options.reload_config_path = None;
    let observer: BootstrapObserver = Arc::new(parking_lot::Mutex::new(None));
    options.bootstrap_observer = Some(Arc::clone(&observer));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("local addr"));
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let mut server = tokio::spawn(run_multi(options, listener, async move {
        let _ = stopped.await;
    }));
    let view = wait_for_observer(&observer, &mut server).await;
    wait_for_ok(
        &reqwest::Client::new(),
        &format!("{base}/v1/status"),
        "the server",
    )
    .await;
    MultiServer {
        base,
        view,
        server,
        stop,
    }
}

async fn shut_down(server: MultiServer) {
    let _ = server.stop.send(());
    let _ = tokio::time::timeout(Duration::from_secs(30), server.server).await;
}

fn shield(tree: u32, height: u64) -> IndexerMessage {
    IndexerMessage::Event {
        event: RailgunEvent::Shield {
            block_number: height,
            tx_hash: [0u8; 32],
            tree_number: tree,
            start_position: 0,
            leaves: vec![CommitmentLeaf {
                tree_number: tree,
                leaf_index: 0,
                commitment_hash: raven_railgun_testkit::canonical(0x31),
                ciphertext: Vec::new(),
            }],
        },
        block_height: height,
    }
}

/// Every store the server opens, the bootstrap one and the one the chain-tree auto-spawn
/// driver opens after boot, takes the `[global]` seats and lifetime.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn global_keys_bound_every_store_auto_spawn_opens() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = multi_config(
        dir.path(),
        &configured_limits(),
        &spawn_template(dir.path()),
    );
    let server = boot_multi(config.path()).await;
    let client = reqwest::Client::new();
    let mut pack = None;

    assert_configured_seats(&client, &server.base, BOOT_INSTANCE, &mut pack).await;

    server
        .view
        .channels
        .indexer_tx
        .send(shield(1, 1))
        .await
        .expect("indexer channel open");
    let params = format!("{}/v1/instance/{SPAWNED_TREE_INSTANCE}/params", server.base);
    wait_for_ok(&client, &params, SPAWNED_TREE_INSTANCE).await;
    assert_configured_seats(&client, &server.base, SPAWNED_TREE_INSTANCE, &mut pack).await;

    shut_down(server).await;
}
