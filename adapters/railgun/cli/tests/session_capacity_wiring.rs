//! What an uncredentialed caller can hold on a running server is what the operator configured:
//! packing-key seats per instance, their lifetime, and `/v1/events` streams in total and per
//! peer. Each bound is asserted over HTTP against a server booted through a production entry
//! point, `[global]` keys for the multi-instance path and flags for the single-instance binary,
//! and for every store the server opens, auto-spawned ones included.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::too_many_lines
)]

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use raven_inspire::inspiring::{ClientPackingKeys, PackParams};
use raven_inspire::math::GaussianSampler;
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::ServerCrs;
use raven_railgun_cli::serve_production::{
    build_http_config as build_single_http_config, run_with_listener as run_single,
    ProductionServeOptions, SessionCapacity,
};
use raven_railgun_cli::serve_production_multi::{
    build_http_config as build_multi_http_config, load_options_from_toml,
    run_with_listener as run_multi, BootstrapObserver, BootstrapView, MultiServeOptions,
};
use raven_railgun_core::{CommitmentLeaf, RailgunEvent};
use raven_railgun_engine::pir_table::EncoderKind;
use raven_railgun_engine::session_pool::SessionStoreLimits;
use raven_railgun_http::{read_versioned, write_versioned, HttpConfig, InstanceParams};
use raven_railgun_indexer::IndexerMessage;
use raven_railgun_persistence::{PpoiEventType, WalEntryPayload};
use serde_json::{json, Value};

const TOKEN: &str = "session-capacity-wiring-token-padded";
const BOOT_INSTANCE: &str = "commit-tree-0";
const SPAWNED_TREE_INSTANCE: &str = "commit-tree-1";
const LIST_TEMPLATE: &str = "ppoi";
const LIST_KEY_HEX: &str = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";
/// The smallest cell a leaf-keyed encoder accepts, at the narrowest legal row.
const CELL_ROWS: usize = 65_536;
const ROW_BYTES: usize = 32;

const SEATS: usize = 3;
const TTL_SECS: u64 = 600;
const STREAMS: usize = 2;
const STREAMS_PER_PEER: usize = 1;

const LIMIT_FLAGS: [(&str, &str); 4] = [
    ("--max-sessions-per-instance", "64"),
    ("--session-ttl-secs", "3600"),
    ("--max-sse-connections", "64"),
    ("--max-sse-connections-per-peer", "16"),
];

fn list_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    for (byte, pair) in key.iter_mut().zip(LIST_KEY_HEX.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).expect("ascii hex");
        *byte = u8::from_str_radix(pair, 16).expect("hex byte");
    }
    key
}

fn configured_limits() -> String {
    format!(
        "max_sessions_per_instance = {SEATS}\n\
         session_ttl_secs = {TTL_SECS}\n\
         max_sse_connections = {STREAMS}\n\
         max_sse_connections_per_peer = {STREAMS_PER_PEER}\n"
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
verification_mode = "chain-root-history"
data_source = {{ kind = "indexer", filter = {{ tree_number = 0 }} }}
{tail}
"#
    )
    .expect("write config");
    file.flush().expect("flush config");
    file
}

fn spawn_templates(dir: &Path) -> String {
    let dir = dir.display();
    format!(
        r#"
[auto_spawn]
enabled = true
data_dir_template = "{dir}/commit-tree-{{tree_number}}"
encoder = "per-leaf-bc"
entries = {CELL_ROWS}
entry_bytes = {ROW_BYTES}

[[ppoi_list_template]]
template_id = "{LIST_TEMPLATE}"
list_key = "{LIST_KEY_HEX}"
encoder = "per-list-status"
data_dir_template = "{dir}/list-{{list_key}}"
entries = {CELL_ROWS}
entry_bytes = {ROW_BYTES}
"#
    )
}

fn single_options(data_dir: PathBuf, rpc_url: String) -> ProductionServeOptions {
    ProductionServeOptions {
        bind: "127.0.0.1:0".parse().expect("address"),
        token: TOKEN.to_owned(),
        rpc_url,
        railgun_proxy: "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9".to_owned(),
        chain_id: 1,
        start_block: 0,
        mirror_endpoint: "http://127.0.0.1:1".to_owned(),
        list_key: LIST_KEY_HEX.to_owned(),
        data_dir,
        instance_id: BOOT_INSTANCE.to_owned(),
        max_concurrent_queries: 4,
        respond_timeout_secs: 30,
        entries: CELL_ROWS,
        entry_bytes: ROW_BYTES,
        encoder: EncoderKind::PerLeafBc { tree_number: 0 },
        session_eviction_interval_secs: 0,
        metrics_public: false,
        enable_fanout: false,
        max_fanout_shards: 16,
        session_capacity: SessionCapacity::default(),
    }
}

fn assert_documented_defaults(config: &HttpConfig, path: &str) {
    let demo = HttpConfig::demo(TOKEN);
    let pairs = [
        (
            "max_sessions_per_instance",
            config.max_sessions_per_instance,
            64,
        ),
        ("max_sse_connections", config.max_sse_connections, 64),
        (
            "max_sse_connections_per_peer",
            config.max_sse_connections_per_peer,
            16,
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

/// The line of `serve-production --help` that introduces `flag`, and the paragraph under it.
fn help_entry(help: &str, flag: &str) -> String {
    let introducer = format!("{flag} <");
    let mut lines = help
        .lines()
        .skip_while(|line| !line.trim_start().starts_with(&introducer));
    let first = lines
        .next()
        .unwrap_or_else(|| panic!("{flag} is not a serve-production flag:\n{help}"));
    std::iter::once(first)
        .chain(lines.take_while(|line| !line.trim_start().starts_with('-')))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn unset_keys_and_flags_keep_the_documented_defaults() {
    let dir = tempfile::tempdir().expect("tempdir");
    let options = load_options_from_toml(multi_config(dir.path(), "", "").path()).expect("load");
    assert_eq!(options.session_capacity, SessionCapacity::default());
    assert_documented_defaults(&build_multi_http_config(&options), "multi-instance");

    let single = single_options(dir.path().join("single"), "http://127.0.0.1:1".to_owned());
    assert_documented_defaults(&build_single_http_config(&single), "single-instance");

    let help = raven_railgun(&["serve-production", "--help"]);
    assert!(help.status.success(), "serve-production --help failed");
    let help = String::from_utf8(help.stdout).expect("utf-8 help");
    for (flag, documented) in LIMIT_FLAGS {
        let entry = help_entry(&help, flag);
        assert!(
            entry.contains(&format!("[default: {documented}]")),
            "{flag} must default to {documented}: {entry}"
        );
    }
}

/// The TOML carries these for the multi-instance path, so a flag beside `--config` would be a
/// second source for one value.
#[test]
fn every_limit_flag_is_refused_beside_a_config_file() {
    for (flag, value) in LIMIT_FLAGS {
        let output = raven_railgun(&["serve-production", "--config", "unused.toml", flag, value]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "{flag} was accepted beside --config"
        );
        assert!(
            stderr.contains("cannot be used with"),
            "{flag} beside --config must be a usage conflict: {stderr}"
        );
    }
}

/// The lifetime ceiling is a privacy bound, and it is enforced before any store opens: a
/// refused config leaves no data_dir behind.
#[tokio::test]
async fn a_lifetime_above_the_ceiling_is_refused_before_any_store_opens() {
    let dir = tempfile::tempdir().expect("tempdir");
    let options =
        load_options_from_toml(multi_config(dir.path(), "session_ttl_secs = 3601\n", "").path())
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

    let mut single = single_options(dir.path().join("single"), "http://127.0.0.1:1".to_owned());
    single.session_capacity.session_ttl_secs = 3601;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let error = run_single(single, listener, std::future::pending())
        .await
        .expect_err("a 3601 s lifetime must refuse the single-instance boot");
    assert!(
        format!("{error:#}").contains("session_ttl_secs 3601"),
        "{error:#}"
    );
    assert!(!dir.path().join("single").exists(), "a store was opened");

    let data_dir = dir.path().join("binary");
    let data_dir_arg = data_dir.to_str().expect("utf-8 tempdir");
    let output = raven_railgun(&[
        "serve-production",
        "--token",
        TOKEN,
        "--rpc-url",
        "http://127.0.0.1:1",
        "--mirror-endpoint",
        "http://127.0.0.1:1",
        "--data-dir",
        data_dir_arg,
        "--session-ttl-secs",
        "3601",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "the binary booted at 3601 s");
    assert!(stderr.contains("session_ttl_secs 3601"), "{stderr}");
    assert!(!data_dir.exists(), "the binary opened a store");
}

/// Packing keys a wallet would upload to `instance`, derived from the parameters it serves.
async fn packing_keys(client: &reqwest::Client, base: &str, instance: &str) -> Vec<u8> {
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
    let pack = PackParams::try_new(&crs.params, crs.inspiring_num_columns).expect("pack params");
    let keys = ClientPackingKeys::generate(&secret, &pack, crs.inspiring_w_seed, &mut sampler);
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
async fn assert_configured_seats(client: &reqwest::Client, base: &str, instance: &str) {
    let keys = packing_keys(client, base, instance).await;
    for identity in 0..SEATS {
        let before = unix_now();
        let (status, expires) = establish(client, base, instance, identity, &keys).await;
        assert_eq!(
            status,
            reqwest::StatusCode::OK,
            "{instance}: seat {identity} of {SEATS} must be admitted"
        );
        let lifetime = expires.expect("expiry").saturating_sub(before);
        assert!(
            (TTL_SECS..=TTL_SECS + 5).contains(&lifetime),
            "{instance}: a seat must live the configured {TTL_SECS} s, not {lifetime} s"
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

/// Opens one `/v1/events` stream; a 200 is held open by keeping the response.
async fn open_stream(
    client: &reqwest::Client,
    base: &str,
    forwarded_for: Option<&str>,
) -> reqwest::Response {
    let mut request = client.get(format!("{base}/v1/events"));
    if let Some(peer) = forwarded_for {
        request = request.header("x-forwarded-for", peer);
    }
    tokio::time::timeout(Duration::from_secs(30), request.send())
        .await
        .expect("events response within 30 s")
        .expect("events request")
}

/// Three peers against `STREAMS` total and `STREAMS_PER_PEER` each: the first peer's second
/// stream is refused as its own excess, and the third peer finds the shared pool full.
async fn assert_configured_streams(peers: [(&reqwest::Client, Option<&str>); 3], base: &str) {
    let [(first, first_as), (second, second_as), (third, third_as)] = peers;
    let mut held = Vec::new();
    let opened = open_stream(first, base, first_as).await;
    assert_eq!(opened.status(), reqwest::StatusCode::OK, "first stream");
    held.push(opened);
    let excess = open_stream(first, base, first_as).await;
    assert_eq!(
        excess.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "a peer's stream past the configured {STREAMS_PER_PEER} per peer, not the default 16"
    );
    let opened = open_stream(second, base, second_as).await;
    assert_eq!(opened.status(), reqwest::StatusCode::OK, "second peer");
    held.push(opened);
    let full = open_stream(third, base, third_as).await;
    assert_eq!(
        full.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "a stream past the configured {STREAMS} in total, not the default 64"
    );
    drop(held);
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

/// Bootstrap instance: seats, lifetime, and both stream bounds, all from `[global]`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn global_keys_bound_the_bootstrap_store_and_the_event_stream() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = multi_config(dir.path(), &configured_limits(), "");
    let server = boot_multi(config.path()).await;
    let client = reqwest::Client::new();

    assert_configured_seats(&client, &server.base, BOOT_INSTANCE).await;
    assert_configured_streams(
        [
            (&client, Some("10.0.0.1")),
            (&client, Some("10.0.0.2")),
            (&client, Some("10.0.0.3")),
        ],
        &server.base,
    )
    .await;

    shut_down(server).await;
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

fn list_row() -> WalEntryPayload {
    WalEntryPayload::PpoiListLeafAdded {
        list_key: list_key(),
        list_index: 0,
        blinded_commitment: raven_railgun_testkit::canonical(0x71),
        status: 0,
        event_type: PpoiEventType::Shield,
        signature: vec![0; 64],
        validated_merkleroot: [0; 32],
    }
}

/// Stores opened after boot, by the chain-tree and the PPOI-list auto-spawn drivers, take the
/// same `[global]` seats and lifetime as the bootstrap store.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn global_keys_bound_every_store_auto_spawn_opens() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = multi_config(
        dir.path(),
        &configured_limits(),
        &spawn_templates(dir.path()),
    );
    let server = boot_multi(config.path()).await;
    let client = reqwest::Client::new();

    server
        .view
        .channels
        .indexer_tx
        .send(shield(1, 1))
        .await
        .expect("indexer channel open");
    server
        .view
        .channels
        .mirror_tx
        .send((list_row(), 1))
        .await
        .expect("mirror channel open");

    let list_instance =
        raven_railgun_cli::auto_spawn::instance_id_for_list(LIST_TEMPLATE, &list_key());
    for instance in [SPAWNED_TREE_INSTANCE, list_instance.as_str()] {
        let params = format!("{}/v1/instance/{instance}/params", server.base);
        wait_for_ok(&client, &params, instance).await;
        assert_configured_seats(&client, &server.base, instance).await;
    }

    shut_down(server).await;
}

/// Answers the chain calls the single-instance boot makes; everything else is an RPC error.
async fn chain_rpc() -> String {
    let app = Router::new().route(
        "/",
        post(|Json(request): Json<Value>| async move {
            let id = request.get("id").cloned().unwrap_or(Value::Null);
            let result = match request.get("method").and_then(Value::as_str) {
                Some("eth_chainId") => json!("0x1"),
                Some("eth_getBlockByNumber") => finalized_block(),
                _ => {
                    return (
                        StatusCode::OK,
                        Json(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": { "code": -32601, "message": "unsupported in fixture" }
                        })),
                    );
                }
            };
            (
                StatusCode::OK,
                Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })),
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    url
}

fn finalized_block() -> Value {
    let zero_hash = format!("0x{}", "0".repeat(64));
    json!({
        "number": "0x10",
        "hash": format!("0x{}", "1".repeat(64)),
        "parentHash": zero_hash,
        "sha3Uncles": zero_hash,
        "logsBloom": format!("0x{}", "0".repeat(512)),
        "transactionsRoot": zero_hash,
        "stateRoot": zero_hash,
        "receiptsRoot": zero_hash,
        "miner": format!("0x{}", "0".repeat(40)),
        "difficulty": "0x0",
        "totalDifficulty": "0x0",
        "mixHash": zero_hash,
        "nonce": "0x0000000000000000",
        "extraData": "0x",
        "size": "0x0",
        "gasLimit": "0x0",
        "gasUsed": "0x0",
        "timestamp": "0x0",
        "transactions": [],
        "uncles": [],
        "baseFeePerGas": "0x0",
    })
}

/// Kills the server on every exit path, a failed assertion included.
struct ServingBinary {
    child: std::process::Child,
    log: PathBuf,
}

impl ServingBinary {
    fn log_tail(&self) -> String {
        let log = std::fs::read_to_string(&self.log).unwrap_or_default();
        let start = log.len().saturating_sub(4_000);
        log.get(start..).unwrap_or(&log).to_owned()
    }
}

impl Drop for ServingBinary {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_loopback_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("local addr")
        .port()
}

fn client_from(source: Ipv4Addr) -> reqwest::Client {
    reqwest::Client::builder()
        .local_address(IpAddr::V4(source))
        .build()
        .expect("client")
}

/// The single-instance binary, flags only: seats, lifetime and both stream bounds. Peers are
/// told apart by loopback source address, since this path trusts no forwarding header; Linux
/// routes all of 127.0.0.0/8 to the loopback interface.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flags_bound_the_single_instance_store_and_the_event_stream() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rpc_url = chain_rpc().await;
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), free_loopback_port());
    let data_dir = dir.path().join("single");
    let log = dir.path().join("serve.log");
    let log_file = std::fs::File::create(&log).expect("log file");
    let (seats, ttl, streams, per_peer) = (
        SEATS.to_string(),
        TTL_SECS.to_string(),
        STREAMS.to_string(),
        STREAMS_PER_PEER.to_string(),
    );
    let child = Command::new(env!("CARGO_BIN_EXE_raven-railgun"))
        .args([
            "serve-production",
            "--bind",
            &bind.to_string(),
            "--token",
            TOKEN,
            "--rpc-url",
            &rpc_url,
            "--mirror-endpoint",
            "http://127.0.0.1:1",
            "--start-block",
            "0",
            "--data-dir",
            data_dir.to_str().expect("utf-8 tempdir"),
            "--instance-id",
            BOOT_INSTANCE,
            "--encoder",
            "per-leaf-bc",
            "--tree-number",
            "0",
            "--list-key",
            LIST_KEY_HEX,
            "--entries",
            &CELL_ROWS.to_string(),
            "--entry-bytes",
            &ROW_BYTES.to_string(),
            "--max-sessions-per-instance",
            &seats,
            "--session-ttl-secs",
            &ttl,
            "--max-sse-connections",
            &streams,
            "--max-sse-connections-per-peer",
            &per_peer,
        ])
        .env_remove("RAVEN_BEARER_TOKEN")
        .env_remove("RAVEN_RPC_URL")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(log_file.try_clone().expect("log handle"))
        .stderr(log_file)
        .spawn()
        .expect("spawn raven-railgun");
    let mut serving = ServingBinary { child, log };

    let base = format!("http://{bind}");
    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        if let Ok(Some(status)) = serving.child.try_wait() {
            panic!("the server exited ({status}):\n{}", serving.log_tail());
        }
        if client
            .get(format!("{base}/v1/status"))
            .bearer_auth(TOKEN)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the server never answered /v1/status:\n{}",
            serving.log_tail()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    assert_configured_seats(&client, &base, BOOT_INSTANCE).await;
    let (first, second, third) = (
        client_from(Ipv4Addr::LOCALHOST),
        client_from(Ipv4Addr::new(127, 0, 0, 2)),
        client_from(Ipv4Addr::new(127, 0, 0, 3)),
    );
    assert_configured_streams([(&first, None), (&second, None), (&third, None)], &base).await;
    drop(serving);
}
