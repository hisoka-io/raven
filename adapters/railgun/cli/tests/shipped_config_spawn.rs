//! The shipped multi-instance config, run the way an operator runs it: the production binary,
//! `serve-production --config`, in a child process.
//!
//! The shim routes were certified for months by a hand-wired state while the deployment served
//! 503. Here nothing is wired by the test: the example file is rewritten only where it names a
//! host, a directory or a secret, and every answer comes over HTTP from the binary's own boot.
//!
//! Both upstreams are in-process listeners on loopback, so nothing leaves the machine.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::routing::post;
use axum::{Json, Router};
use raven_railgun_cli::serve_production_multi::{load_options_from_toml, MultiServeOptions};
use raven_railgun_engine::imt::Imt;
use raven_railgun_engine::orchestrator::{DataSourceFilter, LEAVES_PER_PPOI_BLOCK};
use raven_railgun_http::status::{MirrorFeedState, MirrorFeedView};
use reqwest::StatusCode;
use serde_json::{json, Value};

const BEARER_TOKEN: &str = "shipped-config-spawn-token-padded-long";

// Each of these must occur exactly once, so a reworded example fails here instead of booting
// against a live host.
const SHIPPED_BIND: &str = "bind = \"0.0.0.0:8080\"";
const SHIPPED_TOKEN: &str = "token = \"REPLACE_ME\"";
const SHIPPED_RPC_URL: &str = "rpc_url = \"https://mainnet.example/eth\"";
const SHIPPED_MIRROR: &str = "mirror_endpoint = \"https://ppoi.fdi.network\"";
/// Every data directory and template sits under this root, so it is replaced wherever it occurs.
const SHIPPED_DATA_ROOT: &str = "/var/lib/raven-railgun/";

/// The config binds port 0, so the port is read back from this line of the binary's log.
const LISTENING: &str = "raven-railgun multi-instance production serve listening";

/// Rows upstream holds for the declared list. Fewer than a block, so the list ends inside
/// block 0 and every later declared block is legitimately empty.
const LIST_ROWS: u32 = 3;
const _: () = assert!(LIST_ROWS < LEAVES_PER_PPOI_BLOCK);

/// Incremented only when a coverage proof refuses. It is what separates "the proof ran and
/// refused" from "no store was ever wired": both answer 503.
const COVERAGE_REFUSALS_TOTAL: &str = "raven_railgun_shim_coverage_refusals_total";
const COMMIT_TREE_ROUTE: &str = "commit-tree-merkle-proof";
const LIST_ROUTES: [&str; 3] = ["pois-per-list", "merkle-proofs", "status-header"];

/// The eleven-instance boot served in 105-123 s on a 16-core box, 111 s pinned to four logical
/// CPUs and 114 s on two: it is close to serial, so a runner's per-core speed sets it. The CI lane
/// runs under nextest's `production-cell` profile, which kills at 1200 s. The budgets here sum
/// below that, so a stuck boot fails with the log tail rather than as a bare kill.
const BOOT_BUDGET: Duration = Duration::from_mins(15);
/// After the boot serves: the first mirror page and the first indexer tick are both immediate.
const SETTLE_BUDGET: Duration = Duration::from_secs(60);

/// The child. Dropping it reaps the process, so a failed assertion cannot leak a server.
struct Node {
    child: Child,
    log: PathBuf,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Node {
    fn output(&self) -> String {
        String::from_utf8_lossy(&std::fs::read(&self.log).unwrap_or_default()).into_owned()
    }

    fn tail(&self) -> String {
        let output = self.output();
        let mut lines: Vec<&str> = output.lines().rev().take(60).collect();
        lines.reverse();
        lines.join("\n")
    }
}

/// A booted node and what the test knows of its config. `node` is declared first so it is
/// reaped before the directory holding its data is removed.
struct Booted {
    node: Node,
    _root: tempfile::TempDir,
    addr: SocketAddr,
    declared_instances: BTreeSet<String>,
    trees: Vec<u32>,
    list_key: String,
    roots: Arc<Vec<[u8; 32]>>,
    chain_calls: Calls,
}

fn leaf_at(index: u32) -> [u8; 32] {
    let mut leaf = [0u8; 32];
    leaf[28..].copy_from_slice(&(index + 1).to_be_bytes());
    leaf
}

async fn loopback() -> (tokio::net::TcpListener, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    (listener, url)
}

fn serve(listener: tokio::net::TcpListener, app: Router) {
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
}

type Calls = Arc<parking_lot::Mutex<Vec<String>>>;

fn block_at(number: u64) -> Value {
    let hash = |n: u64| {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&n.to_be_bytes());
        format!("0x{}", hex::encode(bytes))
    };
    json!({
        "hash": hash(number),
        "parentHash": hash(number.saturating_sub(1)),
        "sha3Uncles": hash(0),
        "miner": "0x0000000000000000000000000000000000000000",
        "stateRoot": hash(0),
        "transactionsRoot": hash(0),
        "receiptsRoot": hash(0),
        "logsBloom": format!("0x{}", "0".repeat(512)),
        "difficulty": "0x0",
        "number": format!("0x{number:x}"),
        "gasLimit": "0x1c9c380",
        "gasUsed": "0x0",
        "timestamp": "0x65000000",
        "extraData": "0x",
        "mixHash": hash(0),
        "nonce": "0x0000000000000000",
        "baseFeePerGas": "0x7",
        "size": "0x220",
        "transactions": [],
        "uncles": []
    })
}

fn rpc_error(id: Value, message: &str) -> Json<Value> {
    Json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": -32601, "message": message }
    }))
}

/// A chain as far as a boot asks of it: the configured chain id, a finalized `head`, and no
/// Railgun logs. Any other method is refused, so a boot that starts needing one fails loudly
/// instead of reading a guess.
fn chain_rpc(chain_id: u64, head: u64, calls: Calls) -> Router {
    Router::new().route(
        "/",
        post(move |Json(request): Json<Value>| {
            let calls = Arc::clone(&calls);
            async move {
                let method = request["method"].as_str().unwrap_or_default().to_owned();
                let id = request.get("id").cloned().unwrap_or(Value::Null);
                calls.lock().push(method.clone());
                let result = match method.as_str() {
                    "eth_chainId" => json!(format!("0x{chain_id:x}")),
                    "eth_blockNumber" => json!(format!("0x{head:x}")),
                    "eth_getBlockByNumber" => block_at(
                        request["params"][0]
                            .as_str()
                            .and_then(|asked| asked.strip_prefix("0x"))
                            .and_then(|digits| u64::from_str_radix(digits, 16).ok())
                            .unwrap_or(head),
                    ),
                    "eth_getLogs" => json!([]),
                    _ => return rpc_error(id, &format!("stub has no {method}")),
                };
                Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
            }
        }),
    )
}

/// Upstream holding rows `0..LIST_ROWS` of `list_key`, each with the root upstream publishes
/// after it. Every other list is empty.
fn ppoi_upstream(list_key: String, roots: Arc<Vec<[u8; 32]>>) -> Router {
    Router::new().route(
        "/",
        post(move |Json(request): Json<Value>| {
            let roots = Arc::clone(&roots);
            let list_key = list_key.clone();
            async move {
                let id = request.get("id").cloned().unwrap_or(Value::Null);
                if request["method"] != "ppoi_poi_events" {
                    return rpc_error(id, "stub answers ppoi_poi_events only");
                }
                let params = &request["params"];
                let start = params["startIndex"].as_u64().expect("startIndex");
                let end = params["endIndex"].as_u64().expect("endIndex");
                let rows: Vec<Value> = if params["listKey"] == list_key.as_str() {
                    (start..=end)
                        .map_while(|index| {
                            let index = u32::try_from(index).ok()?;
                            let root = roots.get(usize::try_from(index).ok()?)?;
                            Some(json!({
                                "signedPOIEvent": {
                                    "index": index,
                                    "blindedCommitment": hex::encode(leaf_at(index)),
                                    "signature": "00".repeat(64),
                                    "type": "Shield"
                                },
                                "validatedMerkleroot": hex::encode(root)
                            }))
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                Json(json!({ "jsonrpc": "2.0", "id": id, "result": rows }))
            }
        }),
    )
}

fn upstream_roots() -> Vec<[u8; 32]> {
    let mut tree = Imt::new().expect("imt");
    (0..LIST_ROWS)
        .map(|index| {
            tree.insert_leaves(usize::try_from(index).expect("index"), &[leaf_at(index)])
                .expect("append");
            tree.root()
        })
        .collect()
}

fn replace_once(body: &str, anchor: &str, with: &str) -> String {
    assert_eq!(
        body.matches(anchor).count(),
        1,
        "the shipped example no longer carries exactly one `{anchor}`"
    );
    body.replace(anchor, with)
}

/// The shipped example, rewritten only at its bind, token, chain RPC, upstream and data root,
/// and created owner-only because it carries the token inline.
fn write_shipped_config(root: &Path, rpc_url: &str, mirror_endpoint: &str) -> PathBuf {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/mainnet-6-instance.toml");
    let body = std::fs::read_to_string(example).expect("read the shipped example");
    let body = replace_once(&body, SHIPPED_BIND, "bind = \"127.0.0.1:0\"");
    let body = replace_once(&body, SHIPPED_TOKEN, &format!("token = \"{BEARER_TOKEN}\""));
    let body = replace_once(&body, SHIPPED_RPC_URL, &format!("rpc_url = \"{rpc_url}\""));
    let body = replace_once(
        &body,
        SHIPPED_MIRROR,
        &format!("mirror_endpoint = \"{mirror_endpoint}\""),
    );
    assert!(
        body.contains(SHIPPED_DATA_ROOT),
        "the shipped example no longer places data under {SHIPPED_DATA_ROOT}"
    );
    let body = body.replace(SHIPPED_DATA_ROOT, &format!("{}/", root.display()));

    let path = root.join("config.toml");
    let mut file = owner_only(&path);
    std::io::Write::write_all(&mut file, body.as_bytes()).expect("write config");
    path
}

fn owner_only(path: &Path) -> std::fs::File {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).expect("create config");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file
            .metadata()
            .expect("config metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the config must be created owner-only");
    }
    file
}

/// The commit trees and the single PPOI list the config declares, read from the file the
/// binary loads, so the probes follow the example rather than a copy of it.
fn declared_domains(opts: &MultiServeOptions) -> (Vec<u32>, [u8; 32]) {
    let mut trees: Vec<u32> = opts
        .instances
        .iter()
        .filter_map(|inst| match inst.data_source {
            DataSourceFilter::ChainTreeNumber(tree) => Some(tree),
            _ => None,
        })
        .collect();
    trees.sort_unstable();
    let mut keys: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut blocks = 0usize;
    for inst in &opts.instances {
        if let DataSourceFilter::PpoiListBlock { list_key, .. } = inst.data_source {
            keys.insert(list_key);
            blocks += 1;
        }
    }
    assert_eq!(
        keys.len(),
        1,
        "the example declares path blocks for one list"
    );
    assert!(
        trees.len() >= 2 && blocks >= 2,
        "fewer than two trees and two blocks cannot tell a declared store from any store"
    );
    (trees, keys.into_iter().next().expect("one list"))
}

fn spawn_binary(config: &Path, root: &Path) -> Node {
    let log = root.join("node.log");
    let out = std::fs::File::create(&log).expect("create node log");
    let err = out.try_clone().expect("clone node log");
    let child = Command::new(env!("CARGO_BIN_EXE_raven-railgun"))
        .arg("serve-production")
        .arg("--config")
        .arg(config)
        // Only what the test sets: an inherited RAVEN_BEARER_TOKEN is a second token source,
        // which the loader refuses.
        .env_clear()
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .spawn()
        .expect("spawn the production binary");
    Node { child, log }
}

fn listening_addr(output: &str) -> Option<SocketAddr> {
    output
        .lines()
        .filter(|line| line.contains(LISTENING))
        .find_map(|line| {
            let (_, rest) = line.split_once("bind=")?;
            rest.split_whitespace().next()?.parse().ok()
        })
}

async fn wait_until_listening(node: &mut Node) -> SocketAddr {
    let started = Instant::now();
    loop {
        if let Some(addr) = listening_addr(&node.output()) {
            return addr;
        }
        if let Some(status) = node.child.try_wait().expect("poll the child") {
            panic!(
                "the binary exited {status} before serving:\n{}",
                node.tail()
            );
        }
        assert!(
            started.elapsed() < BOOT_BUDGET,
            "the binary did not serve within {BOOT_BUDGET:?}:\n{}",
            node.tail()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn boot_the_shipped_config() -> Booted {
    let root = tempfile::tempdir().expect("tempdir");
    let (chain_listener, rpc_url) = loopback().await;
    let (upstream_listener, mirror_endpoint) = loopback().await;
    let config = write_shipped_config(root.path(), &rpc_url, &mirror_endpoint);

    let opts = load_options_from_toml(&config).expect("parse the rewritten shipped config");
    let (trees, list_key) = declared_domains(&opts);
    let list_key = hex::encode(list_key);
    let roots = Arc::new(upstream_roots());
    let chain_calls = Calls::default();
    serve(
        chain_listener,
        // One block past the start, so the indexer has a range to scan.
        chain_rpc(
            opts.chain_id,
            opts.start_block + 1,
            Arc::clone(&chain_calls),
        ),
    );
    serve(
        upstream_listener,
        ppoi_upstream(list_key.clone(), Arc::clone(&roots)),
    );

    let mut node = spawn_binary(&config, root.path());
    let addr = wait_until_listening(&mut node).await;
    Booted {
        node,
        _root: root,
        addr,
        declared_instances: opts
            .instances
            .iter()
            .map(|inst| inst.instance_id.as_str().to_owned())
            .collect(),
        trees,
        list_key,
        roots,
        chain_calls,
    }
}

async fn ask(request: reqwest::RequestBuilder, what: &str) -> (StatusCode, Value) {
    let response = request.send().await.expect(what);
    let status = response.status();
    let body = if status.is_success() {
        response.json().await.expect(what)
    } else {
        Value::Null
    };
    (status, body)
}

/// Readiness is uncredentialed and carries its body at 503 too; only the feed for the declared
/// list is read from it.
async fn wait_until_caught_up(booted: &Booted) -> MirrorFeedView {
    let started = Instant::now();
    let client = reqwest::Client::new();
    loop {
        let body: Value = client
            .get(format!("http://{}/v1/health/ready", booted.addr))
            .send()
            .await
            .expect("readiness")
            .json()
            .await
            .expect("readiness body");
        let feeds: Vec<MirrorFeedView> =
            serde_json::from_value(body["mirror_feeds"].clone()).expect("mirror feeds");
        if let Some(feed) = feeds
            .into_iter()
            .find(|feed| feed.list_key == booted.list_key)
        {
            if feed.state == MirrorFeedState::CaughtUp {
                return feed;
            }
        }
        assert!(
            started.elapsed() < SETTLE_BUDGET,
            "the list feed never caught up with the stub upstream: {body}\n{}",
            booted.node.tail()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// The indexer's first tick scans the range past the start block. A boot that skipped the chain
/// workers never asks for logs.
async fn wait_until_scanned(booted: &Booted) {
    let started = Instant::now();
    while !booted
        .chain_calls
        .lock()
        .iter()
        .any(|method| method == "eth_getLogs")
    {
        assert!(
            started.elapsed() < SETTLE_BUDGET,
            "the chain indexer never scanned: {:?}\n{}",
            booted.chain_calls.lock(),
            booted.node.tail()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn ask_commit_tree(addr: SocketAddr, tree_number: u32) -> StatusCode {
    reqwest::Client::new()
        .post(format!(
            "http://{addr}/v1/commit-tree/{tree_number}/merkle-proof"
        ))
        .json(&json!({ "leafIndex": 0 }))
        .send()
        .await
        .expect("commit-tree merkle proof")
        .status()
}

async fn scrape(addr: SocketAddr) -> String {
    let response = reqwest::Client::new()
        .get(format!("http://{addr}/metrics"))
        .bearer_auth(BEARER_TOKEN)
        .send()
        .await
        .expect("scrape");
    assert_eq!(response.status(), StatusCode::OK, "metrics scrape");
    response.text().await.expect("metrics body")
}

fn refusals_for(scrape: &str, route: &str) -> u64 {
    let label = format!("route=\"{route}\"");
    scrape
        .lines()
        .find(|line| {
            line.starts_with(COVERAGE_REFUSALS_TOTAL)
                && line.contains(&label)
                && !line.starts_with('#')
        })
        .and_then(|line| line.rsplit(' ').next()?.parse().ok())
        .unwrap_or(0)
}

/// What the list routes answered, each asked exactly once so a refusal count is exact.
struct ListAnswers {
    pois: (StatusCode, Value),
    proofs: (StatusCode, Value),
    header: (StatusCode, Value),
}

async fn ask_list_routes(booted: &Booted, held: [u8; 32], absent: [u8; 32]) -> ListAnswers {
    let client = reqwest::Client::new();
    let base = format!("http://{}/v1/poi", booted.addr);
    let list_key = booted.list_key.as_str();
    let pois = ask(
        client.post(format!("{base}/pois-per-list")).json(&json!({
            "listKeys": [list_key],
            "blindedCommitmentDatas": [
                { "blindedCommitment": hex::encode(leaf_at(0)) },
                { "blindedCommitment": hex::encode(held) },
                { "blindedCommitment": hex::encode(absent) },
            ],
        })),
        "pois-per-list",
    )
    .await;
    let proofs = ask(
        client
            .post(format!("{base}/merkle-proofs"))
            .json(&json!({ "listKey": list_key, "blindedCommitments": [hex::encode(held)] })),
        "merkle-proofs",
    )
    .await;
    let header = ask(
        client.get(format!("{base}/{list_key}/status-header")),
        "status-header",
    )
    .await;
    ListAnswers {
        pois,
        proofs,
        header,
    }
}

/// Every commit tree the shipped config declares reaches its own store and one it does not
/// declare is refused by the coverage proof; the declared list answers rows only a store the
/// binary fed from upstream can hold.
///
/// The commit-tree refusal count is the load-bearing assertion there: exactly one, the
/// undeclared tree, while the declared trees answered 404 from an empty store. Take the store
/// registry out of the boot and every one of them answers 503 with the counter at zero.
///
/// No `Authorization` header goes to a shim route: the read path is public and a wallet holds
/// no credential. Only the `/metrics` scrape is authenticated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "boots the production binary on the shipped 11-instance config, ~100-120 s of PIR \
            setup on a 16-core box. Trigger: changing serve-production --config boot wiring, shim-route store \
            resolution, or the example config's declared trees and list blocks."]
async fn the_shipped_config_serves_shim_routes_from_the_stores_it_declares() {
    let booted = boot_the_shipped_config().await;
    let addr = booted.addr;

    let (status, listed) = ask(
        reqwest::Client::new().get(format!("http://{addr}/v1/status")),
        "status",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", booted.node.tail());
    let served: BTreeSet<String> = listed["instances"]
        .as_array()
        .expect("status instances")
        .iter()
        .map(|inst| inst["id"].as_str().expect("instance id").to_owned())
        .collect();
    assert_eq!(
        served, booted.declared_instances,
        "the binary serves every declared instance"
    );

    let feed = wait_until_caught_up(&booted).await;
    assert_eq!(feed.rows_held, u64::from(LIST_ROWS), "{feed:?}");
    wait_until_scanned(&booted).await;

    let mut declared_trees = Vec::with_capacity(booted.trees.len());
    for tree in &booted.trees {
        declared_trees.push((*tree, ask_commit_tree(addr, *tree).await));
    }
    let undeclared_tree = booted.trees.last().copied().expect("a declared tree") + 1;
    let undeclared = ask_commit_tree(addr, undeclared_tree).await;
    let held = leaf_at(LIST_ROWS - 1);
    let absent = leaf_at(LIST_ROWS);
    let answers = ask_list_routes(&booted, held, absent).await;
    let scrape = scrape(addr).await;

    for (tree, status) in &declared_trees {
        assert_eq!(
            *status,
            StatusCode::NOT_FOUND,
            "commit tree {tree} is declared, so the request must reach its store and miss \
             there rather than find no store at all"
        );
    }
    assert_eq!(
        undeclared,
        StatusCode::SERVICE_UNAVAILABLE,
        "commit tree {undeclared_tree} is held by nobody and must not be answered from a \
         declared tree's store"
    );
    assert_eq!(
        refusals_for(&scrape, COMMIT_TREE_ROUTE),
        1,
        "exactly one commit-tree request refused through the proof, the undeclared one; zero \
         means no registry was installed and every 503 is the absent-store 503: {scrape}"
    );

    let list_key = booted.list_key.as_str();
    let (status, pois) = &answers.pois;
    assert_eq!(*status, StatusCode::OK, "{}", booted.node.tail());
    for (bc, want) in [(leaf_at(0), "Valid"), (held, "Valid"), (absent, "Missing")] {
        assert_eq!(pois[hex::encode(bc)][list_key], want, "{pois}");
    }
    let (status, proofs) = &answers.proofs;
    assert_eq!(*status, StatusCode::OK, "{}", booted.node.tail());
    assert_eq!(proofs[0]["leaf"], hex::encode(held), "{proofs}");
    assert_eq!(
        proofs[0]["root"],
        hex::encode(booted.roots.last().expect("a root")),
        "the proof must come from the block holding the row, at the root upstream published"
    );
    let (status, header) = &answers.header;
    assert_eq!(*status, StatusCode::OK, "{}", booted.node.tail());
    assert_eq!(header["listKey"], list_key, "{header}");
    for route in LIST_ROUTES {
        assert_eq!(
            refusals_for(&scrape, route),
            0,
            "{route} answered from its declared blocks, so no proof may have refused: {scrape}"
        );
    }
}
