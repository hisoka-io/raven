//! The config the image ships, run the way an operator runs it: the production binary,
//! `serve-production --config`, in a child process.
//!
//! The shim routes were certified for months by a hand-wired state while the deployment served
//! 503. Here nothing is wired by the test: the example file is rewritten only where it names a
//! host, a directory or a secret, and every answer comes over HTTP from the binary's own boot.
//!
//! The upstream is an in-process listener on loopback, so nothing leaves the machine.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

#[path = "support/bc_prefixes.rs"]
mod bc_prefixes;

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::routing::post;
use axum::{Json, Router};
use bc_prefixes::{prefix_of, read_segment, Segment};
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
const SHIPPED_MIRROR: &str = "mirror_endpoint = \"https://ppoi.fdi.network\"";
/// Every data directory sits under this root, so it is replaced wherever it occurs.
const SHIPPED_DATA_ROOT: &str = "/srv/raven/data/";

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
const LIST_ROUTES: [&str; 2] = ["merkle-proofs", "bc-prefixes"];
/// The block the list reaches at row 393,216, which the shipped config must declare ahead of it.
const NEXT_BLOCK_INSTANCE: &str = "ppoi-paths-ofac-6";

/// The boot builds one production cell per instance, close to serially, so a runner's per-core
/// speed sets it. The CI lane runs under nextest's `production-cell` profile, which kills at
/// 1200 s. The budgets here sum below that, so a stuck boot fails with the log tail rather than
/// as a bare kill.
const BOOT_BUDGET: Duration = Duration::from_mins(15);
/// After the boot serves: the first mirror page is immediate.
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
    list_key: String,
    roots: Arc<Vec<[u8; 32]>>,
}

/// Distinct in the bytes the index publishes too, or a renumbered index would still match.
fn leaf_at(index: u32) -> [u8; 32] {
    let mut leaf = [0u8; 32];
    let row = (index + 1).to_be_bytes();
    leaf[28..].copy_from_slice(&row);
    leaf[2..6].copy_from_slice(&row);
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

fn rpc_error(id: Value, message: &str) -> Json<Value> {
    Json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": -32601, "message": message }
    }))
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

/// The shipped example, rewritten only at its bind, token, upstream and data root, and created
/// owner-only because it carries the token inline.
fn write_shipped_config(root: &Path, mirror_endpoint: &str) -> PathBuf {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/mainnet-ppoi.toml");
    let body = std::fs::read_to_string(example).expect("read the shipped example");
    let body = replace_once(&body, SHIPPED_BIND, "bind = \"127.0.0.1:0\"");
    let body = replace_once(&body, SHIPPED_TOKEN, &format!("token = \"{BEARER_TOKEN}\""));
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

/// The single PPOI list the config declares, read from the file the binary loads, so the probes
/// follow the example rather than a copy of it. It declares nothing else.
fn declared_list(opts: &MultiServeOptions) -> [u8; 32] {
    let mut keys: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut blocks = 0usize;
    for inst in &opts.instances {
        match inst.data_source {
            DataSourceFilter::PpoiListBlock { list_key, .. } => {
                keys.insert(list_key);
                blocks += 1;
            }
            other => panic!("the shipped config declares a non-block instance: {other:?}"),
        }
    }
    assert_eq!(
        keys.len(),
        1,
        "the example declares path blocks for one list"
    );
    assert!(
        blocks >= 2,
        "fewer than two blocks cannot tell a declared store from any store"
    );
    keys.into_iter().next().expect("one list")
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
    let (upstream_listener, mirror_endpoint) = loopback().await;
    let config = write_shipped_config(root.path(), &mirror_endpoint);

    let opts = load_options_from_toml(&config).expect("parse the rewritten shipped config");
    let list_key = hex::encode(declared_list(&opts));
    let roots = Arc::new(upstream_roots());
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
        list_key,
        roots,
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
    proofs: (StatusCode, Value),
    absent_proof: StatusCode,
    index: Segment,
}

async fn ask_list_routes(booted: &Booted, held: [u8; 32], absent: [u8; 32]) -> ListAnswers {
    let client = reqwest::Client::new();
    let base = format!("http://{}/v1/poi", booted.addr);
    let list_key = booted.list_key.as_str();
    let proof_of = |bc: [u8; 32]| {
        client
            .post(format!("{base}/merkle-proofs"))
            .json(&json!({ "listKey": list_key, "blindedCommitments": [hex::encode(bc)] }))
    };
    let proofs = ask(proof_of(held), "merkle-proofs").await;
    let (absent_proof, _) = ask(proof_of(absent), "merkle-proofs for an absent row").await;
    let index = read_segment(
        client
            .get(format!("{base}/{list_key}/bc-prefixes"))
            .send()
            .await
            .expect("bc-prefixes"),
    )
    .await;
    ListAnswers {
        proofs,
        absent_proof,
        index,
    }
}

/// The shipped config serves every block it declares, the one the list reaches next included,
/// and answers list rows only from a store the binary fed from upstream; a commit tree it does
/// not declare is refused by the coverage proof.
///
/// The refusal count is the load-bearing assertion there: exactly one, the commit tree, while
/// the list routes answered from the declared blocks. Take the store registry out of the boot
/// and every one of them answers 503 with the counter at zero.
///
/// No `Authorization` header goes to a shim route: the read path is public and a wallet holds
/// no credential. Only the `/metrics` scrape is authenticated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "boots the production binary on the shipped seven-block config, a production cell per \
            block. Trigger: changing serve-production --config boot wiring, shim-route store \
            resolution, or the example config's declared list blocks."]
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
    assert!(
        served.contains(NEXT_BLOCK_INSTANCE),
        "the block holding row 393,216 must be served before the list reaches it: {served:?}"
    );
    let params = reqwest::Client::new()
        .get(format!(
            "http://{addr}/v1/instance/{NEXT_BLOCK_INSTANCE}/params"
        ))
        .send()
        .await
        .expect("params of the next block");
    assert_eq!(
        params.status(),
        StatusCode::OK,
        "{NEXT_BLOCK_INSTANCE} hands a wallet what it needs to query it"
    );

    let feed = wait_until_caught_up(&booted).await;
    assert_eq!(feed.rows_held, u64::from(LIST_ROWS), "{feed:?}");

    let undeclared = ask_commit_tree(addr, 0).await;
    let held = leaf_at(LIST_ROWS - 1);
    let absent = leaf_at(LIST_ROWS);
    let answers = ask_list_routes(&booted, held, absent).await;
    let scrape = scrape(addr).await;

    assert_eq!(
        undeclared,
        StatusCode::SERVICE_UNAVAILABLE,
        "commit tree 0 is held by nobody and must not be answered from a list block's store"
    );
    assert_eq!(
        refusals_for(&scrape, COMMIT_TREE_ROUTE),
        1,
        "exactly one commit-tree request refused through the proof; zero means no registry \
         was installed and every 503 is the absent-store 503: {scrape}"
    );

    let (status, proofs) = &answers.proofs;
    assert_eq!(*status, StatusCode::OK, "{}", booted.node.tail());
    assert_eq!(proofs[0]["leaf"], hex::encode(held), "{proofs}");
    assert_eq!(
        proofs[0]["root"],
        hex::encode(booted.roots.last().expect("a root")),
        "the proof must come from the block holding the row, at the root upstream published"
    );
    assert_eq!(
        answers.absent_proof,
        StatusCode::NOT_FOUND,
        "a row past the list's end is absent from the declared blocks that cover it"
    );
    let index = &answers.index;
    assert_eq!(index.status, StatusCode::OK, "{}", booted.node.tail());
    let rows = u64::from(LIST_ROWS);
    assert_eq!(
        (index.base, index.next, index.total),
        (Some(0), Some(rows), Some(rows)),
        "the list ends inside block 0, so one frontier segment is all of it"
    );
    let expected: Vec<_> = (0..LIST_ROWS).map(|row| prefix_of(&leaf_at(row))).collect();
    assert_eq!(
        index.rows, expected,
        "every row sits at its global position in the index"
    );
    for route in LIST_ROUTES {
        assert_eq!(
            refusals_for(&scrape, route),
            0,
            "{route} answered from its declared blocks, so no proof may have refused: {scrape}"
        );
    }
}
