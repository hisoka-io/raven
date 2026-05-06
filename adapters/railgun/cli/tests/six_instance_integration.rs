//! End-to-end synthetic-chain integration test for the canonical
//! 6-instance mainnet topology. Each test is `#[ignore]`-gated.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::manual_contains,
    clippy::panic,
    clippy::unwrap_used,
    clippy::too_many_lines,
    clippy::cast_possible_truncation
)]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use raven_railgun_cli::serve_production_multi::{
    load_options_from_toml, run_with_listener, BootstrapInstanceView, BootstrapObserver,
    BootstrapView, MultiServeOptions,
};
use raven_railgun_core::{CommitmentLeaf, RailgunEvent};
use raven_railgun_engine::orchestrator::{DataSourceFilter, VerificationMode};
use raven_railgun_engine::persistence::SnapshotPolicy;
use raven_railgun_engine::pir_table::EncoderKind;
use raven_railgun_indexer::{
    BlockId, ChainSource, IndexerError, IndexerMessage, Result as IndexerResult,
};
use raven_railgun_persistence::WalEntryPayload;
use serde::Deserialize;
use tokio::sync::oneshot;

const BEARER_TOKEN: &str = "six-instance-integration-token-pad";

const PPOI_LIST_OFAC_HEX: &str = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";
const PPOI_LIST_RAILWAY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000001";

#[derive(Debug, Deserialize)]
struct StatusJson {
    instances: Vec<InstanceJson>,
}

#[derive(Debug, Deserialize)]
struct InstanceJson {
    id: String,
    #[serde(default)]
    #[allow(dead_code)]
    epoch: u64,
    #[allow(dead_code)]
    active_k_concurrency: u32,
}

/// In-process synthetic chain source. PPOI instances do not get one
/// because the verifier loop only fires for `ChainTreeNumber` sources.
struct SyntheticChainSource {
    verify_calls: AtomicU64,
    last_seen_root: parking_lot::Mutex<[u8; 32]>,
}

impl SyntheticChainSource {
    fn new() -> Self {
        Self {
            verify_calls: AtomicU64::new(0),
            last_seen_root: parking_lot::Mutex::new([0u8; 32]),
        }
    }

    fn verify_count(&self) -> u64 {
        self.verify_calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ChainSource for SyntheticChainSource {
    async fn latest_block(&self) -> IndexerResult<u64> {
        Ok(20_000_000)
    }
    async fn events_in_range(
        &self,
        _from_block: u64,
        _to_block: u64,
    ) -> IndexerResult<Vec<RailgunEvent>> {
        Err(IndexerError::Rpc("synthetic: events_in_range".into()))
    }
    async fn root_history(
        &self,
        _tree_number: u32,
        merkle_root: [u8; 32],
        _at: Option<BlockId>,
    ) -> IndexerResult<bool> {
        self.verify_calls.fetch_add(1, Ordering::SeqCst);
        *self.last_seen_root.lock() = merkle_root;
        Ok(true)
    }
    async fn block_hash(&self, _block_number: u64) -> IndexerResult<[u8; 32]> {
        Err(IndexerError::Rpc("synthetic: block_hash".into()))
    }
    async fn merkle_root(&self, _at: Option<BlockId>) -> IndexerResult<[u8; 32]> {
        self.verify_calls.fetch_add(1, Ordering::SeqCst);
        Ok(*self.last_seen_root.lock())
    }
    async fn active_tree_number(&self, _at: Option<BlockId>) -> IndexerResult<u32> {
        // Fixed 3: trees 0/1/2 are frozen-branch (root_history alone),
        // tree 3 is active-branch (root_history + merkle_root).
        Ok(3)
    }
}

fn rewrite_to_tempdir(src: &Path, tmp: &Path, bind: SocketAddr, token: &str) -> std::path::PathBuf {
    let body = std::fs::read_to_string(src).expect("read example toml");
    let mut out = body;
    out = out.replace("/var/lib/raven-railgun/", &format!("{}/", tmp.display()));
    out = out.replace("0.0.0.0:8080", &bind.to_string());
    out = out.replace("REPLACE_ME", token);
    let path = tmp.join("config.toml");
    std::fs::write(&path, out).expect("write rewritten config");
    path
}

fn example_toml_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/mainnet-6-instance.toml")
}

/// `aggressive_snapshot` overrides per-instance `SnapshotPolicy` to
/// `max_appends_per_snapshot = 1` so each event triggers a commit;
/// tests exercising the cadence-1 verifier opt in.
fn build_opts(
    tmp: &Path,
    bind: SocketAddr,
    observer: BootstrapObserver,
    chain_sources: &[Arc<SyntheticChainSource>],
    aggressive_snapshot: bool,
) -> MultiServeOptions {
    let cfg_path = rewrite_to_tempdir(&example_toml_path(), tmp, bind, BEARER_TOKEN);
    let mut opts = load_options_from_toml(&cfg_path).expect("parse config");
    opts.bind = bind;
    opts.skip_chain_workers = true;
    opts.skip_mirror_workers = true;
    opts.entries = 256;

    let mut chain_idx = 0usize;
    for inst in &mut opts.instances {
        inst.use_flock = false;
        if aggressive_snapshot {
            inst.snapshot_policy = SnapshotPolicy {
                max_appends_per_snapshot: 1,
                ..SnapshotPolicy::default()
            };
        }
        if matches!(inst.data_source, DataSourceFilter::ChainTreeNumber(_)) {
            inst.verification_cadence_n = 1;
            let src = chain_sources
                .get(chain_idx)
                .expect("caller supplied a chain source per commit-tree instance");
            inst.chain_source = Some(Arc::clone(src) as Arc<dyn ChainSource>);
            chain_idx += 1;
        }
    }
    opts.bootstrap_observer = Some(observer);
    opts
}

fn parse_hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = s.as_bytes()[i * 2];
        let lo = s.as_bytes()[i * 2 + 1];
        let nib = |c: u8| match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("non-hex byte"),
        };
        *byte = (nib(hi) << 4) | nib(lo);
    }
    out
}

fn canonical_commit(seed: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = seed.max(1);
    b
}

async fn spawn_server(
    opts: MultiServeOptions,
) -> (
    SocketAddr,
    tokio::task::JoinHandle<anyhow::Result<()>>,
    oneshot::Sender<()>,
) {
    let listener = tokio::net::TcpListener::bind(opts.bind)
        .await
        .expect("bind ephemeral");
    let local_addr = listener.local_addr().expect("local_addr");
    let (tx, rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        run_with_listener(opts, listener, async move {
            let _ = rx.await;
        })
        .await
    });
    (local_addr, server, tx)
}

async fn wait_for_status(local_addr: SocketAddr) -> StatusJson {
    let url = format!("http://{local_addr}/v1/status");
    let client = reqwest::Client::new();
    let mut last_err: Option<String> = None;
    for _ in 0..240u32 {
        match client.get(&url).bearer_auth(BEARER_TOKEN).send().await {
            Ok(resp) if resp.status().is_success() => {
                return resp.json().await.expect("parse status json");
            }
            Ok(resp) => last_err = Some(format!("HTTP {}", resp.status())),
            Err(e) => last_err = Some(e.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("status never returned 2xx; last_err = {last_err:?}");
}

async fn wait_for_observer(observer: &BootstrapObserver) -> BootstrapView {
    for _ in 0..480u32 {
        if let Some(view) = observer.lock().clone() {
            return view;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("bootstrap observer never populated");
}

async fn shutdown(
    tx: oneshot::Sender<()>,
    server: tokio::task::JoinHandle<anyhow::Result<()>>,
) -> anyhow::Result<()> {
    let _ = tx.send(());
    match tokio::time::timeout(Duration::from_secs(20), server).await {
        Ok(Ok(res)) => res,
        Ok(Err(join_err)) => Err(anyhow::anyhow!("server task join error: {join_err}")),
        Err(_) => Err(anyhow::anyhow!("server shutdown timed out")),
    }
}

/// Cancels the server task without firing the graceful-shutdown
/// oneshot, so consumer tasks exit on channel-close without a final
/// `drive_commit`; WAL tail survives for cold-restart replay.
async fn abort_without_final_commit(
    _tx: oneshot::Sender<()>,
    server: tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    server.abort();
    let _ = tokio::time::timeout(Duration::from_secs(20), server).await;
    // Let consumers release per-instance Persistence Arcs (file locks)
    // before restart attempts to reacquire them.
    tokio::time::sleep(Duration::from_millis(500)).await;
}

async fn drive_synthetic_events(
    view: &BootstrapView,
    list_key_ofac: [u8; 32],
    list_key_railway: [u8; 32],
) {
    let chain = &view.channels.indexer_tx;
    let mirror = &view.channels.mirror_tx;

    chain
        .send(IndexerMessage::Event {
            event: RailgunEvent::Shield {
                block_number: 100,
                tx_hash: [0u8; 32],
                tree_number: 0,
                start_position: 0,
                leaves: vec![CommitmentLeaf {
                    tree_number: 0,
                    leaf_index: 0,
                    commitment_hash: canonical_commit(0xA0),
                    ciphertext: vec![],
                }],
            },
            block_height: 100,
        })
        .await
        .expect("send tree-0 shield");
    chain
        .send(IndexerMessage::Event {
            event: RailgunEvent::Transact {
                block_number: 200,
                tx_hash: [0u8; 32],
                tree_number: 2,
                start_position: 0,
                leaves: vec![CommitmentLeaf {
                    tree_number: 2,
                    leaf_index: 0,
                    commitment_hash: canonical_commit(0xC2),
                    ciphertext: vec![],
                }],
            },
            block_height: 200,
        })
        .await
        .expect("send tree-2 transact");
    chain
        .send(IndexerMessage::Event {
            event: RailgunEvent::Shield {
                block_number: 300,
                tx_hash: [0u8; 32],
                tree_number: 3,
                start_position: 0,
                leaves: vec![CommitmentLeaf {
                    tree_number: 3,
                    leaf_index: 0,
                    commitment_hash: canonical_commit(0xD3),
                    ciphertext: vec![],
                }],
            },
            block_height: 300,
        })
        .await
        .expect("send tree-3 shield");
    chain
        .send(IndexerMessage::Event {
            event: RailgunEvent::Nullified {
                block_number: 400,
                tx_hash: [0u8; 32],
                tree_number: 1,
                nullifiers: vec![canonical_commit(0xB1)],
            },
            block_height: 400,
        })
        .await
        .expect("send tree-1 nullified");

    mirror
        .send((
            WalEntryPayload::PpoiListLeafAdded {
                list_key: list_key_ofac,
                list_index: 0,
                blinded_commitment: canonical_commit(0x71),
                status: 0,
            },
            0,
        ))
        .await
        .expect("send ofac leaf");
    mirror
        .send((
            WalEntryPayload::PpoiStatus {
                list_key: list_key_ofac,
                blinded_commitment: canonical_commit(0x71),
                status: 1,
            },
            0,
        ))
        .await
        .expect("send ofac status");
    mirror
        .send((
            WalEntryPayload::PpoiListLeafAdded {
                list_key: list_key_railway,
                list_index: 0,
                blinded_commitment: canonical_commit(0x82),
                status: 0,
            },
            0,
        ))
        .await
        .expect("send railway leaf");
    mirror
        .send((
            WalEntryPayload::PpoiStatus {
                list_key: list_key_railway,
                blinded_commitment: canonical_commit(0x82),
                status: 2,
            },
            0,
        ))
        .await
        .expect("send railway status");
}

async fn wait_for_apply(view: &BootstrapView, deadline_secs: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(deadline_secs);
    loop {
        let mut all_ready = true;
        for inst in &view.instances {
            match inst.data_source {
                DataSourceFilter::ChainTreeNumber(t) => {
                    let store = inst.logical_store.lock();
                    let leaves = store.imt_leaf_count_for(t);
                    let nullified_only = t == 1;
                    if !nullified_only && leaves == 0 {
                        all_ready = false;
                        break;
                    }
                    if nullified_only {
                        let m = inst.metrics.lock();
                        if m.events_processed == 0 {
                            all_ready = false;
                            break;
                        }
                    }
                }
                DataSourceFilter::PpoiList(lk) => {
                    let store = inst.logical_store.lock();
                    if store.ppoi_list_leaves_iter(&lk).next().is_none() {
                        all_ready = false;
                        break;
                    }
                }
            }
        }
        if all_ready {
            return;
        }
        assert!(
            tokio::time::Instant::now() <= deadline,
            "apply did not complete within {deadline_secs} s"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn six_synthetic_sources() -> Vec<Arc<SyntheticChainSource>> {
    (0..4)
        .map(|_| Arc::new(SyntheticChainSource::new()))
        .collect()
}

fn find_inst<'a>(view: &'a BootstrapView, id: &str) -> &'a BootstrapInstanceView {
    view.instances
        .iter()
        .find(|i| i.instance_id.as_str() == id)
        .unwrap_or_else(|| panic!("no instance {id}"))
}

// Closure 1: bootstrap surfaces all six instances + their encoder labels.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stands up 6 InsPIRe instances; ~10 s wall on Zen 5"]
async fn six_instance_bootstrap_serves_status_for_all_six() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let observer: BootstrapObserver = Arc::new(parking_lot::Mutex::new(None));
    let chain_sources = six_synthetic_sources();
    let opts = build_opts(
        tmp.path(),
        bind,
        Arc::clone(&observer),
        &chain_sources,
        false,
    );

    let (local_addr, server, stop) = spawn_server(opts).await;
    let body = wait_for_status(local_addr).await;
    let view = wait_for_observer(&observer).await;

    assert_eq!(body.instances.len(), 6, "/v1/status must list 6 instances");
    let ids: Vec<&str> = body.instances.iter().map(|i| i.id.as_str()).collect();
    for expect in [
        "commitments-tree-0",
        "commitments-tree-1",
        "commitments-tree-2",
        "commitments-tree-live",
        "ppoi-status-ofac",
        "ppoi-path-railway",
    ] {
        assert!(
            ids.iter().any(|id| *id == expect),
            "missing {expect} in {ids:?}"
        );
    }

    assert_eq!(view.instances.len(), 6);
    let label_for = |id: &str| find_inst(&view, id).encoder_label;
    assert_eq!(label_for("commitments-tree-0"), "per-node");
    assert_eq!(label_for("commitments-tree-1"), "per-node");
    assert_eq!(label_for("commitments-tree-2"), "per-node");
    assert_eq!(label_for("commitments-tree-live"), "per-node");
    assert_eq!(label_for("ppoi-status-ofac"), "per-list-status");
    assert_eq!(label_for("ppoi-path-railway"), "per-list-node");

    shutdown(stop, server).await.expect("graceful shutdown");
}

// Closure 2: chain events route to the correct commit-tree instance only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stands up 6 InsPIRe instances; drives 4 chain events; ~12 s wall on Zen 5"]
async fn chain_events_route_to_correct_commit_tree_instance() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let observer: BootstrapObserver = Arc::new(parking_lot::Mutex::new(None));
    let chain_sources = six_synthetic_sources();
    let opts = build_opts(
        tmp.path(),
        bind,
        Arc::clone(&observer),
        &chain_sources,
        false,
    );

    let lk_ofac = parse_hex32(PPOI_LIST_OFAC_HEX);
    let lk_railway = parse_hex32(PPOI_LIST_RAILWAY_HEX);

    let (_local_addr, server, stop) = spawn_server(opts).await;
    let view = wait_for_observer(&observer).await;
    drive_synthetic_events(&view, lk_ofac, lk_railway).await;
    wait_for_apply(&view, 25).await;

    for inst in &view.instances {
        match inst.data_source {
            DataSourceFilter::ChainTreeNumber(0) => {
                let store = inst.logical_store.lock();
                assert_eq!(
                    store.leaf(0, 0).copied(),
                    Some(canonical_commit(0xA0)),
                    "tree-0 must hold its shield leaf"
                );
                let m = inst.metrics.lock();
                assert_eq!(m.last_applied_block, 100);
                assert_eq!(m.events_processed, 1);
            }
            DataSourceFilter::ChainTreeNumber(2) => {
                let store = inst.logical_store.lock();
                assert_eq!(
                    store.leaf(2, 0).copied(),
                    Some(canonical_commit(0xC2)),
                    "tree-2 must hold its transact leaf"
                );
                let m = inst.metrics.lock();
                assert_eq!(m.last_applied_block, 200);
                assert_eq!(m.events_processed, 1);
            }
            DataSourceFilter::ChainTreeNumber(3) => {
                let store = inst.logical_store.lock();
                assert_eq!(
                    store.leaf(3, 0).copied(),
                    Some(canonical_commit(0xD3)),
                    "tree-3 must hold its shield leaf"
                );
                let m = inst.metrics.lock();
                assert_eq!(m.last_applied_block, 300);
                assert_eq!(m.events_processed, 1);
            }
            DataSourceFilter::ChainTreeNumber(1) => {
                let m = inst.metrics.lock();
                assert_eq!(
                    m.events_processed, 1,
                    "tree-1 must have processed its nullified event"
                );
                assert_eq!(m.last_applied_block, 400);
                let store = inst.logical_store.lock();
                assert_eq!(
                    store.imt_leaf_count_for(0),
                    0,
                    "tree-1 must NOT see tree-0 leaves"
                );
                assert_eq!(
                    store.imt_leaf_count_for(2),
                    0,
                    "tree-1 must NOT see tree-2 leaves"
                );
                assert_eq!(
                    store.imt_leaf_count_for(3),
                    0,
                    "tree-1 must NOT see tree-3 leaves"
                );
            }
            DataSourceFilter::ChainTreeNumber(other) => {
                panic!("unexpected commit-tree number {other}");
            }
            DataSourceFilter::PpoiList(_) => {
                let m = inst.metrics.lock();
                assert_eq!(
                    m.last_applied_block, 0,
                    "PPOI instance must NOT see chain events ({} block-height seen)",
                    m.last_applied_block
                );
            }
        }
    }

    shutdown(stop, server).await.expect("graceful shutdown");
}

// Closure 3: PPOI events route to the matching list-key instance only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stands up 6 InsPIRe instances; drives 4 PPOI events; ~12 s wall on Zen 5"]
async fn ppoi_events_route_to_correct_list_instance() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let observer: BootstrapObserver = Arc::new(parking_lot::Mutex::new(None));
    let chain_sources = six_synthetic_sources();
    let opts = build_opts(
        tmp.path(),
        bind,
        Arc::clone(&observer),
        &chain_sources,
        false,
    );

    let lk_ofac = parse_hex32(PPOI_LIST_OFAC_HEX);
    let lk_railway = parse_hex32(PPOI_LIST_RAILWAY_HEX);

    let (_local_addr, server, stop) = spawn_server(opts).await;
    let view = wait_for_observer(&observer).await;
    drive_synthetic_events(&view, lk_ofac, lk_railway).await;
    wait_for_apply(&view, 25).await;

    for inst in &view.instances {
        match inst.data_source {
            DataSourceFilter::PpoiList(k) if k == lk_ofac => {
                let store = inst.logical_store.lock();
                assert_eq!(
                    store.ppoi_bc_at(&lk_ofac, 0),
                    Some(canonical_commit(0x71)),
                    "ofac instance must hold its leaf"
                );
                assert_eq!(
                    store.ppoi_status_at(&lk_ofac, 0),
                    Some(1),
                    "ofac instance must hold the status update"
                );
                assert!(
                    store.ppoi_list_leaves_iter(&lk_railway).next().is_none(),
                    "ofac instance must NOT see railway leaves"
                );
            }
            DataSourceFilter::PpoiList(k) if k == lk_railway => {
                let store = inst.logical_store.lock();
                assert_eq!(
                    store.ppoi_bc_at(&lk_railway, 0),
                    Some(canonical_commit(0x82)),
                    "railway instance must hold its leaf"
                );
                assert_eq!(
                    store.ppoi_status_at(&lk_railway, 0),
                    Some(2),
                    "railway instance must hold the status update"
                );
                assert!(
                    store.ppoi_list_leaves_iter(&lk_ofac).next().is_none(),
                    "railway instance must NOT see ofac leaves"
                );
            }
            DataSourceFilter::PpoiList(_) => panic!("unexpected ppoi list_key"),
            DataSourceFilter::ChainTreeNumber(_) => {
                let store = inst.logical_store.lock();
                assert_eq!(
                    store.ppoi_count(),
                    0,
                    "commit-tree instance must NOT receive PPOI status rows"
                );
            }
        }
    }

    shutdown(stop, server).await.expect("graceful shutdown");
}

// Closure 4: layer 2 verifier fires only on commit-tree instances.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stands up 6 InsPIRe instances; drives 4 chain events + asserts L2 cadence; ~14 s wall"]
async fn layer2_fires_only_on_commit_tree_instances() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let observer: BootstrapObserver = Arc::new(parking_lot::Mutex::new(None));
    let chain_sources = six_synthetic_sources();
    // Aggressive snapshot policy: each event triggers a commit so
    // the cadence-1 verifier loop fires. Entries bumped to match
    // entries_per_shard so the re-encode path is shape-stable
    // (re-encoding with a different shape than the initial setup
    // would produce a polynomial vector of mismatched length).
    let mut opts = build_opts(
        tmp.path(),
        bind,
        Arc::clone(&observer),
        &chain_sources,
        true,
    );
    opts.entries = 2048;

    let (_local_addr, server, stop) = spawn_server(opts).await;
    let view = wait_for_observer(&observer).await;

    // Toy cell shape (256 entries × 2048 EPS = 1 shard) only fits
    // tree-0 leaves into shard 0; tree-N (N>0) leaves map out of range.
    // One commit-tree firing the verifier suffices to lock the positive arm.
    view.channels
        .indexer_tx
        .send(IndexerMessage::Event {
            event: RailgunEvent::Shield {
                block_number: 100,
                tx_hash: [0u8; 32],
                tree_number: 0,
                start_position: 0,
                leaves: vec![CommitmentLeaf {
                    tree_number: 0,
                    leaf_index: 0,
                    commitment_hash: canonical_commit(0xA0),
                    ciphertext: vec![],
                }],
            },
            block_height: 100,
        })
        .await
        .expect("send tree-0 shield");

    let tree0 = view
        .instances
        .iter()
        .find(|i| matches!(i.data_source, DataSourceFilter::ChainTreeNumber(0)))
        .expect("tree-0 instance present");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let m = *tree0.metrics.lock();
        if m.commits_fired >= 1 || m.consumer_errors > 0 {
            break;
        }
        assert!(
            tokio::time::Instant::now() <= deadline,
            "tree-0 did not commit within 60 s"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(1000)).await;

    assert!(
        chain_sources[0].verify_count() >= 1,
        "tree-0 verifier must have fired at least once; got {}",
        chain_sources[0].verify_count(),
    );

    // PPOI instances must record 0 reorgs/commits — verifier never
    // runs (no chain_source) and no events were routed to them.
    for inst in &view.instances {
        if matches!(inst.data_source, DataSourceFilter::PpoiList(_)) {
            let m = inst.metrics.lock();
            assert_eq!(
                m.reorgs_handled, 0,
                "PPOI instance {} must record 0 reorgs",
                inst.instance_id
            );
            assert_eq!(
                m.commits_fired, 0,
                "PPOI instance {} must record 0 commits",
                inst.instance_id
            );
        }
    }

    shutdown(stop, server).await.expect("graceful shutdown");
}

// Closure 5: kill + restart preserves per-instance state from disk.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stands up 6 InsPIRe instances twice (kill + restart cycle); ~25 s wall on Zen 5"]
async fn kill_restart_preserves_per_instance_state() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("addr");

    let lk_ofac = parse_hex32(PPOI_LIST_OFAC_HEX);
    let lk_railway = parse_hex32(PPOI_LIST_RAILWAY_HEX);

    // Phase 1: cold boot, drive events, capture per-instance state.
    let observer1: BootstrapObserver = Arc::new(parking_lot::Mutex::new(None));
    let chain_sources1 = six_synthetic_sources();
    let opts1 = build_opts(
        tmp.path(),
        bind,
        Arc::clone(&observer1),
        &chain_sources1,
        false,
    );

    let (_addr1, server1, stop1) = spawn_server(opts1).await;
    let view1 = wait_for_observer(&observer1).await;
    drive_synthetic_events(&view1, lk_ofac, lk_railway).await;
    wait_for_apply(&view1, 25).await;

    let mut chain_pre: Vec<(u32, u64, Option<[u8; 32]>)> = Vec::new();
    let mut ppoi_pre: Vec<([u8; 32], Option<[u8; 32]>)> = Vec::new();
    for inst in &view1.instances {
        match inst.data_source {
            DataSourceFilter::ChainTreeNumber(t) => {
                let store = inst.logical_store.lock();
                let m = inst.metrics.lock();
                chain_pre.push((t, m.last_applied_block, store.leaf(t, 0).copied()));
            }
            DataSourceFilter::PpoiList(k) => {
                let store = inst.logical_store.lock();
                ppoi_pre.push((k, store.ppoi_bc_at(&k, 0)));
            }
        }
    }

    // Hard-kill: aborting drops `bootstrap` in place; consumers exit on
    // channel-close without a final `drive_commit`. WAL tail past
    // `current_snapshot_seq` is the V1 carrier for the LogicalLeafStore
    // sidecar (snapshotted state alone does not carry it).
    abort_without_final_commit(stop1, server1).await;

    // Phase 2: cold restart from the same data_dirs.
    let observer2: BootstrapObserver = Arc::new(parking_lot::Mutex::new(None));
    let chain_sources2 = six_synthetic_sources();
    let opts2 = build_opts(
        tmp.path(),
        bind,
        Arc::clone(&observer2),
        &chain_sources2,
        false,
    );
    let (_addr2, server2, stop2) = spawn_server(opts2).await;
    let view2 = wait_for_observer(&observer2).await;

    // Let consumers finish recovery + apply tail WAL entries.
    tokio::time::sleep(Duration::from_millis(500)).await;

    for (t, _pre_block, pre_leaf) in &chain_pre {
        let inst = view2
            .instances
            .iter()
            .find(|i| matches!(i.data_source, DataSourceFilter::ChainTreeNumber(tt) if tt == *t))
            .unwrap_or_else(|| panic!("no commit-tree instance for tree {t} after restart"));
        let store = inst.logical_store.lock();
        let post_leaf = store.leaf(*t, 0).copied();
        assert_eq!(
            post_leaf, *pre_leaf,
            "tree-{t} leaf must match pre-shutdown after restart"
        );
    }
    for (k, pre_bc) in &ppoi_pre {
        let inst = view2
            .instances
            .iter()
            .find(|i| matches!(i.data_source, DataSourceFilter::PpoiList(kk) if kk == *k))
            .unwrap_or_else(|| panic!("no ppoi instance for list {k:?} after restart"));
        let store = inst.logical_store.lock();
        assert_eq!(
            store.ppoi_bc_at(k, 0),
            *pre_bc,
            "ppoi list leaf must match pre-shutdown after restart"
        );
    }

    shutdown(stop2, server2).await.expect("second shutdown");
}

// Closure 6: bootstrap refuses when manifest encoder_label diverges.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stands up 6 InsPIRe instances once + retries one with mismatched encoder; ~14 s wall"]
async fn manifest_label_mismatch_refuses_boot_per_instance() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("addr");

    let observer1: BootstrapObserver = Arc::new(parking_lot::Mutex::new(None));
    let chain_sources1 = six_synthetic_sources();
    let opts1 = build_opts(
        tmp.path(),
        bind,
        Arc::clone(&observer1),
        &chain_sources1,
        false,
    );
    let (_addr1, server1, stop1) = spawn_server(opts1).await;
    let _view1 = wait_for_observer(&observer1).await;
    shutdown(stop1, server1).await.expect("first shutdown");

    // Phase 2: same data_dirs but flip commitments-tree-0's encoder
    // (PerLeafPath -> PerNode). Both are commit-tree-valid; only the
    // manifest verifier rejects the mismatch.
    let observer2: BootstrapObserver = Arc::new(parking_lot::Mutex::new(None));
    let chain_sources2 = six_synthetic_sources();
    let mut opts2 = build_opts(
        tmp.path(),
        bind,
        Arc::clone(&observer2),
        &chain_sources2,
        false,
    );
    for inst in &mut opts2.instances {
        if inst.instance_id.as_str() == "commitments-tree-0" {
            inst.encoder = EncoderKind::PerNode { tree_number: 0 };
        }
    }

    let listener = tokio::net::TcpListener::bind(bind).await.expect("bind");
    let (tx, rx) = oneshot::channel::<()>();
    let result = run_with_listener(opts2, listener, async move {
        let _ = rx.await;
    })
    .await;
    let _ = tx.send(());

    let err = result.expect_err("bootstrap must reject encoder_label mismatch");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("encoder_label") || msg.contains("encoder label"),
        "expected encoder_label-mismatch error, got: {msg}",
    );
}

#[test]
fn example_toml_parses_to_six_instances_with_expected_encoders() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let cfg = rewrite_to_tempdir(&example_toml_path(), tmp.path(), bind, BEARER_TOKEN);
    let opts = load_options_from_toml(&cfg).expect("parse");
    assert_eq!(opts.instances.len(), 6);
    let labels: Vec<&'static str> = opts.instances.iter().map(|i| i.encoder.label()).collect();
    let want = [
        "per-node",
        "per-node",
        "per-node",
        "per-node",
        "per-list-status",
        "per-list-node",
    ];
    assert_eq!(labels, want, "encoder labels drifted");

    for inst in &opts.instances {
        match inst.data_source {
            DataSourceFilter::ChainTreeNumber(_) => assert_eq!(
                inst.verification_mode,
                VerificationMode::ChainRootHistory,
                "{} must use ChainRootHistory",
                inst.instance_id
            ),
            DataSourceFilter::PpoiList(_) => assert_eq!(
                inst.verification_mode,
                VerificationMode::UpstreamSignature,
                "{} must use UpstreamSignature",
                inst.instance_id
            ),
        }
    }
}
