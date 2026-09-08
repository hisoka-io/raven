//! Reorg-window sidecar persistence: the Layer 1 reorg cache must
//! survive an indexer restart and rebuild from RPC when the chain
//! advanced (or reorged) past the persisted top during downtime.
//!
//! Also covers codec-level invariants: tampered CRC, wrong magic, and
//! wrong version must all surface as load errors rather than silently
//! returning drift.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::needless_continue,
    clippy::match_same_arms,
    clippy::cast_possible_truncation
)]

use async_trait::async_trait;
use raven_railgun_core::RailgunEvent;
use raven_railgun_indexer::{
    decode_reorg_window, encode_reorg_window, load_reorg_window, persist_reorg_window, ChainSource,
    IndexerError, IndexerMessage, IndexerWorker, IndexerWorkerConfig, Result, REORG_WINDOW_MAGIC,
    REORG_WINDOW_VERSION,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// One recorded RPC call; the order distinguishes "consulted the loaded
/// window before scanning" from "started cold".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MockOp {
    LatestBlock,
    BlockHash(u64),
}

#[derive(Debug, Default)]
struct WindowMockSource {
    inner: Mutex<MockInner>,
}

#[derive(Debug, Default)]
struct MockInner {
    chain: BTreeMap<u64, [u8; 32]>,
    latest: u64,
    ops: Vec<MockOp>,
}

impl WindowMockSource {
    fn new() -> Self {
        Self::default()
    }
    fn set_block(&self, n: u64, hash: [u8; 32]) {
        let mut g = self.inner.lock().expect("lock");
        g.chain.insert(n, hash);
        g.latest = g.latest.max(n);
    }
    fn rewrite(&self, from: u64, to: u64, new_hash: [u8; 32]) {
        let mut g = self.inner.lock().expect("lock");
        for n in from..=to {
            g.chain.insert(n, new_hash);
        }
    }
    fn clear_ops(&self) {
        self.inner.lock().expect("lock").ops.clear();
    }
    fn ops(&self) -> Vec<MockOp> {
        self.inner.lock().expect("lock").ops.clone()
    }
}

#[async_trait]
impl ChainSource for WindowMockSource {
    async fn latest_block(&self) -> Result<u64> {
        let mut g = self.inner.lock().expect("lock");
        g.ops.push(MockOp::LatestBlock);
        Ok(g.latest)
    }
    async fn events_in_range(&self, _from: u64, _to: u64) -> Result<Vec<RailgunEvent>> {
        Ok(Vec::new())
    }
    async fn root_history(
        &self,
        _t: u32,
        _r: [u8; 32],
        _at: Option<alloy::eips::BlockId>,
    ) -> Result<bool> {
        Ok(true)
    }
    async fn block_hash(&self, n: u64) -> Result<[u8; 32]> {
        let mut g = self.inner.lock().expect("lock");
        g.ops.push(MockOp::BlockHash(n));
        g.chain
            .get(&n)
            .copied()
            .ok_or_else(|| IndexerError::Rpc(format!("block {n} not in mock chain")))
    }
    async fn merkle_root(&self, _at: Option<alloy::eips::BlockId>) -> Result<[u8; 32]> {
        Err(IndexerError::Rpc("not used".into()))
    }
    async fn active_tree_number(&self, _at: Option<alloy::eips::BlockId>) -> Result<u32> {
        Err(IndexerError::Rpc("not used".into()))
    }
}

fn sample_cache() -> BTreeMap<u64, [u8; 32]> {
    let mut m = BTreeMap::new();
    m.insert(100, [0xaa; 32]);
    m.insert(101, [0xbb; 32]);
    m.insert(102, [0xcc; 32]);
    m
}

#[test]
fn reorg_window_codec_round_trips_a_known_map() {
    let cache = sample_cache();
    let bytes = encode_reorg_window(&cache);
    assert_eq!(&bytes[..8], &REORG_WINDOW_MAGIC, "magic prefix must match");
    let decoded = decode_reorg_window(&bytes).expect("decode ok");
    assert_eq!(decoded, cache, "decode must be the inverse of encode");
}

/// Locks the magic/version: the exact bytes are part of the on-disk wire contract.
#[test]
fn reorg_window_magic_constant_locked_to_rvnrgidx() {
    assert_eq!(REORG_WINDOW_MAGIC, *b"RVNRGIDX");
    assert_eq!(REORG_WINDOW_VERSION, 1u16);
}

/// Tampered CRC fails the load.
#[test]
fn reorg_window_decode_rejects_tampered_crc() {
    let cache = sample_cache();
    let mut bytes = encode_reorg_window(&cache);
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    let err = decode_reorg_window(&bytes).expect_err("must fail CRC");
    let msg = format!("{err}");
    assert!(msg.contains("CRC"), "expected CRC error; got {msg}");
}

/// Wrong magic fails the load.
#[test]
fn reorg_window_decode_rejects_wrong_magic() {
    let cache = sample_cache();
    let mut bytes = encode_reorg_window(&cache);
    bytes[0] = b'X';
    let err = decode_reorg_window(&bytes).expect_err("must fail magic");
    let msg = format!("{err}");
    // wrong magic also breaks the CRC, so either error is a valid fail-closed outcome.
    assert!(
        msg.contains("magic") || msg.contains("CRC"),
        "expected magic or CRC error; got {msg}"
    );
}

/// Wrong version fails the load.
#[test]
fn reorg_window_decode_rejects_wrong_version() {
    let cache = sample_cache();
    // Encode the body manually so the CRC over a version-bumped body
    // still validates, isolating the version-mismatch path from the
    // CRC path.
    let mut body = Vec::new();
    body.extend_from_slice(&REORG_WINDOW_MAGIC);
    let bad_version: u16 = REORG_WINDOW_VERSION.wrapping_add(7);
    body.extend_from_slice(&bad_version.to_le_bytes());
    let count = u32::try_from(cache.len()).expect("u32");
    body.extend_from_slice(&count.to_le_bytes());
    for (h, hash) in &cache {
        body.extend_from_slice(&h.to_le_bytes());
        body.extend_from_slice(hash);
    }
    let crc = crc32_ieee(&body);
    let mut bytes = body;
    bytes.extend_from_slice(&crc.to_le_bytes());
    let err = decode_reorg_window(&bytes).expect_err("must fail version");
    let msg = format!("{err}");
    assert!(msg.contains("version"), "expected version error; got {msg}");
}

/// Atomic-rename: a stale `.tmp` left behind from a torn write must not
/// prevent the final write on retry, and the final `<path>` must load
/// cleanly afterwards.
#[test]
fn reorg_window_persist_recovers_after_dangling_tmp() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("reorg_window.bin");

    // Simulate a previous torn write: a leftover `.tmp` with garbage.
    let tmp_path = {
        let mut name = std::ffi::OsString::from(path.file_name().expect("filename"));
        name.push(".tmp");
        path.with_file_name(name)
    };
    std::fs::write(&tmp_path, b"corrupt-leftover-from-prior-run").expect("write tmp");
    assert!(tmp_path.is_file());

    let cache = sample_cache();
    persist_reorg_window(&path, &cache).expect("persist ok");
    assert!(path.is_file(), "final sidecar must exist after persist");

    let loaded = load_reorg_window(&path).expect("load ok");
    assert_eq!(loaded, cache);
}

/// Load on a missing file returns an empty map (fresh-start path).
#[test]
fn reorg_window_load_returns_empty_for_missing_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nonexistent.bin");
    assert!(!path.exists());
    let loaded = load_reorg_window(&path).expect("load ok on missing");
    assert!(loaded.is_empty());
}

/// Wait until a heartbeat reports `scanned_through_block >= watermark`.
/// The persist of a chunk tip happens before the heartbeat that announces it,
/// so a satisfied wait means the sidecar for that tip is already on disk.
async fn wait_for_watermark(
    rx: &mut mpsc::Receiver<IndexerMessage>,
    watermark: u64,
    budget: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + budget;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
            Ok(Some(IndexerMessage::Heartbeat {
                scanned_through_block,
                ..
            })) if scanned_through_block >= watermark => return true,
            Ok(Some(_)) => continue,
            Ok(None) => return false,
            Err(_) => continue,
        }
    }
    false
}

/// Drive a worker run to populate the sidecar, then restart against the same
/// chain: the persisted window must carry the exact chunk-tip hashes, and the
/// restarted worker must consult that loaded window (stale-check on its top)
/// before it does anything else. "Emits something after restart" proves
/// neither; a build with the sidecar load deleted passed the previous
/// version of this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indexer_reorg_window_persists_across_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("indexer_reorg_window.bin");

    let src = Arc::new(WindowMockSource::new());
    for n in 0..=50u64 {
        src.set_block(n, [u8::try_from(n & 0xff).expect("byte"); 32]);
    }

    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(256);
    let worker = IndexerWorker::new(Arc::clone(&src), tx);
    let cfg = IndexerWorkerConfig {
        start_block: 0,
        poll_interval_secs: 1,
        chunk_blocks: 49,
        reorg_window_path: Some(path.clone()),
        reorg_window_entries: 256,
        ..IndexerWorkerConfig::default()
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });
    assert!(
        wait_for_watermark(&mut rx, 50, Duration::from_secs(10)).await,
        "first run must scan through the chain tip"
    );
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), join).await;

    // Exact bytes, not just presence: chunk tips 49 and 50 with the mock hashes.
    let expected: BTreeMap<u64, [u8; 32]> = [(49u64, [49u8; 32]), (50u64, [50u8; 32])]
        .into_iter()
        .collect();
    let persisted = load_reorg_window(&path).expect("first-run sidecar loads");
    assert_eq!(
        persisted, expected,
        "sidecar must hold exactly the scanned chunk-tip hashes"
    );

    src.clear_ops();
    let (tx2, mut rx2) = mpsc::channel::<IndexerMessage>(256);
    let worker2 = IndexerWorker::new(Arc::clone(&src), tx2);
    let cfg2 = IndexerWorkerConfig {
        start_block: 49,
        poll_interval_secs: 1,
        chunk_blocks: 49,
        reorg_window_path: Some(path.clone()),
        reorg_window_entries: 256,
        ..IndexerWorkerConfig::default()
    };
    let join2 = tokio::spawn(async move { worker2.run(cfg2).await });
    assert!(
        wait_for_watermark(&mut rx2, 50, Duration::from_secs(10)).await,
        "post-restart worker must scan back to the tip"
    );
    drop(rx2);
    let _ = tokio::time::timeout(Duration::from_secs(5), join2).await;

    // The startup stale-check runs before the first poll tick, so the first
    // recorded RPC call proves the persisted window top (50) was loaded and
    // consulted; a cold start opens with `latest_block` instead.
    let ops = src.ops();
    assert_eq!(
        ops.first(),
        Some(&MockOp::BlockHash(50)),
        "restart must verify the loaded window top before scanning; ops={ops:?}"
    );
}

/// Reorg-while-down: the persisted top hash no longer matches the canonical
/// chain; the worker must rebuild from RPC at startup and persist the rebuilt
/// window. Only the sidecar's post-restart CONTENT can prove that: a build
/// with the rebuild branch disabled passed the previous version of this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indexer_reorg_window_rebuilds_when_chain_advanced_past_cache() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("indexer_reorg_window.bin");

    let src = Arc::new(WindowMockSource::new());
    for n in 0..=20u64 {
        src.set_block(n, [u8::try_from(n & 0xff).expect("byte"); 32]);
    }

    let (tx, mut rx) = mpsc::channel::<IndexerMessage>(64);
    let worker = IndexerWorker::new(Arc::clone(&src), tx);
    let cfg = IndexerWorkerConfig {
        start_block: 0,
        poll_interval_secs: 1,
        chunk_blocks: 19,
        reorg_window_path: Some(path.clone()),
        reorg_window_entries: 32,
        ..IndexerWorkerConfig::default()
    };
    let join = tokio::spawn(async move { worker.run(cfg).await });
    assert!(
        wait_for_watermark(&mut rx, 20, Duration::from_secs(8)).await,
        "first run must scan through the chain tip"
    );
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(3), join).await;

    let stale = load_reorg_window(&path).expect("first-run sidecar loads");
    assert_eq!(
        stale.get(&20),
        Some(&[20u8; 32]),
        "first run must persist the pre-reorg tip hash"
    );

    src.rewrite(0, 20, [0xff; 32]);

    let (tx2, mut rx2) = mpsc::channel::<IndexerMessage>(64);
    let worker2 = IndexerWorker::new(Arc::clone(&src), tx2);
    let cfg2 = IndexerWorkerConfig {
        start_block: 20,
        poll_interval_secs: 1,
        chunk_blocks: 19,
        reorg_window_path: Some(path.clone()),
        reorg_window_entries: 32,
        ..IndexerWorkerConfig::default()
    };
    let join2 = tokio::spawn(async move { worker2.run(cfg2).await });
    let deadline2 = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut got_post = false;
    while tokio::time::Instant::now() < deadline2 && !got_post {
        match tokio::time::timeout(Duration::from_millis(800), rx2.recv()).await {
            Ok(Some(_)) => got_post = true,
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    assert!(got_post, "post-rebuild worker must continue emitting");
    drop(rx2);
    let _ = tokio::time::timeout(Duration::from_secs(3), join2).await;

    let rebuilt = load_reorg_window(&path).expect("post-rebuild sidecar loads");
    assert_eq!(
        rebuilt.get(&20),
        Some(&[0xff_u8; 32]),
        "the stale top must be replaced by the post-reorg canonical hash; \
         sidecar still carries {:?}",
        rebuilt.get(&20)
    );
    assert!(
        rebuilt.len() >= 2 && rebuilt.values().all(|h| *h == [0xff_u8; 32]),
        "the rebuilt window must span below the top with canonical hashes; got {} entries",
        rebuilt.len()
    );
}

// Deleted here: indexer_reorg_window_falls_back_to_empty_on_missing_sidecar.
// The fresh-boot half (no sidecar: worker still scans, persists a canonical
// fresh sidecar) is held by indexer_reorg_window_persists_across_restart, whose
// first leg asserts the exact persisted map; the empty-load half is held by
// reorg_window_load_returns_empty_for_missing_file. Both proven RED under a
// persist-no-op mutant that also killed the test this comment replaces.

/// Local CRC32 (IEEE polynomial) used by the wrong-version test to
/// recompute the CRC over a hand-crafted body. Mirrors the crate's
/// internal `crc32` helper.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = u32::try_from(i).expect("u32");
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *slot = c;
    }
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        let idx = ((crc ^ u32::from(b)) & 0xff) as usize;
        crc = table[idx] ^ (crc >> 8);
    }
    crc ^ 0xffff_ffff
}
