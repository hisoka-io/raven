//! Real-data signature oracle: a recorded capture of an upstream PPOI list, served by the replay
//! over loopback, fed through the production mirror feed with signature checks on. Every row
//! must verify under the list key, the rows served without `0x` included, and a row planted with
//! a changed signature, index, type or commitment must be refused by index and never sent.
//!
//! By hand, with a capture folder in the replay crate's format:
//! `PPOI_REPLAY_CAPTURE=<folder> cargo test --manifest-path adapters/railgun/Cargo.toml
//! -p raven-railgun-ppoi-replay --profile ci-test --test capture_signatures -- --ignored
//! --nocapture`.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::too_many_lines,
    reason = "by-hand oracle; the receipt is the printed run"
)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use raven_railgun_core::ListKey;
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_ppoi_mirror::{
    FeedProgress, FeedStatus, MirrorConfig, MirrorError, PreflightFailure, UpstreamPpoiMirror,
};
use raven_railgun_ppoi_replay::{
    parse_noncanonical_jsonl, Capture, ChainScope, EventRow, EventType, Replay, WireOverride,
};
use tokio::sync::mpsc;

const CAPTURE_ENV: &str = "PPOI_REPLAY_CAPTURE";
/// A wait fails only when nothing moves for this long.
const STALL: Duration = Duration::from_secs(60);

struct Folder {
    list_key: [u8; 32],
    rows: Vec<EventRow>,
    overrides: BTreeMap<u32, WireOverride>,
    scope: ChainScope,
    node_status: Vec<u8>,
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn load(folder: &Path) -> Folder {
    let (capture, scope) = Capture::load_dir(folder).expect("capture folder loads");
    let noncanonical = folder.join("noncanonical.jsonl");
    let overrides = if noncanonical.exists() {
        parse_noncanonical_jsonl(
            std::str::from_utf8(&read(&noncanonical)).expect("noncanonical.jsonl is UTF-8"),
        )
        .expect("overrides parse")
    } else {
        BTreeMap::new()
    };
    Folder {
        list_key: *capture.list_key(),
        rows: capture.rows().to_vec(),
        overrides,
        scope,
        node_status: read(&folder.join("node-status-end.json")),
    }
}

async fn serve(
    folder: &Folder,
    rows: Vec<EventRow>,
    overrides: BTreeMap<u32, WireOverride>,
) -> (String, tokio::task::JoinHandle<()>) {
    let served = rows.len();
    let capture = Capture::new(folder.list_key, rows, overrides).expect("capture rebuilds");
    let replay = Replay::new(capture, folder.scope.clone(), &folder.node_status, served)
        .expect("replay serves the folder");
    let (addr, server) = common::spawn(Arc::new(replay)).await;
    (format!("http://{addr}"), server)
}

fn checking_mirror(endpoint: String, scope: &ChainScope) -> Arc<UpstreamPpoiMirror> {
    Arc::new(
        UpstreamPpoiMirror::new(MirrorConfig {
            endpoint,
            chain_type: scope.chain_type.to_string(),
            chain_id: u64::from(scope.chain_id),
            txid_version: scope.txid_version.clone(),
            poll_interval_secs: 1,
            verify_signatures: true,
            ..MirrorConfig::default()
        })
        .expect("mirror config")
        .with_backfill_interval(Duration::ZERO),
    )
}

fn wal_type(event_type: EventType) -> raven_railgun_persistence::PpoiEventType {
    use raven_railgun_persistence::PpoiEventType;
    match event_type {
        EventType::Shield => PpoiEventType::Shield,
        EventType::Transact => PpoiEventType::Transact,
        EventType::Unshield => PpoiEventType::Unshield,
        EventType::LegacyTransact => PpoiEventType::LegacyTransact,
    }
}

fn hex(bytes: &[u8]) -> String {
    common::hex(bytes)
}

/// One way to plant a bad row, and the index the feed must refuse.
struct Plant {
    case: &'static str,
    refused_at: u32,
    rows: Vec<EventRow>,
    overrides: BTreeMap<u32, WireOverride>,
}

fn plants(folder: &Folder, unprefixed: u32, prefixed: u32) -> Vec<Plant> {
    let base = |case, refused_at| Plant {
        case,
        refused_at,
        rows: folder.rows.clone(),
        overrides: folder.overrides.clone(),
    };
    let sync_override = |plant: &mut Plant, at: u32| {
        let row = plant.rows[at as usize].clone();
        if let Some(wire) = plant.overrides.get_mut(&at) {
            wire.signature = hex(&row.signature);
            row.event_type.wire_name().clone_into(&mut wire.event_type);
            wire.blinded_commitment = hex(&row.blinded_commitment);
        }
    };
    let mut out = Vec::new();
    for at in [unprefixed, prefixed] {
        let mut plant = base("a flipped signature", at);
        plant.rows[at as usize].signature[7] ^= 0x01;
        sync_override(&mut plant, at);
        out.push(plant);

        let mut plant = base("another event type", at);
        let row = &mut plant.rows[at as usize];
        row.event_type = if row.event_type == EventType::Shield {
            EventType::Transact
        } else {
            EventType::Shield
        };
        sync_override(&mut plant, at);
        out.push(plant);

        let mut plant = base("a flipped commitment", at);
        plant.rows[at as usize].blinded_commitment[31] ^= 0x01;
        sync_override(&mut plant, at);
        out.push(plant);

        let mut plant = base("a row moved to the next index", at + 1);
        let mut moved = plant.rows[at as usize].clone();
        moved.index = at + 1;
        plant.rows[at as usize + 1] = moved;
        plant.overrides.remove(&(at + 1));
        if let Some(wire) = plant.overrides.get(&at).cloned() {
            plant.overrides.insert(at + 1, wire);
        }
        out.push(plant);
    }
    // Served with `0x` like every other row, the unprefixed row no longer matches what was signed.
    let mut plant = base("an unprefixed commitment given 0x", unprefixed);
    plant.overrides.remove(&unprefixed);
    out.push(plant);
    out
}

async fn refused_once_asked_from(
    mirror: Arc<UpstreamPpoiMirror>,
    list_key: [u8; 32],
    at: u32,
) -> (FeedProgress, usize) {
    let status = FeedStatus::default();
    let (tx, mut rx) = mpsc::channel(8);
    let at = u64::from(at);
    let feed = tokio::spawn(mirror.run_feed(
        ListKey(list_key),
        at,
        move |cursor| cursor..at + 1,
        status.clone(),
        tx,
    ));
    let progress = tokio::time::timeout(STALL, async {
        loop {
            let progress = status.snapshot();
            if progress.signatures_refused > 0 || progress.stopped.is_some() {
                return progress;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the planted row is answered");
    feed.abort();
    let mut sent = 0;
    while rx.try_recv().is_ok() {
        sent += 1;
    }
    (progress, sent)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an operator capture folder named by PPOI_REPLAY_CAPTURE, which is not in the \
            repository; about 20 s at ci-test. Trigger: run by hand when the feed's decoder or \
            signature check, or the captured list, changes"]
async fn every_captured_row_verifies_at_ingest_and_planted_forgeries_are_refused() {
    let folder = PathBuf::from(
        std::env::var(CAPTURE_ENV)
            .unwrap_or_else(|_| panic!("{CAPTURE_ENV} is unset; name a capture folder")),
    );
    let folder = load(&folder);
    let total = folder.rows.len();
    let unprefixed: Vec<u32> = folder
        .overrides
        .iter()
        .filter(|(_, wire)| !wire.blinded_commitment.starts_with("0x"))
        .map(|(index, _)| *index)
        .collect();
    eprintln!(
        "capture: {total} rows, {} served without 0x at {unprefixed:?}",
        unprefixed.len()
    );
    assert!(
        !unprefixed.is_empty(),
        "fixture: no unprefixed row to prove"
    );

    let (endpoint, server) = serve(&folder, folder.rows.clone(), folder.overrides.clone()).await;
    let mirror = checking_mirror(endpoint, &folder.scope);
    let status = FeedStatus::default();
    let (tx, mut rx) = mpsc::channel(4_096);
    let started = Instant::now();
    let end = u64::try_from(total).expect("row count");
    let feed = tokio::spawn(Arc::clone(&mirror).run_feed(
        ListKey(folder.list_key),
        0,
        move |cursor| cursor..end,
        status.clone(),
        tx,
    ));
    let mut delivered = 0usize;
    while delivered < total {
        let (payload, _) = tokio::time::timeout(STALL, rx.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "nothing for {STALL:?} after {delivered} rows: {:?}",
                    status.snapshot()
                )
            })
            .expect("the feed stays open until the last row");
        let WalEntryPayload::PpoiListLeafAdded {
            list_index,
            blinded_commitment,
            event_type,
            signature,
            validated_merkleroot,
            ..
        } = payload
        else {
            panic!("row {delivered} reached the engine as {payload:?}");
        };
        let row = &folder.rows[delivered];
        assert_eq!(list_index, row.index);
        assert_eq!(
            blinded_commitment, row.blinded_commitment,
            "row {delivered}"
        );
        assert_eq!(event_type, wal_type(row.event_type), "row {delivered}");
        assert_eq!(signature, row.signature.to_vec(), "row {delivered}");
        assert_eq!(
            validated_merkleroot, row.validated_merkleroot,
            "row {delivered}"
        );
        delivered += 1;
    }
    let stopped = tokio::time::timeout(STALL, feed)
        .await
        .expect("the feed stops at the end of its span")
        .expect("feed task");
    assert!(
        matches!(stopped, Err(MirrorError::Unheld { list_index }) if list_index == end),
        "{stopped:?}"
    );
    let progress = status.snapshot();
    assert_eq!(
        (progress.signatures_refused, progress.rows_delivered),
        (0, end),
        "every captured row verifies"
    );
    eprintln!(
        "all {total} rows verified and delivered in {:?}",
        started.elapsed()
    );
    server.abort();

    let prefixed = unprefixed[0] - 1;
    assert!(!folder.overrides.contains_key(&prefixed));
    for plant in plants(&folder, unprefixed[0], prefixed) {
        let (endpoint, server) = serve(&folder, plant.rows, plant.overrides).await;
        let (progress, sent) = refused_once_asked_from(
            checking_mirror(endpoint, &folder.scope),
            folder.list_key,
            plant.refused_at,
        )
        .await;
        server.abort();
        assert_eq!(
            (
                progress.last_failure,
                progress.next_index,
                progress.rows_delivered,
                sent
            ),
            (
                Some(PreflightFailure::BadSignature(u64::from(plant.refused_at))),
                u64::from(plant.refused_at),
                0,
                0
            ),
            "{} at row {}",
            plant.case,
            plant.refused_at
        );
        eprintln!("refused {} at row {}", plant.case, plant.refused_at);
    }
}
