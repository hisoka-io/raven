//! A per-list row whose list index has no record must decode as ABSENT to ANY reader, and a
//! row below the list frontier served that way must be counted and logged.
//!
//! "Any reader" is the weakest one: it maps the status byte and checks nothing else, not the
//! leaf and not the format marker. The SDK checks both, and its refusal is not what this proves.
//! Status byte 0 is `Valid`, the verdict that authorizes a spend, so a zero-filled row is the
//! fail-open case.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::rlwe::RlweSecretKey;
use raven_railgun_core::{AdapterError, InstanceId, POIStatus};
use raven_railgun_engine::imt::Imt;
use raven_railgun_engine::inspire::{
    apply_wal_entry, build_client_session, build_seeded_query, extract_response,
    register_client_session, setup_state, InspireServerState, LogicalLeafStore, RavenInspireScheme,
};
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine_multi, DataSourceFilter, InstanceConfig,
};
use raven_railgun_engine::persistence::{ConsumerEvent, RetentionPolicy, SnapshotPolicy};
use raven_railgun_engine::pir_table::list::PATH10_MAGIC;
use raven_railgun_engine::pir_table::{
    EncoderKind, PerListPath10Encoder, PirTableEncoder, PATH10_RECORD_BYTES,
};
use raven_railgun_engine::{InstanceRole, PirScheme};
use raven_railgun_persistence::{PpoiEventType, WalEntryPayload};

const LIST_KEY: [u8; 32] = [0x6b; 32];
const EPS: u32 = 2048;
const PATH10_STATUS: usize = 32;
const PATH10_MARKER: std::ops::Range<usize> = 34..38;
const UNFILLED: &str = "raven_railgun_pir_unfilled_rows_total";

/// Rows 0 and 2: filled. Row 1: no leaf, below the frontier. Rows 3 and up: past the frontier.
const FIRST: u32 = 0;
const HOLE: u32 = 1;
const FILLED: u32 = 2;
const FRONTIER: u32 = 3;

/// Fr-canonical and distinct per index.
fn bc_for(list_index: u32) -> [u8; 32] {
    let mut bc = [0u8; 32];
    bc[0] = 0x0a;
    bc[1..5].copy_from_slice(&list_index.to_be_bytes());
    bc[31] = 0x01;
    bc
}

fn leaf(list_index: u32) -> WalEntryPayload {
    rooted_leaf(list_index, [0; 32])
}

fn rooted_leaf(list_index: u32, validated_merkleroot: [u8; 32]) -> WalEntryPayload {
    WalEntryPayload::PpoiListLeafAdded {
        list_key: LIST_KEY,
        list_index,
        blinded_commitment: bc_for(list_index),
        event_type: PpoiEventType::Shield,
        validated_merkleroot,
    }
}

/// The weakest reader: the status byte alone, mapped the way the wire defines it.
fn verdict(byte: u8) -> Option<POIStatus> {
    [
        POIStatus::Valid,
        POIStatus::ShieldBlocked,
        POIStatus::ProofSubmitted,
        POIStatus::Missing,
    ]
    .into_iter()
    .find(|status| status.wire_byte() == byte)
}

/// A below-frontier absence, reached through the public apply path alone.
///
/// Leaf 1 lands at a height above leaf 2, so a rewind between them takes leaf 1 and keeps leaf
/// 2: the tree keeps three leaves and row 1 has no record.
fn store_with_a_hole(encoder: &dyn PirTableEncoder) -> LogicalLeafStore {
    let mut store = LogicalLeafStore::new();
    for (payload, height) in [
        (leaf(FIRST), 100),
        (leaf(HOLE), 300),
        (leaf(FILLED), 200),
        (WalEntryPayload::Reorg { height: 250 }, 250),
    ] {
        apply_wal_entry(&mut store, &payload, height, encoder).expect("apply");
    }
    assert_eq!(
        store.ppoi_imt(&LIST_KEY).map(Imt::leaf_count),
        Some(FRONTIER as usize),
        "precondition: the frontier stays at three leaves"
    );
    assert!(
        store.ppoi_bc_at(&LIST_KEY, HOLE).is_none(),
        "precondition: row 1 has no leaf"
    );
    assert!(
        store.ppoi_bc_at(&LIST_KEY, FIRST).is_some(),
        "precondition: row 0 keeps its leaf"
    );
    store
}

fn path10_encoder() -> PerListPath10Encoder {
    PerListPath10Encoder::new(EPS, LIST_KEY).expect("path10 encoder")
}

fn rows(bytes: &[u8], width: usize) -> Vec<&[u8]> {
    assert_eq!(bytes.len(), EPS as usize * width, "one shard of rows");
    bytes.chunks_exact(width).collect()
}

#[test]
fn every_path10_row_without_a_record_has_no_marker_and_reads_missing() {
    let encoder = path10_encoder();
    let store = store_with_a_hole(&encoder);

    let shard = encoder.materialize_shard(0, &store);
    for (list_index, row) in rows(&shard, PATH10_RECORD_BYTES).into_iter().enumerate() {
        let filled = list_index == FILLED as usize || list_index == FIRST as usize;
        assert_eq!(
            &row[PATH10_MARKER] == PATH10_MAGIC.as_slice(),
            filled,
            "path10 row {list_index}: the marker must be present exactly when the row is filled"
        );
        let expected = if filled {
            POIStatus::Valid
        } else {
            POIStatus::Missing
        };
        assert_eq!(
            verdict(row[PATH10_STATUS]),
            Some(expected),
            "path10 row {list_index} must read {expected:?} to a reader that skips the marker"
        );
    }

    for (label, bytes) in [
        ("past the tail", encoder.materialize_shard(1, &store)),
        (
            "empty list",
            encoder.materialize_shard(0, &LogicalLeafStore::new()),
        ),
    ] {
        for row in bytes.as_chunks::<PATH10_RECORD_BYTES>().0 {
            assert_ne!(
                &row[PATH10_MARKER],
                PATH10_MAGIC.as_slice(),
                "{label}: no marker"
            );
            assert_eq!(
                verdict(row[PATH10_STATUS]),
                Some(POIStatus::Missing),
                "{label}"
            );
        }
    }
}

/// Every `raven::pir_table` warn, as field name to rendered value.
#[derive(Clone, Default)]
struct WarnLog(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

struct Fields(BTreeMap<String, String>);

impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0.insert(field.name().to_owned(), value.to_string());
    }
}

impl tracing::Subscriber for WarnLog {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        let mut fields = Fields(BTreeMap::new());
        event.record(&mut fields);
        if fields.0.get("target").map(String::as_str) == Some("raven::pir_table") {
            self.0.lock().expect("warn log").push(fields.0);
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Keyed by the `encoder` and `missing` labels.
type Counts = BTreeMap<(String, String), u64>;
type Warns = Vec<BTreeMap<String, String>>;

fn unfilled_counts(snapshotter: &Snapshotter) -> Counts {
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(composite, _, _, value)| {
            let key = composite.key();
            if key.name() != UNFILLED {
                return None;
            }
            let label = |name: &str| {
                key.labels()
                    .find(|l| l.key() == name)
                    .map(|l| l.value().to_owned())
                    .unwrap_or_default()
            };
            match value {
                DebugValue::Counter(count) => Some(((label("encoder"), label("missing")), count)),
                _ => None,
            }
        })
        .collect()
}

/// Materialize shards 0 and 1 and return what was counted and logged.
fn observe(encoder: &dyn PirTableEncoder, store: &LogicalLeafStore) -> (Counts, Warns) {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let log = WarnLog::default();
    metrics::with_local_recorder(&recorder, || {
        tracing::subscriber::with_default(log.clone(), || {
            encoder.materialize_shard(0, store);
            encoder.materialize_shard(1, store);
        });
    });
    let warns = log.0.lock().expect("warn log").clone();
    (unfilled_counts(&snapshotter), warns)
}

fn assert_counted_and_named(encoder: &dyn PirTableEncoder) {
    let store = store_with_a_hole(encoder);
    let (counts, warns) = observe(encoder, &store);
    let label = encoder.label().to_owned();
    assert_eq!(
        counts,
        BTreeMap::from([((label.clone(), "leaf".to_owned()), 1)]),
        "{label}: exactly the below-frontier hole counts; the {} padding rows past the \
         frontier in shard 0 and the whole of shard 1 must not",
        EPS - FRONTIER
    );
    let named: BTreeSet<(String, String, String)> = warns
        .iter()
        .map(|w| {
            (
                w.get("list_key").cloned().unwrap_or_default(),
                w.get("list_index").cloned().unwrap_or_default(),
                w.get("missing").cloned().unwrap_or_default(),
            )
        })
        .collect();
    let key_hex = "6b".repeat(32);
    assert_eq!(
        named,
        BTreeSet::from([(key_hex, HOLE.to_string(), "leaf".to_owned())]),
        "{label}: one warn per unfilled row, naming the list and the index"
    );
    assert_eq!(warns.len(), 1, "{label}: no warn for padding");

    let clean = {
        let mut store = LogicalLeafStore::new();
        for i in 0..FRONTIER {
            apply_wal_entry(&mut store, &leaf(i), 100, encoder).expect("apply");
        }
        store
    };
    let (counts, warns) = observe(encoder, &clean);
    assert!(
        counts.values().all(|c| *c == 0) && warns.is_empty(),
        "{label}: a list with no holes serves padding silently: {counts:?} {warns:?}"
    );
}

#[test]
fn the_path10_encoder_counts_and_names_each_unfilled_row_and_never_padding() {
    assert_counted_and_named(&path10_encoder());
}

/// The bytes a client decrypts, not the bytes handed to the encoder: a real query, the
/// server's respond and the client's extract.
fn decrypt_rows(
    state: &InspireServerState,
    secret_key: RlweSecretKey,
    list_indices: &[u32],
) -> Vec<Vec<u8>> {
    let params = InspireParams::secure_128_d2048();
    let mut session =
        build_client_session((*state.crs).clone(), secret_key, &params).expect("client session");
    register_client_session(&mut session, state).expect("register session");
    list_indices
        .iter()
        .map(|list_index| {
            let (client_state, query) = build_seeded_query(
                &session,
                state.shard_config(),
                u64::from(*list_index),
                &params,
            )
            .expect("query");
            let response =
                <RavenInspireScheme as PirScheme>::respond(state, &query).expect("respond");
            extract_response(&state.crs, &client_state, &response, state.entry_size)
                .expect("extract")
        })
        .collect()
}

/// One shard served through setup, then decrypted.
fn served_rows(database: &[u8], entry_size: usize, list_indices: &[u32]) -> Vec<Vec<u8>> {
    let params = InspireParams::secure_128_d2048();
    let (state, secret_key) =
        setup_state(&params, database, entry_size, InspireVariant::TwoPacking).expect("setup");
    decrypt_rows(&state, secret_key, list_indices)
}

#[test]
fn a_served_path10_row_with_no_record_decrypts_to_missing_without_a_marker() {
    let encoder = path10_encoder();
    let store = store_with_a_hole(&encoder);
    let database = encoder.materialize_shard(0, &store);
    let indices = [HOLE, FRONTIER + 7];
    let served = served_rows(&database, PATH10_RECORD_BYTES, &indices);
    for (list_index, row) in indices.into_iter().zip(served) {
        assert_ne!(
            &row[PATH10_MARKER],
            PATH10_MAGIC.as_slice(),
            "row {list_index}"
        );
        assert_eq!(
            verdict(row[PATH10_STATUS]),
            Some(POIStatus::Missing),
            "served path10 row {list_index}"
        );
    }
}

const BOOTED_SHARDS: usize = 2;

/// Bytes a fresh-state factory may seed before the first commit. Byte j of row r is
/// (r + j) % 251, so `Valid` recurs every 251 rows at any status offset.
fn seeded_rows(width: usize) -> Vec<u8> {
    (0..BOOTED_SHARDS * EPS as usize)
        .flat_map(|r| (0..width).map(move |j| u8::try_from((r + j) % 251).unwrap_or(0)))
        .collect()
}

/// Boots one instance over a seeded two-shard table, feeds it the list's first `FRONTIER`
/// leaves with their upstream roots, and decrypts `list_indices` from the state it serves once
/// the commit those leaves trigger has landed.
async fn served_after_commit(
    encoder: EncoderKind,
    width: usize,
    list_indices: &[u32],
) -> Vec<Vec<u8>> {
    let params = InspireParams::secure_128_d2048();
    let (fresh, secret_key) = setup_state(
        &params,
        &seeded_rows(width),
        width,
        InspireVariant::TwoPacking,
    )
    .expect("setup");
    let mut fresh = Some(fresh);
    let dir = tempfile::tempdir().expect("tempdir");
    let config = InstanceConfig {
        instance_id: InstanceId::new(format!("unwritten-rows-{}", encoder.label())),
        role: InstanceRole::Live,
        data_dir: dir.path().join("instance"),
        encoder,
        record_size: width,
        entries_per_shard: EPS,
        data_source: DataSourceFilter::PpoiListBlock {
            list_key: LIST_KEY,
            block: 0,
        },
        use_flock: false,
        snapshot_policy: SnapshotPolicy {
            max_appends_per_snapshot: FRONTIER as usize,
            max_seconds_between_snapshots: u64::MAX,
            retention: RetentionPolicy::default(),
        },
        scheme_tag: "raven-inspire-twopacking-inspiring-wp3-unwritten-rows".to_owned(),
        channel_capacity: 64,
        max_concurrent_queries: None,
        verification_cadence_n: 0,
        chain_source: None,
    };
    let handle = bootstrap_railgun_engine_multi(vec![config], params, |_| {
        fresh
            .take()
            .ok_or_else(|| AdapterError::Internal("factory reused".to_owned()))
    })
    .expect("boot");
    let booted = handle.instances.first().expect("one instance");

    let mut upstream = Imt::new().expect("reference tree");
    for list_index in 0..FRONTIER {
        upstream
            .insert_leaves(list_index as usize, &[bc_for(list_index)])
            .expect("reference insert");
        let row = rooted_leaf(list_index, upstream.root());
        booted
            .sender
            .send(ConsumerEvent::Ppoi(row, 100))
            .await
            .expect("consumer open");
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        let metrics = *booted.metrics.lock();
        assert_eq!(
            metrics.consumer_errors, 0,
            "every leaf carries its own root"
        );
        if metrics.commits_fired >= 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the feed's commit did not land"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let rows = decrypt_rows(&booted.instance.current_state(), secret_key, list_indices);
    for instance in &handle.instances {
        instance.consumer.abort();
    }
    handle.router.abort();
    rows
}

/// Every leaf dirties shard 0, so the commit rewrites all of it from the encoder: no seeded row
/// may survive there, including row 219, which the seed makes `Valid` at the status offset:
/// (219 + 32) % 251 == 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_booted_path10_instance_serves_unmarked_missing_rows_across_a_committed_shard() {
    const SEEDED_VALID: u32 = 219;
    assert_eq!(
        verdict(
            seeded_rows(PATH10_RECORD_BYTES)
                [SEEDED_VALID as usize * PATH10_RECORD_BYTES + PATH10_STATUS]
        ),
        Some(POIStatus::Valid),
        "precondition: the seed reads Valid at row {SEEDED_VALID}"
    );
    let indices = [FILLED, FRONTIER, SEEDED_VALID, EPS - 1];
    let served = served_after_commit(
        EncoderKind::PerListPath10 { list_key: LIST_KEY },
        PATH10_RECORD_BYTES,
        &indices,
    )
    .await;
    for (list_index, row) in indices.into_iter().zip(&served) {
        let filled = list_index == FILLED;
        assert_eq!(
            &row[PATH10_MARKER] == PATH10_MAGIC.as_slice(),
            filled,
            "served path10 row {list_index}: the marker must be present exactly when filled"
        );
        let expected = if filled {
            POIStatus::Valid
        } else {
            POIStatus::Missing
        };
        assert_eq!(
            verdict(row[PATH10_STATUS]),
            Some(expected),
            "served path10 row {list_index} after the commit"
        );
    }
    assert_eq!(&served[0][..32], &bc_for(FILLED), "the encoder's leaf");
}
