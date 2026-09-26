//! A per-list row whose list index has no record must decode as ABSENT to ANY reader, and a
//! row below the list frontier served that way must be counted and logged.
//!
//! "Any reader" is the weakest one: it maps the status byte and checks nothing else, no BC
//! tail and no format marker. The SDK checks both, and its refusal is not what this proves.
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
    bootstrap_railgun_engine_multi, DataSourceFilter, InstanceConfig, VerificationMode,
    LEAVES_PER_PPOI_BLOCK,
};
use raven_railgun_engine::persistence::{ConsumerEvent, RetentionPolicy, SnapshotPolicy};
use raven_railgun_engine::pir_table::list::PATH10_MAGIC;
use raven_railgun_engine::pir_table::{
    EncoderKind, PerListPath10Encoder, PerListStatusEncoder, PirTableEncoder, LEAVES_PER_TREE,
    PATH10_RECORD_BYTES,
};
use raven_railgun_engine::{InstanceRole, PirScheme};
use raven_railgun_persistence::{PpoiEventType, WalEntryPayload};

const LIST_KEY: [u8; 32] = [0x6b; 32];
const STATUS_RECORD: usize = 32;
const EPS: u32 = 2048;
const PATH10_STATUS: usize = 32;
const PATH10_MARKER: std::ops::Range<usize> = 34..38;
const UNFILLED: &str = "raven_railgun_pir_unfilled_rows_total";

/// Row 0: leaf kept, status rolled back. Row 1: no leaf, below the frontier. Row 2: filled,
/// `Valid`. Rows 3 and up: past the frontier.
const DROPPED_STATUS: u32 = 0;
const HOLE: u32 = 1;
const FILLED: u32 = 2;
const FRONTIER: u32 = 3;

/// Fr-canonical, distinct per index, and non-zero in the bytes a status row's tail carries.
fn bc_for(list_index: u32) -> [u8; 32] {
    let mut bc = [0u8; 32];
    bc[0] = 0x0a;
    bc[1..5].copy_from_slice(&list_index.to_be_bytes());
    bc[31] = 0x01;
    bc
}

fn leaf(list_index: u32, status: POIStatus) -> WalEntryPayload {
    rooted_leaf(list_index, status, [0; 32])
}

fn rooted_leaf(
    list_index: u32,
    status: POIStatus,
    validated_merkleroot: [u8; 32],
) -> WalEntryPayload {
    WalEntryPayload::PpoiListLeafAdded {
        list_key: LIST_KEY,
        list_index,
        blinded_commitment: bc_for(list_index),
        status: status.wire_byte(),
        event_type: PpoiEventType::Shield,
        signature: vec![0; 64],
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

/// Both below-frontier absences, reached through the public apply path alone.
///
/// Leaf 1 lands at a height above leaf 2, so a rewind between them takes leaf 1 and keeps leaf
/// 2: the tree keeps three leaves and row 1 has no record. Leaf 0's later ShieldBlocked update
/// is rewound too, which leaves the leaf with no status at all.
fn store_with_both_absences(encoder: &dyn PirTableEncoder) -> LogicalLeafStore {
    let mut store = LogicalLeafStore::new();
    for (payload, height) in [
        (leaf(DROPPED_STATUS, POIStatus::Valid), 100),
        (leaf(HOLE, POIStatus::Valid), 300),
        (leaf(FILLED, POIStatus::Valid), 200),
        (
            WalEntryPayload::PpoiStatus {
                list_key: LIST_KEY,
                blinded_commitment: bc_for(DROPPED_STATUS),
                status: POIStatus::ShieldBlocked.wire_byte(),
            },
            260,
        ),
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
        store.ppoi_bc_at(&LIST_KEY, DROPPED_STATUS).is_some()
            && store.ppoi_status_at(&LIST_KEY, DROPPED_STATUS).is_none(),
        "precondition: row 0 keeps its leaf and loses its status"
    );
    store
}

fn status_encoder() -> PerListStatusEncoder {
    PerListStatusEncoder::new(STATUS_RECORD, EPS, LIST_KEY).expect("status encoder")
}

fn path10_encoder() -> PerListPath10Encoder {
    PerListPath10Encoder::new(EPS, LIST_KEY).expect("path10 encoder")
}

fn rows(bytes: &[u8], width: usize) -> Vec<&[u8]> {
    assert_eq!(bytes.len(), EPS as usize * width, "one shard of rows");
    bytes.chunks_exact(width).collect()
}

#[test]
fn every_status_row_without_a_verdict_reads_missing_and_only_a_real_verdict_reads_valid() {
    let encoder = status_encoder();
    let store = store_with_both_absences(&encoder);

    let shard = encoder.materialize_shard(0, &store);
    for (list_index, row) in rows(&shard, STATUS_RECORD).into_iter().enumerate() {
        let expected = if list_index == FILLED as usize {
            POIStatus::Valid
        } else {
            POIStatus::Missing
        };
        assert_eq!(
            verdict(row[0]),
            Some(expected),
            "status row {list_index} must read {expected:?}"
        );
    }
    let by_index = rows(&shard, STATUS_RECORD);
    assert_eq!(&by_index[FILLED as usize][1..], &bc_for(FILLED)[..31]);
    assert_eq!(
        &by_index[DROPPED_STATUS as usize][1..],
        &bc_for(DROPPED_STATUS)[..31]
    );
    assert!(
        by_index[HOLE as usize][1..].iter().all(|b| *b == 0),
        "no record, no tail"
    );

    let past_the_tail = encoder.materialize_shard(1, &store);
    assert!(
        rows_read(&past_the_tail, STATUS_RECORD, 0).all(|v| v == Some(POIStatus::Missing)),
        "a shard wholly past the frontier must read Missing on every row"
    );
    let empty = encoder.materialize_shard(0, &LogicalLeafStore::new());
    assert!(
        rows_read(&empty, STATUS_RECORD, 0).all(|v| v == Some(POIStatus::Missing)),
        "a list with no leaves must read Missing on every row"
    );
}

fn rows_read(
    bytes: &[u8],
    width: usize,
    status_offset: usize,
) -> impl Iterator<Item = Option<POIStatus>> + '_ {
    bytes
        .chunks_exact(width)
        .map(move |row| verdict(row[status_offset]))
}

#[test]
fn every_path10_row_without_a_record_has_no_marker_and_reads_missing() {
    let encoder = path10_encoder();
    let store = store_with_both_absences(&encoder);

    let shard = encoder.materialize_shard(0, &store);
    for (list_index, row) in rows(&shard, PATH10_RECORD_BYTES).into_iter().enumerate() {
        let filled = list_index == FILLED as usize || list_index == DROPPED_STATUS as usize;
        assert_eq!(
            &row[PATH10_MARKER] == PATH10_MAGIC.as_slice(),
            filled,
            "path10 row {list_index}: the marker must be present exactly when the row is filled"
        );
        let expected = if list_index == FILLED as usize {
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
    let store = store_with_both_absences(encoder);
    let (counts, warns) = observe(encoder, &store);
    let label = encoder.label().to_owned();
    assert_eq!(
        counts,
        BTreeMap::from([
            ((label.clone(), "leaf".to_owned()), 1),
            ((label.clone(), "status".to_owned()), 1),
        ]),
        "{label}: exactly the two below-frontier rows count; the {} padding rows past the \
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
        BTreeSet::from([
            (key_hex.clone(), HOLE.to_string(), "leaf".to_owned()),
            (key_hex, DROPPED_STATUS.to_string(), "status".to_owned()),
        ]),
        "{label}: one warn per unfilled row, naming the list and the index"
    );
    assert_eq!(warns.len(), 2, "{label}: no warn for padding");

    let clean = {
        let mut store = LogicalLeafStore::new();
        for i in 0..FRONTIER {
            apply_wal_entry(&mut store, &leaf(i, POIStatus::Valid), 100, encoder).expect("apply");
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
fn the_status_encoder_counts_and_names_each_unfilled_row_and_never_padding() {
    assert_counted_and_named(&status_encoder());
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
fn a_served_status_row_with_no_record_decrypts_to_missing() {
    let encoder = status_encoder();
    let store = store_with_both_absences(&encoder);
    let database = encoder.materialize_shard(0, &store);
    let cases = [
        (HOLE, POIStatus::Missing),
        (FRONTIER + 7, POIStatus::Missing),
        (DROPPED_STATUS, POIStatus::Missing),
        (FILLED, POIStatus::Valid),
    ];
    let indices: Vec<u32> = cases.iter().map(|(list_index, _)| *list_index).collect();
    let served = served_rows(&database, STATUS_RECORD, &indices);
    for ((list_index, expected), row) in cases.into_iter().zip(served) {
        assert_eq!(
            verdict(row[0]),
            Some(expected),
            "served status row {list_index}"
        );
    }
}

#[test]
fn a_served_path10_row_with_no_record_decrypts_to_missing_without_a_marker() {
    let encoder = path10_encoder();
    let store = store_with_both_absences(&encoder);
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
        verification_mode: VerificationMode::UpstreamAsserted,
        data_source: DataSourceFilter::PpoiList(LIST_KEY),
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
        let row = rooted_leaf(list_index, POIStatus::Valid, upstream.root());
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
/// may survive there, including row 251, which the seed makes `Valid`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_booted_status_instance_serves_missing_rows_across_a_committed_shard() {
    const SEEDED_VALID: u32 = 251;
    assert_eq!(
        verdict(seeded_rows(STATUS_RECORD)[SEEDED_VALID as usize * STATUS_RECORD]),
        Some(POIStatus::Valid),
        "precondition: the seed reads Valid at row {SEEDED_VALID}"
    );
    let cases = [
        (0, POIStatus::Valid),
        (FILLED, POIStatus::Valid),
        (FRONTIER, POIStatus::Missing),
        (SEEDED_VALID, POIStatus::Missing),
        (EPS - 1, POIStatus::Missing),
    ];
    let indices: Vec<u32> = cases.iter().map(|(list_index, _)| *list_index).collect();
    let served = served_after_commit(
        EncoderKind::PerListStatus { list_key: LIST_KEY },
        STATUS_RECORD,
        &indices,
    )
    .await;
    for ((list_index, expected), row) in cases.into_iter().zip(&served) {
        assert_eq!(
            verdict(row[0]),
            Some(expected),
            "served status row {list_index} after the commit"
        );
    }
    assert_eq!(&served[1][1..], &bc_for(FILLED)[..31], "the encoder's row");
}

/// The path10 twin. Row 219 is seeded `Valid` at the status offset: (219 + 32) % 251 == 0.
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

/// A status table holds one tree, and the client asks status at the list index, never by block.
/// Rows for indices past that tree are written nowhere because apply refuses the index before any
/// row or dirty mark exists, not because this dirty set drops it. Every index the table holds
/// dirties the shard carrying its row. A row past the table is never served: the client refuses
/// to ask for it and the server refuses a query for a shard it does not hold.
#[test]
fn the_status_dirty_set_covers_every_index_the_instance_can_hold_and_nothing_else_arrives() {
    let encoder = status_encoder();
    let shards = LEAVES_PER_TREE / EPS;
    assert_eq!(
        EncoderKind::PerListStatus { list_key: LIST_KEY }.min_total_entries(),
        LEAVES_PER_TREE,
        "the status table has exactly one tree's rows"
    );
    for list_index in 0..LEAVES_PER_TREE {
        let dirty = encoder.affected_shards_for_ppoi_leaf(&LIST_KEY, list_index);
        assert_eq!(
            dirty,
            BTreeSet::from([list_index / EPS]),
            "index {list_index} must dirty the shard carrying its row"
        );
        assert!(list_index / EPS < shards);
    }

    let mut store = LogicalLeafStore::new();
    let refusal = apply_wal_entry(
        &mut store,
        &leaf(LEAVES_PER_PPOI_BLOCK, POIStatus::Valid),
        100,
        &encoder,
    )
    .expect_err("an index past one tree cannot enter a whole-list store");
    assert!(
        refusal.to_string().contains("capacity"),
        "the refusal must name the capacity: {refusal}"
    );
    assert!(
        store.dirty_shards().is_empty(),
        "a refused row marks nothing"
    );
    assert!(store.ppoi_bc_at(&LIST_KEY, LEAVES_PER_PPOI_BLOCK).is_none());
    assert!(store.ppoi_imt(&LIST_KEY).is_none());
}
