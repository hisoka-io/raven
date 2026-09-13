#![allow(clippy::expect_used)]

use std::time::{Duration, Instant};

use raven_inspire::ServerSessionHandle;
use raven_inspire_session::{
    BoundedSessionStore, SessionCounts, SessionEvictions, SessionStoreError,
    SessionStoreErrorClass, SessionStoreLimits,
};
use sha2::{Digest, Sha256};

const FLOOR_FILE: &str = "session-handle-floor-v1.bin";
const WITNESS_FILE: &str = "session-handle-issuance-v1.bin";

fn limits() -> SessionStoreLimits {
    SessionStoreLimits {
        max_sessions: 4,
        ttl: Duration::from_secs(10),
    }
}

#[test]
fn empty_sweep_reports_one_ordered_zero_delta_and_current_counts() {
    let store = BoundedSessionStore::with_limits(limits());
    let (outcome, observation, warnings) = store.sweep_expired(Instant::now()).into_parts();

    assert_eq!(outcome.expect("empty sweep"), 0);
    assert!(warnings.is_empty());
    assert_eq!(observation.sequence, 1);
    assert_eq!(observation.evictions, SessionEvictions::default());
    assert_eq!(observation.flushes, 0);
    assert_eq!(
        observation.counts,
        Some(SessionCounts {
            occupancy: 0,
            serviceable: 0,
        })
    );
}

#[test]
fn missing_remove_publishes_current_counts_without_an_eviction() {
    let store = BoundedSessionStore::with_limits(limits());
    let (outcome, observation, warnings) = store.remove(ServerSessionHandle(7)).into_parts();

    assert!(!outcome.expect("missing removal is a no-op"));
    assert!(warnings.is_empty());
    assert_eq!(observation.sequence, 1);
    assert_eq!(observation.evictions, SessionEvictions::default());
    assert_eq!(observation.flushes, 0);
    assert_eq!(
        observation.counts,
        Some(SessionCounts {
            occupancy: 0,
            serviceable: 0,
        })
    );
}

#[test]
fn a_present_corrupt_floor_is_a_typed_durability_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("session-handle-floor-v1.bin"), b"short")
        .expect("write corrupt floor");

    let error = BoundedSessionStore::open_with_limits(dir.path(), limits())
        .expect_err("present corruption must fail closed");

    assert_eq!(error.class(), SessionStoreErrorClass::Durability);
    assert!(error.to_string().contains("session handle floor"));
}

#[test]
fn a_checksum_mismatch_is_a_typed_durability_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    drop(BoundedSessionStore::open_with_limits(dir.path(), limits()).expect("prime floor"));
    let floor_path = dir.path().join("session-handle-floor-v1.bin");
    let mut bytes = std::fs::read(&floor_path).expect("read floor");
    *bytes.get_mut(10).expect("floor byte") ^= 1;
    std::fs::write(&floor_path, bytes).expect("corrupt floor");

    let error = BoundedSessionStore::open_with_limits(dir.path(), limits())
        .expect_err("checksum mismatch must fail closed");
    assert_eq!(error.class(), SessionStoreErrorClass::Durability);
    assert!(error.to_string().contains("checksum mismatch"));
}

#[test]
fn a_validly_encoded_rolled_back_floor_refuses_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    drop(BoundedSessionStore::open_with_limits(dir.path(), limits()).expect("first open"));
    let floor_path = dir.path().join("session-handle-floor-v1.bin");
    let stale_floor = std::fs::read(&floor_path).expect("read first floor");
    drop(BoundedSessionStore::open_with_limits(dir.path(), limits()).expect("second open"));
    std::fs::write(&floor_path, stale_floor).expect("restore valid earlier floor");

    let error = BoundedSessionStore::open_with_limits(dir.path(), limits())
        .expect_err("valid rollback must not reissue the first reserved range");
    assert_eq!(error.class(), SessionStoreErrorClass::Durability);
    assert!(error.to_string().contains("floor"), "{error}");
}

#[test]
fn legacy_manifest_refuses_initialization_when_both_handle_files_are_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("manifest.json"),
        b"prior persisted instance",
    )
    .expect("write history signal");

    let error = BoundedSessionStore::open_with_limits(dir.path(), limits())
        .expect_err("prior serving cannot restart handles at zero");
    assert_eq!(error.class(), SessionStoreErrorClass::Durability);
    assert!(!dir.path().join("session-handle-floor-v1.bin").exists());
}

#[test]
fn fresh_layout_artifacts_without_history_allow_initialization() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_layout, _lock) =
        raven_storage::StoreLayout::open_with_lock(dir.path()).expect("production-shaped layout");
    drop(BoundedSessionStore::open_with_limits(dir.path(), limits()).expect("fresh open"));

    assert_eq!(read_floor(&dir.path().join(FLOOR_FILE)), 1024);
    assert_eq!(read_floor(&dir.path().join(WITNESS_FILE)), 1024);
}

#[test]
fn valid_legacy_floor_without_witness_migrates_above_its_range() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_floor(&dir.path().join(FLOOR_FILE), 1024);
    std::fs::write(dir.path().join("manifest.json"), b"legacy instance").expect("legacy manifest");

    drop(BoundedSessionStore::open_with_limits(dir.path(), limits()).expect("legacy migration"));

    assert_eq!(read_floor(&dir.path().join(FLOOR_FILE)), 2048);
    assert_eq!(read_floor(&dir.path().join(WITNESS_FILE)), 2048);
}

#[test]
fn deleting_only_the_witness_migrates_from_the_authoritative_floor() {
    let dir = tempfile::tempdir().expect("tempdir");
    drop(BoundedSessionStore::open_with_limits(dir.path(), limits()).expect("first open"));
    std::fs::remove_file(dir.path().join(WITNESS_FILE)).expect("remove witness only");

    drop(BoundedSessionStore::open_with_limits(dir.path(), limits()).expect("safe migration"));

    assert_eq!(read_floor(&dir.path().join(FLOOR_FILE)), 2048);
    assert_eq!(read_floor(&dir.path().join(WITNESS_FILE)), 2048);
}

#[test]
fn interrupted_publication_burns_the_higher_floor_range() {
    let dir = tempfile::tempdir().expect("tempdir");
    drop(BoundedSessionStore::open_with_limits(dir.path(), limits()).expect("first open"));
    write_floor(&dir.path().join(FLOOR_FILE), 2048);

    drop(BoundedSessionStore::open_with_limits(dir.path(), limits()).expect("retry open"));

    assert_eq!(read_floor(&dir.path().join(FLOOR_FILE)), 3072);
    assert_eq!(read_floor(&dir.path().join(WITNESS_FILE)), 3072);
}

#[test]
fn witness_ahead_of_floor_refuses_rewind() {
    let dir = tempfile::tempdir().expect("tempdir");
    drop(BoundedSessionStore::open_with_limits(dir.path(), limits()).expect("first open"));
    write_witness(&dir.path().join(WITNESS_FILE), 2048);

    let error = BoundedSessionStore::open_with_limits(dir.path(), limits())
        .expect_err("witness proves floor is stale");
    assert!(matches!(error, SessionStoreError::FloorRegressed { .. }));
}

#[test]
fn witness_checksum_corruption_refuses_allocation() {
    let dir = tempfile::tempdir().expect("tempdir");
    drop(BoundedSessionStore::open_with_limits(dir.path(), limits()).expect("first open"));
    let witness_path = dir.path().join(WITNESS_FILE);
    let mut bytes = std::fs::read(&witness_path).expect("read witness");
    *bytes.get_mut(10).expect("witness floor byte") ^= 1;
    std::fs::write(&witness_path, bytes).expect("corrupt witness");

    let error = BoundedSessionStore::open_with_limits(dir.path(), limits())
        .expect_err("corrupt witness must not be ignored");
    assert!(matches!(error, SessionStoreError::WitnessInvalid { .. }));
    assert_eq!(error.class(), SessionStoreErrorClass::Durability);
}

#[test]
fn durable_floor_wire_and_mode_stay_exact() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = BoundedSessionStore::open_with_limits(dir.path(), limits()).expect("open store");
    drop(store);

    let floor_path = dir.path().join("session-handle-floor-v1.bin");
    let bytes = std::fs::read(&floor_path).expect("read floor");
    let mut expected = Vec::from(*b"RVNHNDL1");
    expected.extend_from_slice(&1u16.to_be_bytes());
    expected.extend_from_slice(&1024u64.to_be_bytes());
    expected.extend_from_slice(&Sha256::digest(&expected));
    assert_eq!(bytes, expected);
    let witness_path = dir.path().join(WITNESS_FILE);
    let mut expected_witness = Vec::from(*b"RVNHISS1");
    expected_witness.extend_from_slice(&1u16.to_be_bytes());
    expected_witness.extend_from_slice(&1024u64.to_be_bytes());
    expected_witness.extend_from_slice(&Sha256::digest(&expected_witness));
    assert_eq!(
        std::fs::read(&witness_path).expect("read witness"),
        expected_witness
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(&floor_path)
            .expect("floor metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let witness_mode = std::fs::metadata(&witness_path)
            .expect("witness metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(witness_mode, 0o600);
    }
}

#[test]
fn concurrent_open_reserves_every_disjoint_range() {
    const OPENERS: usize = 32;

    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = std::sync::Arc::new(dir.path().to_path_buf());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(OPENERS));
    let openers: Vec<_> = (0..OPENERS)
        .map(|_| {
            let data_dir = std::sync::Arc::clone(&data_dir);
            let barrier = std::sync::Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                BoundedSessionStore::open_with_limits(data_dir.as_path(), limits())
            })
        })
        .collect();
    let mut reserved = 0u64;
    let mut unexpected = Vec::new();
    for opener in openers {
        match opener.join().expect("opener") {
            Ok(store) => {
                reserved += 1;
                drop(store);
            }
            Err(SessionStoreError::FloorLock { .. }) => {}
            Err(error) => unexpected.push(error.to_string()),
        }
    }

    let bytes = std::fs::read(data_dir.join("session-handle-floor-v1.bin")).expect("read floor");
    let floor = u64::from_be_bytes(
        bytes
            .get(10..18)
            .expect("floor field")
            .try_into()
            .expect("floor width"),
    );
    assert!(unexpected.is_empty(), "unexpected errors: {unexpected:?}");
    assert!(reserved > 0);
    assert_eq!(floor, reserved * 1024);
}

#[test]
fn zero_cap_durable_open_refuses_before_creating_floor_or_lock() {
    let dir = tempfile::tempdir().expect("tempdir");
    let error = BoundedSessionStore::open_with_limits(
        dir.path(),
        SessionStoreLimits {
            max_sessions: 0,
            ttl: Duration::from_secs(10),
        },
    )
    .expect_err("zero cap must refuse durable open");

    assert!(matches!(
        error,
        SessionStoreError::InvalidLimits { max_sessions: 0 }
    ));
    assert!(!dir.path().join("session-handle-floor-v1.bin").exists());
    assert!(!dir.path().join(".session-handle-floor.lock").exists());
}

fn read_floor(path: &std::path::Path) -> u64 {
    let bytes = std::fs::read(path).expect("read handle record");
    u64::from_be_bytes(
        bytes
            .get(10..18)
            .expect("floor field")
            .try_into()
            .expect("floor width"),
    )
}

fn write_floor(path: &std::path::Path, floor: u64) {
    write_handle_record(path, floor, *b"RVNHNDL1");
}

fn write_witness(path: &std::path::Path, floor: u64) {
    write_handle_record(path, floor, *b"RVNHISS1");
}

fn write_handle_record(path: &std::path::Path, floor: u64, magic: [u8; 8]) {
    let mut bytes = Vec::from(magic);
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&floor.to_be_bytes());
    bytes.extend_from_slice(&Sha256::digest(&bytes));
    std::fs::write(path, bytes).expect("write handle record");
}
