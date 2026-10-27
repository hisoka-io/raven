#![allow(clippy::expect_used)]

use std::time::{Duration, Instant};

use raven_inspire::ServerSessionHandle;
use raven_inspire_session::{
    BoundedSessionStore, SessionCounts, SessionEvictions, SessionStoreError,
    SessionStoreErrorClass, SessionStoreLimits,
};

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

/// A data directory an earlier build wrote a handle floor into, valid or not, beside an
/// instance manifest, opens as it is and is left as it is: nothing about past handles is read.
#[test]
fn an_older_builds_handle_floor_is_neither_read_nor_rewritten() {
    for floor in [b"short".to_vec(), vec![0xa5; 50]] {
        let dir = tempfile::tempdir().expect("tempdir");
        let floor_path = dir.path().join("session-handle-floor-v1.bin");
        std::fs::write(&floor_path, &floor).expect("old floor");
        std::fs::write(dir.path().join("manifest.json"), b"prior instance").expect("manifest");

        let store = BoundedSessionStore::open_with_limits(dir.path(), limits()).expect("open");
        assert!(store.is_empty());
        drop(store);

        assert_eq!(std::fs::read(&floor_path).expect("floor"), floor);
        assert_eq!(std::fs::read_dir(dir.path()).expect("dir").count(), 2);
    }
}

#[test]
fn zero_cap_open_refuses_and_creates_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let error = BoundedSessionStore::open_with_limits(
        dir.path(),
        SessionStoreLimits {
            max_sessions: 0,
            ttl: Duration::from_secs(10),
        },
    )
    .expect_err("zero cap must refuse open");

    assert!(matches!(
        error,
        SessionStoreError::InvalidLimits { max_sessions: 0 }
    ));
    assert_eq!(error.class(), SessionStoreErrorClass::Configuration);
    assert_eq!(std::fs::read_dir(dir.path()).expect("dir").count(), 0);
}
