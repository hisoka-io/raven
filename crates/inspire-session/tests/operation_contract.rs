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

/// A checked open starts empty under exactly the limits it was given.
#[test]
fn a_checked_open_starts_empty_under_its_limits() {
    let store = BoundedSessionStore::open_with_limits(limits()).expect("open");
    assert!(store.is_empty());
    assert_eq!(store.limits(), limits());
}

#[test]
fn zero_cap_open_refuses() {
    let error = BoundedSessionStore::open_with_limits(SessionStoreLimits {
        max_sessions: 0,
        ttl: Duration::from_secs(10),
    })
    .expect_err("zero cap must refuse open");

    assert!(matches!(
        error,
        SessionStoreError::InvalidLimits { max_sessions: 0 }
    ));
    assert_eq!(error.class(), SessionStoreErrorClass::Configuration);
}
