//! How current the served view is: what the follower last established, read by the routes.
//!
//! A step that ends with the table at the head it read marks the view current. The view is
//! ready while that mark is younger than a bound. An idle chain keeps it current, because a
//! step that finds no new block ends at the head; a follower that stopped, or whose steps keep
//! failing, lets it age past the bound.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Never recorded.
const NEVER: u64 = u64::MAX;

/// The follower's last head, current mark and good step, shared with the routes.
#[derive(Debug)]
pub struct Freshness {
    origin: Instant,
    head: AtomicU64,
    current_ms: AtomicU64,
    good_ms: AtomicU64,
    failed: AtomicU64,
}

/// One reading of [`Freshness`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    /// The newest head a step read.
    pub head: Option<u64>,
    /// Since a step last ended with the table at the head.
    pub current_age: Option<Duration>,
    /// Since a step last succeeded.
    pub step_age: Option<Duration>,
    /// Steps that failed.
    pub failed: u64,
}

impl Reading {
    /// Whether the view was current within `bound`.
    #[must_use]
    pub fn ready(&self, bound: Duration) -> bool {
        self.current_age.is_some_and(|age| age <= bound)
    }
}

impl Default for Freshness {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
            head: AtomicU64::new(NEVER),
            current_ms: AtomicU64::new(NEVER),
            good_ms: AtomicU64::new(NEVER),
            failed: AtomicU64::new(0),
        }
    }
}

impl Freshness {
    fn millis(&self, at: Instant) -> u64 {
        u64::try_from(at.saturating_duration_since(self.origin).as_millis()).unwrap_or(NEVER - 1)
    }

    /// A step succeeded at `at`, having read `head`, and left the table at that head or not.
    pub fn stepped(&self, at: Instant, head: Option<u64>, at_head: bool) {
        let ms = self.millis(at);
        if let Some(head) = head {
            self.head.store(head, Ordering::Relaxed);
        }
        self.good_ms.store(ms, Ordering::Relaxed);
        if at_head {
            self.current_ms.store(ms, Ordering::Relaxed);
        }
    }

    /// A step failed.
    pub fn failed(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }

    /// The state at `now`.
    #[must_use]
    pub fn read(&self, now: Instant) -> Reading {
        let now = self.millis(now);
        let age = |at: &AtomicU64| match at.load(Ordering::Relaxed) {
            NEVER => None,
            ms => Some(Duration::from_millis(now.saturating_sub(ms))),
        };
        Reading {
            head: match self.head.load(Ordering::Relaxed) {
                NEVER => None,
                head => Some(head),
            },
            current_age: age(&self.current_ms),
            step_age: age(&self.good_ms),
            failed: self.failed.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::time::{Duration, Instant};

    use super::Freshness;

    #[test]
    fn ready_only_within_the_bound_of_the_last_step_at_the_head() {
        let fresh = Freshness::default();
        let start = Instant::now();
        let bound = Duration::from_secs(10);
        assert!(!fresh.read(start).ready(bound), "never at the head");
        fresh.stepped(start, Some(100), false);
        assert!(!fresh.read(start).ready(bound), "behind the head");
        fresh.stepped(start, Some(100), true);
        assert!(fresh.read(start + bound).ready(bound));
        let late = fresh.read(start + bound + Duration::from_millis(1));
        assert!(!late.ready(bound));
        assert_eq!(late.head, Some(100));
        fresh.failed();
        assert_eq!(fresh.read(start).failed, 1);
    }
}
