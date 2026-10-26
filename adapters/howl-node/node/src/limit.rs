//! What one node answers per unit of time, and the operator's credential.
//!
//! Wallets reach a node through shared exits, so no limit here is keyed by a client's address:
//! a per-address cap would lock out everyone behind one exit. The bounds are on the node's own
//! work instead: requests per second on each route across all callers, sessions opened per
//! second, request bodies held at once and how long one may take to arrive, and batches queued
//! for a respond permit. Each route has its own bucket, so a flood of one route refuses only
//! that route.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Shortest operator token accepted, in bytes. Length is all the node can check: the token must
/// also be random (e.g. `openssl rand -hex 32`), since the status route does not slow guessing.
pub const MIN_OPERATOR_TOKEN_BYTES: usize = 16;

/// A token bucket's refill rate and depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    /// Tokens added each second.
    pub per_sec: u32,
    /// Tokens held at most, which is the largest burst admitted at once.
    pub burst: u32,
}

/// The bounds a node serves under.
#[derive(Clone, PartialEq, Eq)]
pub struct Limits {
    /// Batches and session registrations computed at once.
    pub concurrent: usize,
    /// Batches and registrations waiting for one of `concurrent`; past this many a caller is
    /// answered `503` at once.
    pub queued: usize,
    /// Longest a caller waits for a permit before it is answered `503`.
    pub permit_wait: Duration,
    /// Session and batch bodies being read or answered at once. A body takes its place before
    /// its first byte is read, and past this many a caller is answered `503`, so the memory held
    /// by bodies stays within this many times a route's body cap.
    pub bodies: usize,
    /// Longest one body may take to arrive; a slower one is answered `408`.
    pub body_timeout: Duration,
    /// Requests on each route but health, status and session, across all callers.
    pub requests: Rate,
    /// Sessions opened, across all callers: the fastest the seats can be filled.
    pub sessions: Rate,
    /// Bearer token opening the status route; `None` keeps it closed.
    pub operator_token: Option<String>,
}

impl std::fmt::Debug for Limits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Limits")
            .field("concurrent", &self.concurrent)
            .field("queued", &self.queued)
            .field("permit_wait", &self.permit_wait)
            .field("bodies", &self.bodies)
            .field("body_timeout", &self.body_timeout)
            .field("requests", &self.requests)
            .field("sessions", &self.sessions)
            .field(
                "operator_token",
                &self.operator_token.as_ref().map(|_| "set"),
            )
            .finish()
    }
}

impl Limits {
    /// The defaults for `concurrent` permits.
    #[must_use]
    pub fn new(concurrent: usize) -> Self {
        let concurrent = concurrent.max(1);
        Self {
            concurrent,
            queued: concurrent.saturating_mul(8),
            permit_wait: Duration::from_secs(20),
            // Room for every permit and queue place, and as many again still arriving.
            bodies: concurrent.saturating_mul(18),
            body_timeout: Duration::from_secs(30),
            // A route served about 64,000 cheap reads a second on two cores, load generator
            // included: 5,000 keeps a flood of all five read routes under half of such a box,
            // and private reads are bounded by the permits, not by this.
            requests: Rate {
                per_sec: 5_000,
                burst: 10_000,
            },
            sessions: Rate {
                per_sec: 4,
                burst: 64,
            },
            operator_token: None,
        }
    }

    /// The first bound that cannot serve.
    ///
    /// # Errors
    /// A message naming it.
    pub fn validate(&self) -> Result<(), String> {
        if self.concurrent == 0 {
            return Err("concurrent must be at least 1".to_owned());
        }
        if self.bodies == 0 {
            return Err("bodies must be at least 1".to_owned());
        }
        if self.body_timeout.is_zero() {
            return Err("the body timeout must be above zero".to_owned());
        }
        if self.permit_wait.is_zero() {
            return Err(
                "the permit wait must be above zero; zero refuses every busy caller".to_owned(),
            );
        }
        for (name, rate) in [("requests", self.requests), ("sessions", self.sessions)] {
            if rate.per_sec == 0 || rate.burst == 0 {
                return Err(format!("{name}: the rate and the burst must be at least 1"));
            }
        }
        if let Some(token) = &self.operator_token {
            if token.len() < MIN_OPERATOR_TOKEN_BYTES {
                return Err(format!(
                    "the operator token is {} bytes; at least {MIN_OPERATOR_TOKEN_BYTES}",
                    token.len()
                ));
            }
        }
        Ok(())
    }
}

/// A token bucket shared by every caller.
#[derive(Debug)]
pub(crate) struct Bucket {
    rate: Rate,
    // tokens held, and when they were counted
    state: Mutex<(f64, Instant)>,
}

impl Bucket {
    pub(crate) fn new(rate: Rate) -> Self {
        Self {
            rate,
            state: Mutex::new((f64::from(rate.burst), Instant::now())),
        }
    }

    /// Take one token, or say how long until one is there.
    pub(crate) fn take(&self, now: Instant) -> Result<(), Duration> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let (held, counted) = *state;
        let rate = f64::from(self.rate.per_sec);
        let held = (held + now.saturating_duration_since(counted).as_secs_f64() * rate)
            .min(f64::from(self.rate.burst));
        if held >= 1.0 {
            *state = (held - 1.0, now);
            Ok(())
        } else {
            *state = (held, now);
            Err(Duration::from_secs_f64((1.0 - held) / rate))
        }
    }
}

/// Seconds for a `Retry-After` header: the wait rounded up, at least one.
pub(crate) fn retry_after_secs(wait: Duration) -> u64 {
    let secs = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
    secs.max(1)
}

/// Whether `presented` is the operator token, in time that does not depend on where they differ.
pub(crate) fn operator_token_matches(configured: Option<&str>, presented: Option<&str>) -> bool {
    use subtle::ConstantTimeEq;
    let (Some(configured), Some(presented)) = (configured, presented) else {
        return false;
    };
    // The length is not secret: every token is at least MIN_OPERATOR_TOKEN_BYTES.
    configured.len() == presented.len()
        && bool::from(configured.as_bytes().ct_eq(presented.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bucket_admits_its_burst_then_refuses_until_it_refills() {
        let bucket = Bucket::new(Rate {
            per_sec: 2,
            burst: 3,
        });
        let t0 = Instant::now();
        for _ in 0..3 {
            assert_eq!(bucket.take(t0), Ok(()));
        }
        let wait = bucket.take(t0).err();
        assert_eq!(wait, Some(Duration::from_millis(500)));
        assert!(bucket.take(t0 + Duration::from_millis(450)).is_err());
        assert_eq!(bucket.take(t0 + Duration::from_millis(510)), Ok(()));
        // A long idle refills to the burst, not past it.
        let later = t0 + Duration::from_secs(60);
        for _ in 0..3 {
            assert_eq!(bucket.take(later), Ok(()));
        }
        assert!(bucket.take(later).is_err());
    }

    #[test]
    fn retry_after_rounds_up_to_whole_seconds() {
        assert_eq!(retry_after_secs(Duration::ZERO), 1);
        assert_eq!(retry_after_secs(Duration::from_millis(1)), 1);
        assert_eq!(retry_after_secs(Duration::from_secs(2)), 2);
        assert_eq!(retry_after_secs(Duration::from_millis(2_001)), 3);
    }

    #[test]
    fn only_the_configured_token_opens() {
        let configured = "0123456789abcdef0123";
        assert!(operator_token_matches(Some(configured), Some(configured)));
        assert!(!operator_token_matches(
            Some(configured),
            Some("0123456789abcdef0124")
        ));
        assert!(!operator_token_matches(
            Some(configured),
            Some("0123456789abcdef")
        ));
        assert!(!operator_token_matches(Some(configured), Some("")));
        assert!(!operator_token_matches(Some(configured), None));
        assert!(!operator_token_matches(None, Some(configured)));
        assert!(!operator_token_matches(None, Some("")));
    }

    #[test]
    fn validation_names_each_unservable_bound() {
        assert_eq!(Limits::new(4).validate(), Ok(()));
        let short = Limits {
            operator_token: Some("x".repeat(MIN_OPERATOR_TOKEN_BYTES - 1)),
            ..Limits::new(4)
        };
        assert!(short
            .validate()
            .is_err_and(|e| e.contains("operator token")));
        let long = Limits {
            operator_token: Some("x".repeat(MIN_OPERATOR_TOKEN_BYTES)),
            ..Limits::new(4)
        };
        assert_eq!(long.validate(), Ok(()));
        let no_rate = Limits {
            sessions: Rate {
                per_sec: 0,
                burst: 1,
            },
            ..Limits::new(4)
        };
        assert!(no_rate.validate().is_err_and(|e| e.contains("sessions")));
        let no_wait = Limits {
            permit_wait: Duration::ZERO,
            ..Limits::new(4)
        };
        assert!(no_wait.validate().is_err());
        let no_bodies = Limits {
            bodies: 0,
            ..Limits::new(4)
        };
        assert!(no_bodies.validate().is_err_and(|e| e.contains("bodies")));
        let no_body_time = Limits {
            body_timeout: Duration::ZERO,
            ..Limits::new(4)
        };
        assert!(no_body_time
            .validate()
            .is_err_and(|e| e.contains("body timeout")));
    }

    #[test]
    fn the_token_never_shows_in_debug_output() {
        let limits = Limits {
            operator_token: Some("a-secret-operator-token".to_owned()),
            ..Limits::new(1)
        };
        assert!(!format!("{limits:?}").contains("a-secret"));
    }
}
