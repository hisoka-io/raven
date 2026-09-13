//! Railgun batch-padding policy over Raven's generic dyadic arithmetic.

pub use raven_core::batch_ladder::LadderViolation;

/// Railgun's permitted batch sizes, mirrored by the TypeScript SDK.
pub const BATCH_SIZE_LADDER: [usize; 6] = [1, 2, 4, 8, 16, 32];

/// Railgun's current deployment ceiling.
pub const MAX_BATCH_SIZE: usize = 32;

/// Largest batch the Railgun policy admits.
#[must_use]
pub const fn max_batch_size() -> usize {
    MAX_BATCH_SIZE
}

/// Whether `len` is a Railgun ladder step.
#[must_use]
pub const fn is_on_ladder(len: usize) -> bool {
    raven_core::batch_ladder::is_on_ladder(len, MAX_BATCH_SIZE)
}

/// Smallest Railgun ladder step fitting `len`, or `None` above the deployment ceiling.
///
/// Empty input retains the adapter's existing `Some(1)` convention so callers can issue their
/// own domain-specific empty-batch error after sizing.
#[must_use]
pub fn padded_len(len: usize) -> Option<usize> {
    if len == 0 {
        return Some(1);
    }
    raven_core::batch_ladder::padded_len(len, MAX_BATCH_SIZE).ok()
}

/// Accept `len` only when it is a Railgun ladder step.
///
/// # Errors
/// Returns a [`LadderViolation`] naming the required step or current deployment ceiling.
pub fn check_batch_len(len: usize) -> Result<(), LadderViolation> {
    raven_core::batch_ladder::check_batch_len(len, MAX_BATCH_SIZE)
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::{
        check_batch_len, is_on_ladder, max_batch_size, padded_len, BATCH_SIZE_LADDER,
        MAX_BATCH_SIZE,
    };

    #[derive(Deserialize)]
    struct BatchCapacityEvidence {
        #[serde(rename = "serializedQueryBytes")]
        query_len: usize,
        #[serde(rename = "batchFrameBytes")]
        frame_len: usize,
        #[serde(rename = "defaultBodyCapBytes")]
        body_cap: usize,
    }

    #[test]
    fn policy_matches_the_existing_six_steps() {
        assert_eq!(BATCH_SIZE_LADDER, [1, 2, 4, 8, 16, 32]);
        assert_eq!(max_batch_size(), MAX_BATCH_SIZE);
        let query_hex =
            include_str!("../../sdk/tests/fixtures/production_handled_query.hex").trim();
        assert_eq!(
            query_hex.len() % 2,
            0,
            "query fixture must contain whole bytes"
        );
        let capacity_evidence: BatchCapacityEvidence = serde_json::from_str(include_str!(
            "../../sdk/tests/fixtures/production_batch_capacity.json"
        ))
        .expect("production capacity evidence is JSON");
        let serialized_query_bytes = query_hex.len() / 2;
        let frame_bytes = capacity_evidence.frame_len;
        let body_cap_bytes = capacity_evidence.body_cap;
        let raw_capacity = (body_cap_bytes - frame_bytes) / serialized_query_bytes;
        let admitted_body_bytes = frame_bytes + raw_capacity * serialized_query_bytes;
        let refused_body_bytes = frame_bytes + (raw_capacity + 1) * serialized_query_bytes;
        assert_eq!(serialized_query_bytes, capacity_evidence.query_len);
        assert_eq!(serialized_query_bytes, 49_445);
        assert_eq!(raw_capacity, 169);
        assert!(admitted_body_bytes <= body_cap_bytes);
        assert!(refused_body_bytes > body_cap_bytes);
        assert_eq!(
            raven_core::batch_ladder::largest_dyadic_step(raw_capacity),
            Ok(128),
            "the production wire capacity exposes 128 without changing adapter policy"
        );
        for step in BATCH_SIZE_LADDER {
            assert!(is_on_ladder(step));
            check_batch_len(step).expect("policy step must pass");
        }
    }

    #[test]
    fn compatibility_wrapper_preserves_sizing_behavior() {
        assert_eq!(padded_len(0), Some(1));
        assert_eq!(padded_len(3), Some(4));
        assert_eq!(padded_len(17), Some(32));
        assert_eq!(padded_len(33), None);
        assert!(check_batch_len(3).is_err());
    }
}
