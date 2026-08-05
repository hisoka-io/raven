//! One uploaded query served against k shards on a single pinned snapshot.
//!
//! Privacy caveat: the cover group arrives as ONE request, so the server learns
//! the group is one client's - linkage that k separate queries do not hand it.
//! Every slot resolves the SAME encrypted local index, and duplicate shard ids are
//! served verbatim, so `[0,0,0]` has an anonymity set of one.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use bytes::Bytes;
use raven_inspire::SeededClientQuery;
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::RavenInspireScheme;
use raven_railgun_engine::DrainState;
use serde::{Deserialize, Serialize};

use crate::batch::{dispatch_batch, BatchError};
use crate::state::AppState;
use crate::versioned::{read_versioned, write_batch_response_versioned};
use crate::{attach_freshness_header, build_response_headers};

/// Request body of `POST /v1/instance/{id}/fanout`. See the module privacy caveat;
/// a slot on a shard's padded tail decrypts to a valid all-zeros plaintext.
#[derive(Debug, Serialize, Deserialize)]
pub struct FanoutRequest {
    /// The single uploaded query. Its `shard_id` is overridden per slot.
    pub query: SeededClientQuery,
    /// Target shards; responses are returned in this order.
    pub shard_ids: Vec<u32>,
}

/// Failure mode of a fan-out request.
#[derive(Debug, thiserror::Error)]
pub enum FanoutError {
    /// `shard_ids` was empty.
    #[error("shard_ids must not be empty")]
    NoShards,
    /// `shard_ids` longer than `HttpConfig::max_fanout_shards`.
    #[error("shard_ids length {got} exceeds max_fanout_shards {cap}")]
    TooManyShards {
        /// Requested fan-out width.
        got: usize,
        /// Configured cap.
        cap: usize,
    },
    /// A shard id does not address a shard of the pinned snapshot.
    #[error(
        "shard id {shard_id} at position {index} out of range: instance has {shard_count} shards"
    )]
    ShardOutOfRange {
        /// Offending shard id.
        shard_id: u32,
        /// 0-based position in `shard_ids`.
        index: usize,
        /// Shard count of the pinned snapshot.
        shard_count: usize,
    },
    /// Dispatch failed on a slot whose shard id is known.
    #[error("shard {shard_id} at position {index} failed: {source}")]
    Dispatch {
        /// Shard the failing slot targeted.
        shard_id: u32,
        /// 0-based position in `shard_ids`.
        index: usize,
        /// Underlying dispatch failure.
        #[source]
        source: BatchError,
    },
    /// Dispatch failed without a resolvable slot (task-level abort).
    #[error("fan-out failed without an attributable shard: {source}")]
    DispatchUnattributed {
        /// Underlying dispatch failure.
        #[source]
        source: BatchError,
    },
}

impl FanoutError {
    /// Map to HTTP status: validation -> 400; dispatch delegates to [`BatchError::status`].
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            FanoutError::NoShards
            | FanoutError::TooManyShards { .. }
            | FanoutError::ShardOutOfRange { .. } => StatusCode::BAD_REQUEST,
            FanoutError::Dispatch { source, .. } | FanoutError::DispatchUnattributed { source } => {
                source.status()
            }
        }
    }

    /// Low-cardinality class label safe to log.
    #[must_use]
    pub fn class(&self) -> &'static str {
        match self {
            FanoutError::NoShards => "no_shards",
            FanoutError::TooManyShards { .. } => "too_many_shards",
            FanoutError::ShardOutOfRange { .. } => "shard_out_of_range",
            FanoutError::Dispatch { source, .. } | FanoutError::DispatchUnattributed { source } => {
                source.class()
            }
        }
    }

    /// Offending shard id, position and counts. Never a scheme error string, which
    /// can echo request-shaped text.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            FanoutError::NoShards => "shard_ids must not be empty".to_owned(),
            FanoutError::TooManyShards { got, cap } => {
                format!("shard_ids length {got} exceeds max_fanout_shards {cap}")
            }
            FanoutError::ShardOutOfRange {
                shard_id,
                index,
                shard_count,
            } => format!(
                "shard id {shard_id} at position {index} is outside the {shard_count}-shard instance"
            ),
            FanoutError::Dispatch {
                shard_id,
                index,
                source,
            } => format!(
                "shard {shard_id} at position {index} failed: {}",
                source.class()
            ),
            FanoutError::DispatchUnattributed { source } => {
                format!("failed with no attributable shard: {}", source.class())
            }
        }
    }
}

/// One fan-out slot: a handle on the shared upload plus the shard it retargets.
struct FanoutSlot {
    query: Arc<SeededClientQuery>,
    shard_id: u32,
}

impl From<FanoutSlot> for SeededClientQuery {
    fn from(slot: FanoutSlot) -> Self {
        let mut query = SeededClientQuery::clone(&slot.query);
        query.shard_id = slot.shard_id;
        query
    }
}

/// Validate `shard_ids` and bind one slot per id to the shared upload. Shards are
/// numbered contiguously from 0, so a length compare is exact membership. Slots
/// share an `Arc`, so peak copies track the concurrency limit, not `shard_ids.len()`.
fn expand_fanout(
    query: &Arc<SeededClientQuery>,
    shard_ids: &[u32],
    shard_count: usize,
    cap: usize,
) -> Result<Vec<FanoutSlot>, FanoutError> {
    if shard_ids.is_empty() {
        return Err(FanoutError::NoShards);
    }
    let cap = cap.max(1);
    if shard_ids.len() > cap {
        return Err(FanoutError::TooManyShards {
            got: shard_ids.len(),
            cap,
        });
    }
    let mut slots = Vec::with_capacity(shard_ids.len());
    for (index, shard_id) in shard_ids.iter().copied().enumerate() {
        if usize::try_from(shard_id).map_or(true, |id| id >= shard_count) {
            return Err(FanoutError::ShardOutOfRange {
                shard_id,
                index,
                shard_count,
            });
        }
        slots.push(FanoutSlot {
            query: Arc::clone(query),
            shard_id,
        });
    }
    Ok(slots)
}

fn attribute_dispatch_error(err: BatchError, shard_ids: &[u32]) -> FanoutError {
    match err
        .index()
        .and_then(|index| shard_ids.get(index).map(|shard_id| (index, *shard_id)))
    {
        Some((index, shard_id)) => FanoutError::Dispatch {
            shard_id,
            index,
            source: err,
        },
        None => FanoutError::DispatchUnattributed { source: err },
    }
}

fn reject(err: &FanoutError) -> (StatusCode, String) {
    let detail = err.detail();
    tracing::warn!(class = err.class(), detail = %detail, "fanout rejected");
    (err.status(), detail)
}

pub(crate) async fn fanout_handler(
    State(app): State<AppState<RavenInspireScheme>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Bytes), (StatusCode, String)> {
    let instance_id = InstanceId::new(id);
    let instance = app
        .engine
        .instance(&instance_id)
        .ok_or((StatusCode::NOT_FOUND, "unknown instance".to_owned()))?;
    if instance.drain_state() != DrainState::Active {
        tracing::info!(
            instance_id = %instance.id,
            drain_state = instance.drain_state().label(),
            "fanout refused: instance is not active"
        );
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            format!("instance is {}", instance.drain_state().label()),
        ));
    }

    let FanoutRequest { query, shard_ids } =
        read_versioned::<FanoutRequest>(&body).map_err(|err| {
            tracing::warn!(?err, "fanout versioned-bincode deserialize failed");
            (
                StatusCode::BAD_REQUEST,
                "fanout request decode failed".to_owned(),
            )
        })?;

    let started = Instant::now();
    // Captured ONCE so validation and every worker read the same snapshot.
    let snapshot_for_fanout = instance.current_snapshot();
    let epoch_at_start = snapshot_for_fanout.epoch;
    let shard_count = snapshot_for_fanout.state.encoded_db.shards.len();

    let shared_query = Arc::new(query);
    let slots = expand_fanout(
        &shared_query,
        &shard_ids,
        shard_count,
        app.config.max_fanout_shards,
    )
    .map_err(|err| reject(&err))?;

    let k = app.config.max_concurrent_queries.max(1);
    let respond_timeout = Duration::from_secs(app.config.respond_timeout_secs.max(1));

    let responses_result = dispatch_batch::<RavenInspireScheme, FanoutSlot>(
        slots,
        Arc::clone(&instance),
        snapshot_for_fanout,
        Arc::clone(&app.semaphore),
        k,
        respond_timeout,
    )
    .await;

    let elapsed = started.elapsed();

    let responses =
        responses_result.map_err(|err| reject(&attribute_dispatch_error(err, &shard_ids)))?;

    metrics::histogram!(
        "raven_railgun_respond_seconds",
        "instance" => instance_id.to_string(),
        "kind" => "fanout"
    )
    .record(elapsed.as_secs_f64());
    metrics::counter!(
        "raven_railgun_queries_total",
        "instance" => instance_id.to_string(),
        "kind" => "fanout"
    )
    .increment(responses.len() as u64);
    #[allow(clippy::cast_precision_loss)]
    let fanout_width = responses.len() as f64;
    metrics::histogram!(
        "raven_railgun_fanout_shards",
        "instance" => instance_id.to_string()
    )
    .record(fanout_width);

    let body_bytes = write_batch_response_versioned(&responses).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "fanout response encode failed".to_owned(),
        )
    })?;

    let mut headers = build_response_headers(epoch_at_start.0, &app.scheme_name).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "fanout response header encode failed".to_owned(),
        )
    })?;
    attach_freshness_header(
        &mut headers,
        app.consumer_metrics.as_ref().as_ref().map(AsRef::as_ref),
        epoch_at_start.0,
    );
    Ok((StatusCode::OK, headers, body_bytes.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use raven_inspire::rgsw::{GadgetVector, SeededRgswCiphertext};
    use raven_inspire::PackingMode;

    fn stub_query() -> Arc<SeededClientQuery> {
        Arc::new(SeededClientQuery {
            shard_id: 0,
            rgsw_ciphertext: SeededRgswCiphertext {
                rows: Vec::new(),
                gadget: GadgetVector::new(2, 1, 3),
            },
            packing_mode: PackingMode::Inspiring,
            inspiring_packing_keys: None,
            session_handle: None,
        })
    }

    #[test]
    fn expand_fanout_shares_one_upload_across_slots() {
        let query = stub_query();
        let slots = expand_fanout(&query, &[0, 1, 2, 0], 4, 16).expect("all ids in range");
        assert_eq!(
            Arc::strong_count(&query),
            slots.len() + 1,
            "every slot must hold a shared handle; a deep clone per slot makes \
             peak memory k x body_size"
        );
    }

    #[test]
    fn fanout_slot_retargets_only_the_shard_id() {
        let query = stub_query();
        let slots = expand_fanout(&query, &[3], 4, 16).expect("id in range");
        let materialized: Vec<SeededClientQuery> =
            slots.into_iter().map(SeededClientQuery::from).collect();
        assert_eq!(materialized[0].shard_id, 3);
        assert_eq!(materialized[0].packing_mode, query.packing_mode);
        assert_eq!(
            materialized[0].rgsw_ciphertext.gadget.base,
            query.rgsw_ciphertext.gadget.base
        );
    }

    #[test]
    fn fanout_error_detail_names_the_offending_integers() {
        let out_of_range = FanoutError::ShardOutOfRange {
            shard_id: 9,
            index: 2,
            shard_count: 4,
        };
        let detail = out_of_range.detail();
        assert!(
            detail.contains('9') && detail.contains('2') && detail.contains('4'),
            "{detail}"
        );

        let too_many = FanoutError::TooManyShards { got: 99, cap: 16 };
        let detail = too_many.detail();
        assert!(detail.contains("99") && detail.contains("16"), "{detail}");

        let dispatch = FanoutError::Dispatch {
            shard_id: 11,
            index: 3,
            source: BatchError::Timeout { index: 3, secs: 30 },
        };
        let detail = dispatch.detail();
        assert!(
            detail.contains("11") && detail.contains("timeout"),
            "{detail}"
        );
    }

    #[test]
    fn fanout_error_detail_omits_the_scheme_error_string() {
        let err = FanoutError::Dispatch {
            shard_id: 1,
            index: 0,
            source: BatchError::Respond {
                index: 0,
                detail: "attacker-shaped scheme text".to_owned(),
            },
        };
        assert!(
            !err.detail().contains("attacker-shaped"),
            "detail is a response body; it must not echo the scheme error string"
        );
    }

    proptest! {
        #[test]
        fn expand_fanout_accepts_exactly_the_non_empty_in_range_lists(
            shard_ids in prop::collection::vec(0u32..12, 0..24),
            shard_count in 0usize..8,
            cap in 0usize..24,
        ) {
            let query = stub_query();
            let accepted = expand_fanout(&query, &shard_ids, shard_count, cap);
            let expected_ok = !shard_ids.is_empty()
                && shard_ids.len() <= cap.max(1)
                && shard_ids
                    .iter()
                    .all(|id| usize::try_from(*id).is_ok_and(|id| id < shard_count));
            prop_assert_eq!(accepted.is_ok(), expected_ok);
            if let Ok(slots) = accepted {
                let targets: Vec<u32> = slots.iter().map(|slot| slot.shard_id).collect();
                prop_assert_eq!(targets, shard_ids);
            }
        }

        #[test]
        fn expand_fanout_rejects_every_id_at_or_past_the_shard_count(
            shard_count in 1usize..8,
            offset in 0u32..64,
        ) {
            let query = stub_query();
            let out_of_range = u32::try_from(shard_count).unwrap_or(u32::MAX).saturating_add(offset);
            let err = expand_fanout(&query, &[0, out_of_range], shard_count, 16)
                .err()
                .expect("an id at or past shard_count must reject");
            prop_assert_eq!(err.class(), "shard_out_of_range");
            prop_assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        }
    }
}
