#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
//! Rejection is atomic: for ANY wire-supplied shape, a kernel either succeeds
//! or leaves client state byte-identical. The example-based suite pins named
//! cases; this drives the same two kernels with generated shapes, because the
//! wave-1 defect was an input class nobody thought to name.

use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use raven_isimplepir::{
    db_update_batch, respond_packed, setup, squish_db, state_update_batch, DbBatchOp, EntryUpdate,
    HintVersion, InsertDelta, LweParams, SquishedDatabase, UpdateBatch, SQUISH_COMPRESSION,
};

fn toy_params() -> LweParams {
    LweParams {
        n: 32,
        log2_q: 32,
        p: 991,
        l: 4,
        m: 4,
        bits_per_element: 9,
    }
}

fn planted_db(params: &LweParams) -> Vec<u32> {
    (0..(params.l * params.m))
        .map(|i| (i as u32 * 37 + 11) % params.p)
        .collect()
}

/// One generated `beta_edit` entry, deliberately unconstrained: `row` and `col`
/// range past their bounds so the generator produces both accepted and rejected
/// batches without the test choosing which.
fn any_edit(params: LweParams) -> impl Strategy<Value = (usize, usize, u32)> {
    (0..params.l + 3, 0..params.m + 3, 0..params.p)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The wave-1 blocker as a property: whatever the batch, a rejected
    /// `state_update_batch` leaves `data`, `l` and `version` exactly as found.
    #[test]
    fn a_rejected_batch_leaves_the_hint_byte_identical(
        edits in proptest::collection::vec(any_edit(toy_params()), 0..6),
        insert_len_delta in -2i64..3,
        include_insert in any::<bool>(),
    ) {
        let params = toy_params();
        let db = planted_db(&params);
        let out = setup(&db, params, Some([5u8; 32])).expect("setup");
        let a_seed = out.server.a_seed;
        let mut hint = out.hint.clone();
        let mut server = out.server;

        let before_data = hint.data.clone();
        let before_l = hint.l;
        let before_version = hint.version;

        // one honest batch supplies a well-formed gamma and version; the
        // generated entries are then spliced in around it
        let honest = db_update_batch(
            &mut server,
            &DbBatchOp { modifications: &[(0, 0, 7)], deletions: &[], insertions: &[] },
            &mut ChaCha20Rng::from_seed([31u8; 32]),
        ).expect("honest batch");
        let gamma = honest.beta_edit.first().map_or(1u32, |e| e.gamma);

        let mut beta_edit: Vec<EntryUpdate> = edits
            .iter()
            .map(|&(row, col, _)| EntryUpdate { row, col, gamma, version: honest.version })
            .collect();
        beta_edit.extend(honest.beta_edit.iter().cloned());

        let beta_add = if include_insert {
            let len = usize::try_from(i64::try_from(params.n).expect("n fits i64") + insert_len_delta)
                .unwrap_or(0);
            vec![InsertDelta { w_prime: vec![3u32; len], version: honest.version }]
        } else {
            Vec::new()
        };

        let batch = UpdateBatch {
            beta_edit,
            beta_del: Vec::new(),
            beta_add,
            version: honest.version,
        };

        match state_update_batch(&mut hint, &a_seed, &params, &batch) {
            Err(_) => {
                prop_assert_eq!(&hint.data, &before_data, "rejected batch mutated hint.data");
                prop_assert_eq!(hint.l, before_l, "rejected batch changed hint.l");
                prop_assert_eq!(hint.version, before_version, "rejected batch advanced the version");
            }
            Ok(()) => {
                prop_assert_eq!(hint.version, batch.version, "accepted batch must advance the version");
                prop_assert_ne!(hint.version, HintVersion::INITIAL);
            }
        }
    }

    /// `respond_packed` must never answer over a shape that violates its own
    /// declared relation. It does not mutate, so the property is on the verdict.
    #[test]
    fn respond_packed_never_answers_a_shape_that_violates_its_declared_relation(
        m_packed_delta in -1i64..3,
        original_m_delta in -1i64..3,
        truncate_by in 0usize..4,
        query_len_delta in -1i64..2,
    ) {
        let params = toy_params();
        let db = planted_db(&params);
        let honest = squish_db(&db, &params).expect("squish");

        let m_packed = usize::try_from(
            i64::try_from(honest.m_packed).expect("fits") + m_packed_delta,
        ).unwrap_or(0);
        let original_m = usize::try_from(
            i64::try_from(honest.original_m).expect("fits") + original_m_delta,
        ).unwrap_or(0);
        let mut data = honest.data.clone();
        data.truncate(data.len().saturating_sub(truncate_by));

        let forged = SquishedDatabase { data, l: honest.l, m_packed, original_m };
        let query_len = usize::try_from(
            i64::try_from(params.m).expect("fits") + query_len_delta,
        ).unwrap_or(0);
        let query = vec![1u32; query_len];

        let well_formed = query_len == forged.original_m
            && forged.m_packed
                == forged.original_m.saturating_add(SQUISH_COMPRESSION).saturating_sub(1)
                    / SQUISH_COMPRESSION
            && forged.data.len() == forged.l.saturating_mul(forged.m_packed);

        let result = respond_packed(&forged, &query);
        if !well_formed {
            prop_assert!(
                result.is_err(),
                "respond_packed answered a malformed shape: query_len {}, original_m {}, \
                 m_packed {}, data_len {}, l {}",
                query_len, forged.original_m, forged.m_packed, forged.data.len(), forged.l,
            );
        }
    }
}
