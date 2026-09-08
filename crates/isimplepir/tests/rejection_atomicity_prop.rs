#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Rejection is atomic AND selective. Two halves, and each needs its own
//! property: a kernel that rejected every shape would satisfy "a rejected
//! input leaves client state byte-identical" on its own, and a kernel that
//! accepted every shape would satisfy "an honest input is answered" on its
//! own. So the accept side and the reject side are pinned separately.
//!
//! Every oracle here is taken from the honest PRODUCER - `squish_db`,
//! `db_update_batch` - never from a restatement of the arithmetic the
//! validator under test uses. A test that recomputes the validator's own
//! `ceil` expression agrees with a mutated validator and proves nothing.

use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use raven_isimplepir::{
    db_update_batch, respond, respond_packed, setup, squish_db, state_update_batch, unsquish_db,
    verify_hint_matches_db, DbBatchOp, EntryUpdate, HintVersion, InsertDelta, IsimplePirError,
    LweParams, ServerState, SquishedDatabase, UpdateBatch,
};

/// Batch generators below index rows and columns directly, so they must track these.
const L: usize = 4;
const M: usize = 4;
const P: u32 = 991;

fn toy_params() -> LweParams {
    LweParams {
        n: 32,
        log2_q: 32,
        p: P,
        l: L,
        m: M,
        bits_per_element: 9,
    }
}

fn squishable_params(l: usize, m: usize) -> LweParams {
    LweParams {
        n: 32,
        log2_q: 32,
        p: P,
        l,
        m,
        bits_per_element: 9,
    }
}

fn planted_db(params: &LweParams) -> Vec<u32> {
    (0..params.l.saturating_mul(params.m))
        .map(|i| (i as u32 * 37 + 11) % params.p)
        .collect()
}

/// Saturating `base + delta`, so a generated perturbation never wraps a `usize`.
fn shift(base: usize, delta: i64) -> usize {
    usize::try_from(
        i64::try_from(base)
            .unwrap_or(i64::MAX)
            .saturating_add(delta),
    )
    .unwrap_or(0)
}

/// `Sum_j DB[i][j] * q[j] mod 2^32` read back through `unsquish_db`. Independent
/// of the packed kernels: it unpacks first, then does the textbook dot.
fn unpacked_reference(packed: &SquishedDatabase, query: &[u32]) -> Vec<u32> {
    let flat = unsquish_db(packed);
    (0..packed.l)
        .map(|i| {
            let row = i.saturating_mul(packed.original_m);
            (0..packed.original_m).fold(0u32, |acc, j| {
                let v = flat.get(row.saturating_add(j)).copied().unwrap_or(0);
                let q = query.get(j).copied().unwrap_or(0);
                acc.wrapping_add(v.wrapping_mul(q))
            })
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The accept half for the batch kernel. Without it, `state_update_batch`
    /// could reject every batch ever built and the atomicity property below
    /// would still be green - which it was, and a mutation proved it.
    #[test]
    fn an_honest_batch_applies_and_the_hint_still_tracks_the_db(
        mods in proptest::collection::vec((0..L, 0..M, 0..P), 0..4),
        dels in proptest::collection::vec((0..L, 0..M), 0..3),
        inserts in proptest::collection::vec(
            proptest::collection::vec(0..P, M..=M), 0..3),
        rng_seed in any::<u8>(),
    ) {
        let params = toy_params();
        let db = planted_db(&params);
        let out = setup(&db, params, Some([5u8; 32])).expect("setup");
        let a_seed = out.server.a_seed;
        let mut hint = out.hint;
        let mut server = out.server;

        let rows: Vec<&[u32]> = inserts.iter().map(Vec::as_slice).collect();
        let batch = db_update_batch(
            &mut server,
            &DbBatchOp { modifications: &mods, deletions: &dels, insertions: &rows },
            &mut ChaCha20Rng::from_seed([rng_seed; 32]),
        ).expect("every generated op is in range");

        let applied = state_update_batch(&mut hint, &a_seed, &params, &batch);
        prop_assert!(
            applied.is_ok(),
            "a batch db_update_batch just produced was rejected: {} mods, {} dels, {} inserts, {:?}",
            mods.len(), dels.len(), inserts.len(), applied.err(),
        );
        prop_assert_eq!(hint.version, batch.version, "hint version must follow the batch");
        prop_assert_eq!(
            hint.l, server.params.l,
            "inserts must extend the hint by as many rows as the db grew"
        );
        // the whole point of the incremental path: the hint must still equal a
        // full H = D * A recomputation
        prop_assert!(
            verify_hint_matches_db(&server, &hint).is_ok(),
            "hint stopped tracking the db after an accepted batch: {:?}",
            verify_hint_matches_db(&server, &hint).err(),
        );
    }

    /// The reject half. One element is malformed BY CONSTRUCTION - a row past
    /// `L`, a column past `M`, an insert row of the wrong width, or a stale
    /// version - so the verdict is asserted unconditionally rather than only on
    /// the branch the implementation happens to take. In-range edits are spliced
    /// AROUND it, so a kernel that applied as it went leaves them behind.
    #[test]
    fn a_malformed_batch_is_rejected_and_leaves_the_hint_byte_identical(
        good in proptest::collection::vec((0..L, 0..M), 0..4),
        flaw in 0usize..4,
        overshoot in 1usize..4,
        position in 0usize..8,
        insert_short in any::<bool>(),
    ) {
        let params = toy_params();
        let db = planted_db(&params);
        let out = setup(&db, params, Some([5u8; 32])).expect("setup");
        let a_seed = out.server.a_seed;
        let mut hint = out.hint;
        let mut server = out.server;

        let honest = db_update_batch(
            &mut server,
            &DbBatchOp { modifications: &[(0, 0, 7)], deletions: &[], insertions: &[] },
            &mut ChaCha20Rng::from_seed([31u8; 32]),
        ).expect("honest batch");
        let gamma = honest.beta_edit.first().map_or(1u32, |e| e.gamma);

        let mut beta_edit: Vec<EntryUpdate> = honest.beta_edit.clone();
        beta_edit.extend(good.iter().map(|&(row, col)| EntryUpdate {
            row, col, gamma, version: honest.version,
        }));
        let mut beta_add: Vec<InsertDelta> = Vec::new();
        let mut version = honest.version;

        match flaw {
            0 => beta_edit.insert(position % (beta_edit.len() + 1), EntryUpdate {
                row: params.l.saturating_add(overshoot).saturating_sub(1),
                col: 0,
                gamma,
                version: honest.version,
            }),
            1 => beta_edit.insert(position % (beta_edit.len() + 1), EntryUpdate {
                row: 0,
                col: params.m.saturating_add(overshoot).saturating_sub(1),
                gamma,
                version: honest.version,
            }),
            // both sides of `n`: a width check that went one-sided (`>` rather than
            // `!=`) still rejects an over-long row, so drawing only long never sees it
            2 => beta_add.push(InsertDelta {
                w_prime: vec![
                    3u32;
                    if insert_short {
                        params.n.saturating_sub(overshoot)
                    } else {
                        params.n.saturating_add(overshoot)
                    }
                ],
                version: honest.version,
            }),
            _ => version = honest.version.next(),
        }

        let forged = UpdateBatch { beta_edit, beta_del: Vec::new(), beta_add, version };

        let before_data = hint.data.clone();
        let before_l = hint.l;
        let before_version = hint.version;

        let result = state_update_batch(&mut hint, &a_seed, &params, &forged);
        prop_assert!(
            result.is_err(),
            "malformed batch (flaw {flaw}, overshoot {overshoot}) was accepted"
        );
        prop_assert_eq!(&hint.data, &before_data, "rejected batch mutated hint.data");
        prop_assert_eq!(hint.l, before_l, "rejected batch changed hint.l");
        prop_assert_eq!(hint.version, before_version, "rejected batch advanced the version");
        prop_assert_eq!(hint.version, HintVersion::INITIAL);
    }

    /// The accept half for the packed kernel: every shape `squish_db` emits must
    /// be answered, and answered byte-identically to `respond` over the same
    /// unpacked database. Restating the packed-width relation in the test would
    /// only agree with a mutated relation, so the shape comes from `squish_db`.
    #[test]
    fn respond_packed_answers_every_shape_squish_db_produces(
        l in 1usize..6,
        m in 1usize..13,
        query_src in proptest::collection::vec(any::<u32>(), 12),
    ) {
        let params = squishable_params(l, m);
        let db = planted_db(&params);
        let query = &query_src[..m];

        let packed = squish_db(&db, &params).expect("squish");
        prop_assert_eq!(unsquish_db(&packed), db.clone(), "pack/unpack must round-trip");

        let plain = ServerState {
            db: db.clone(),
            params,
            a_seed: [0u8; 32],
            version: HintVersion::INITIAL,
        };
        let expected = respond(&plain, query).expect("respond").answer;

        let got = respond_packed(&packed, query);
        prop_assert!(
            got.is_ok(),
            "respond_packed rejected the shape squish_db just produced: L {l}, M {m}, \
             m_packed {}, data len {}, {:?}",
            packed.m_packed, packed.data.len(), got.as_ref().err(),
        );
        prop_assert_eq!(
            got.expect("ok").answer, expected,
            "packed answer diverged from respond at L {}, M {}", l, m
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// The reject half for the packed kernel. `SquishedDatabase` derives
    /// `Deserialize` with public fields, so a peer declares `data`, `m_packed`
    /// and `original_m` independently; the kernels read cells through `.get()`,
    /// so an unchecked shape answers `Ok` over zero-fill. The oracle is
    /// `squish_db` re-run at the DECLARED `original_m` - not the ceil
    /// expression `validate_packed_shape` evaluates.
    #[test]
    fn respond_packed_answers_a_forged_shape_only_if_squish_db_could_emit_it(
        l in 1usize..5,
        m in 1usize..10,
        original_m_delta in -1i64..2,
        m_packed_delta in -1i64..2,
        len_delta in -2i64..3,
        query_len_delta in -1i64..2,
        query_src in proptest::collection::vec(any::<u32>(), 16),
    ) {
        let params = squishable_params(l, m);
        let honest = squish_db(&planted_db(&params), &params).expect("squish");

        let original_m = shift(honest.original_m, original_m_delta);
        let m_packed = shift(honest.m_packed, m_packed_delta);
        // length is taken relative to the FORGED width, so `len_delta == 0`
        // leaves a length-consistent buffer that only the width relation can reject
        let data_len = shift(l.saturating_mul(m_packed), len_delta);
        let mut data = honest.data.clone();
        data.resize(data_len, 0);
        let forged = SquishedDatabase { data, l, m_packed, original_m };

        let query_len = shift(original_m, query_len_delta);
        let query = &query_src[..query_len.min(query_src.len())];

        // the oracle: what squish_db emits for a database of the declared width
        let oracle = squish_db(
            &vec![0u32; l.saturating_mul(original_m)],
            &squishable_params(l, original_m),
        ).expect("oracle squish");
        let producible = forged.m_packed == oracle.m_packed
            && forged.data.len() == oracle.data.len()
            && query.len() == forged.original_m;

        let result = respond_packed(&forged, query);
        if producible {
            prop_assert!(
                result.is_ok(),
                "rejected a shape squish_db emits: original_m {}, m_packed {} (oracle {}), \
                 data len {} (oracle {}), query len {}, {:?}",
                forged.original_m, forged.m_packed, oracle.m_packed,
                forged.data.len(), oracle.data.len(), query.len(), result.as_ref().err(),
            );
            prop_assert_eq!(
                result.expect("ok").answer, unpacked_reference(&forged, query),
                "answer over a well-formed forged shape diverged from the unpacked reference"
            );
        } else {
            // the VARIANT, not merely `is_err`. `respond_packed` has exactly two
            // rejection paths and the forged shape determines which one must fire:
            // the query-length gate runs first, everything else is the shape gate.
            // Asserting only `is_err` leaves a kernel that returns the wrong error
            // type green - mutation-proved, and it is the one claim the retired
            // wire_shape_rejection examples carried that this property did not.
            let query_gate = query.len() != forged.original_m;
            prop_assert!(
                if query_gate {
                    matches!(&result, Err(IsimplePirError::QueryShape { .. }))
                } else {
                    matches!(&result, Err(IsimplePirError::DatabaseShape { .. }))
                },
                "expected {} for a shape squish_db cannot emit: original_m {}, m_packed {} \
                 (oracle {}), data len {} (oracle {}), query len {}, got {:?}",
                if query_gate { "QueryShape" } else { "DatabaseShape" },
                forged.original_m, forged.m_packed, oracle.m_packed,
                forged.data.len(), oracle.data.len(), query.len(),
                result.map(|r| r.answer),
            );
        }
    }
}
