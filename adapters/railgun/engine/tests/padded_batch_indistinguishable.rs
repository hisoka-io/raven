//! Client-side batch padding against the real InsPIRe path.
//!
//! Pins the three properties the fixed-size ladder rests on: the emitted batch
//! length is always a ladder step, a padded slot is byte-shaped exactly like a
//! real one on the wire, and padding does not disturb slot ordering or the
//! plaintexts the real slots decode to.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::batch_ladder;
use raven_railgun_engine::inspire::{
    build_client_session, build_padded_batch, build_seeded_query, extract_response,
    register_client_session, setup_state, InspireServerState, RavenInspireScheme,
};
use raven_railgun_engine::PirScheme;

const ENTRY_SIZE: usize = 32;
const ENTRIES: usize = 256;

fn database() -> Vec<u8> {
    (0..ENTRIES)
        .flat_map(|i| (0..ENTRY_SIZE).map(move |j| u8::try_from((i * 7 + j) % 251).expect("< 251")))
        .collect()
}

fn fixture() -> (
    InspireParams,
    InspireServerState,
    raven_inspire::ClientSession,
    Vec<u8>,
) {
    let params = InspireParams::secure_128_d2048();
    let db = database();
    let (state, sk) =
        setup_state(&params, &db, ENTRY_SIZE, InspireVariant::TwoPacking).expect("setup_state");
    let crs = (*state.crs).clone();
    let mut session = build_client_session(crs, sk, &params).expect("client session");
    register_client_session(&mut session, &state).expect("register session");
    (params, state, session, db)
}

fn expected_record(db: &[u8], index: usize) -> Vec<u8> {
    db.get(index * ENTRY_SIZE..(index + 1) * ENTRY_SIZE)
        .expect("record in range")
        .to_vec()
}

#[test]
fn padding_lands_on_a_ladder_step_for_every_real_count() {
    let (params, state, session, _db) = fixture();
    for real in 1..=8usize {
        let indices: Vec<u64> = (0..real as u64).collect();
        let (states, queries) =
            build_padded_batch(&session, state.shard_config(), &params, &indices)
                .expect("pad batch");
        let step = batch_ladder::padded_len(real).expect("in ladder range");
        assert_eq!(
            queries.len(),
            step,
            "{real} real queries must emit exactly {step} slots"
        );
        assert_eq!(states.len(), queries.len());
        assert!(
            batch_ladder::is_on_ladder(queries.len()),
            "emitted length {} is off the ladder",
            queries.len()
        );
    }
}

#[test]
fn a_padded_slot_is_wire_identical_in_shape_to_a_real_one() {
    let (params, state, session, _db) = fixture();
    let indices: Vec<u64> = vec![3, 11, 42];
    let (_states, queries) =
        build_padded_batch(&session, state.shard_config(), &params, &indices).expect("pad batch");
    assert_eq!(queries.len(), 4, "3 real queries pad to the step at 4");

    let mut lengths = Vec::with_capacity(queries.len());
    for (i, q) in queries.iter().enumerate() {
        assert_eq!(
            q.shard_id,
            queries.first().expect("non-empty").shard_id,
            "slot {i} must address the same shard set as the real slots"
        );
        assert!(
            q.inspiring_packing_keys.is_none(),
            "slot {i} must use the session handle, not inlined keys"
        );
        assert_eq!(
            q.session_handle.is_some(),
            queries.first().expect("non-empty").session_handle.is_some(),
            "slot {i} must carry the same handshake shape as the real slots"
        );
        lengths.push(bincode::serialize(q).expect("serialize slot").len());
    }
    let first = *lengths.first().expect("non-empty");
    assert!(
        lengths.iter().all(|l| *l == first),
        "every slot must serialize to the same byte length, else the pad is \
         distinguishable by size: {lengths:?}"
    );
}

#[test]
fn real_slots_still_decode_in_order_inside_a_padded_batch() {
    let (params, state, session, db) = fixture();
    let indices: Vec<u64> = vec![5, 9, 17];
    let (states, queries) =
        build_padded_batch(&session, state.shard_config(), &params, &indices).expect("pad batch");

    let responses: Vec<_> = queries
        .iter()
        .map(|q| {
            <RavenInspireScheme as PirScheme>::respond(&state, q).expect("server serves every slot")
        })
        .collect();
    assert_eq!(
        responses.len(),
        4,
        "the server answers the pad slots too; a skipped pass would be the distinguisher"
    );

    for (slot, index) in indices.iter().enumerate() {
        let plaintext = extract_response(
            state.crs.as_ref(),
            states.get(slot).expect("state for slot"),
            responses.get(slot).expect("response for slot"),
            ENTRY_SIZE,
        )
        .expect("extract");
        assert_eq!(
            plaintext,
            expected_record(&db, usize::try_from(*index).expect("index fits usize")),
            "slot {slot} must decode the record at global index {index}"
        );
    }
}

#[test]
fn an_unpadded_batch_of_three_is_off_the_ladder() {
    let (params, state, session, _db) = fixture();
    let unpadded: Vec<_> = [1u64, 2, 3]
        .iter()
        .map(|i| {
            build_seeded_query(&session, state.shard_config(), *i, &params)
                .expect("build")
                .1
        })
        .collect();
    assert!(
        batch_ladder::check_batch_len(unpadded.len()).is_err(),
        "the pre-padding call path emits 3 slots, which the server now refuses"
    );
}

#[test]
fn empty_and_oversized_batches_are_typed_errors() {
    let (params, state, session, _db) = fixture();
    let err = build_padded_batch(&session, state.shard_config(), &params, &[])
        .expect_err("empty batch has nothing to pad");
    assert!(
        format!("{err}").contains("at least one real query"),
        "{err}"
    );

    let too_many: Vec<u64> = (0..33).collect();
    let err = build_padded_batch(&session, state.shard_config(), &params, &too_many)
        .expect_err("33 exceeds the top ladder step");
    assert!(format!("{err}").contains("split into"), "{err}");
}
