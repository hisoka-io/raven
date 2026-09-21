//! Every response `respond` returns is already mod-switched to the wire modulus, and the
//! switch is what the serialized size and the extractor both depend on.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_engine::inspire::{
    build_client_session, build_seeded_query, extract_response, register_client_session,
    setup_state, RavenInspireScheme, WIRE_RESPONSE_MODULUS,
};
use raven_railgun_engine::PirScheme;
use raven_railgun_testkit::{cached_toy_state, toy_db, toy_secret_key, TOY_ENTRIES};

/// The served record: ten Merkle levels plus the leaf, 256 InspiRING columns.
const ENTRY_BYTES: usize = 512;
const TARGET_INDEX: u64 = 5;

/// 78-byte envelope, then full `a` and one retained `b` coefficient per 16-bit column.
const fn wire_bytes(entry_bytes: usize, coefficient_bits: usize) -> usize {
    78 + (2048 + entry_bytes / 2) * coefficient_bits / 8
}

fn served_response(
    entry_bytes: usize,
) -> (
    raven_railgun_engine::inspire::InspireServerState,
    raven_inspire::ClientState,
    raven_inspire::ServerResponse,
) {
    let state = cached_toy_state(entry_bytes);
    let params = state.crs.params.clone();
    let mut session = build_client_session((*state.crs).clone(), toy_secret_key(&params), &params)
        .expect("client session");
    register_client_session(&mut session, &state).expect("register session");
    let (client_state, query) =
        build_seeded_query(&session, state.shard_config(), TARGET_INDEX, &params)
            .expect("build_seeded_query");
    let response = RavenInspireScheme::respond(&state, &query).expect("respond");
    (state, client_state, response)
}

fn expected_row() -> Vec<u8> {
    let db = toy_db(TOY_ENTRIES, ENTRY_BYTES);
    let start = usize::try_from(TARGET_INDEX).unwrap() * ENTRY_BYTES;
    db[start..start + ENTRY_BYTES].to_vec()
}

#[test]
fn respond_returns_the_switched_modulus_and_the_tight_wire_size() {
    assert_eq!(wire_bytes(ENTRY_BYTES, 60), 17_358);
    // Status row, the 256 B cell, and the served path row.
    for (entry_bytes, pinned) in [(32, 9_366), (256, 9_870), (ENTRY_BYTES, 10_446)] {
        let (_state, _client_state, response) = served_response(entry_bytes);
        assert_eq!(response.ciphertext.modulus(), WIRE_RESPONSE_MODULUS);
        let wire = response.to_binary().expect("serialize");
        assert_eq!(wire.len(), pinned, "entry_bytes={entry_bytes}");
        assert_eq!(
            wire_bytes(entry_bytes, 36),
            pinned,
            "entry_bytes={entry_bytes}"
        );
    }
}

#[test]
fn the_switched_response_extracts_to_the_row_and_the_unswitched_extractor_cannot() {
    let (state, client_state, response) = served_response(ENTRY_BYTES);
    let expected = expected_row();

    // Negative control: the pre-switch extractor sees a modulus the CRS does not describe.
    // Whether it errors, panics on the NTT moduli, or returns other bytes, it must not
    // produce the row -- otherwise the oracle above proves nothing about the switch.
    let unswitched = std::panic::catch_unwind(|| {
        raven_inspire::extract_two_packing(&state.crs, &client_state, &response, ENTRY_BYTES)
    });
    let decoded_by_unswitched = matches!(&unswitched, Ok(Ok(bytes)) if *bytes == expected);
    assert!(
        !decoded_by_unswitched,
        "the unswitched extractor decoded a switched response: the switch is not on the wire"
    );

    let plaintext =
        extract_response(&state.crs, &client_state, &response, ENTRY_BYTES).expect("extract");
    assert_eq!(plaintext, expected);
}

/// The rung is fixed; the parameters are not. A set whose plaintext modulus the rung cannot
/// carry must fail where an operator sees it, not boot healthy and refuse every query.
#[test]
fn a_parameter_set_the_served_rung_cannot_carry_is_refused_at_setup() {
    let mut params = InspireParams::secure_128_d2048();
    params.p = (1 << 22) + 1;
    let err = setup_state(
        &params,
        &toy_db(TOY_ENTRIES, 32),
        32,
        InspireVariant::TwoPacking,
    )
    .expect_err("36 bits cannot carry a 22-bit plaintext modulus");
    assert!(err.to_string().contains("served response modulus"), "{err}");
}
