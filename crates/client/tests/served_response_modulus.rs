//! The framework client decrypts under its session's modulus or the one served mod-switch
//! rung. A response declaring anything else is refused in bounded time, never decrypted.

#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::mpsc;
use std::time::Duration;

use raven_client::extract_response_rust;
use raven_inspire::math::{GaussianSampler, Poly};
use raven_inspire::params::DEFAULT_Q_2CRT_30BIT;
use raven_inspire::pir::mod_switch::{
    mod_switch_response_checked, MOD_SWITCH_TARGET_36BIT, MOD_SWITCH_TARGET_45BIT,
};
use raven_inspire::rlwe::RlweCiphertext;
use raven_inspire::{
    query_seeded, respond_seeded_inspiring, setup, ClientState, InspireParams, SecurityLevel,
    ServerCrs, ServerResponse,
};

const ENTRY_SIZE: usize = 32;
const TARGET_INDEX: u64 = 42;
/// `162,739 * 422,267`: 36 bits and `== 1 mod 512`, so it clears every arithmetic
/// precondition of the switch; the NTT root search over it never terminates.
const COMPOSITE_36BIT: u64 = 68_719_309_313;
const REFUSAL_BOUND: Duration = Duration::from_secs(20);

struct Served {
    crs: ServerCrs,
    state: ClientState,
    response: ServerResponse,
    row: Vec<u8>,
}

fn serve(crt_moduli: Vec<u64>) -> Served {
    let params = InspireParams {
        ring_dim: 256,
        q: crt_moduli.iter().product(),
        crt_moduli,
        p: 65_537,
        sigma: 6.4,
        gadget_base: 1 << 20,
        query_gadget_len: 3,
        packing_gadget_len: 3,
        security_level: SecurityLevel::Bits128,
    };
    let database: Vec<u8> = (0..params.ring_dim * ENTRY_SIZE)
        .map(|i| ((i * 17 + 3) % 251) as u8)
        .collect();
    let mut sampler = GaussianSampler::with_seed(params.sigma, 37);
    let (crs, encoded_db, sk) = setup(&params, &database, ENTRY_SIZE, &mut sampler).expect("setup");
    let (state, query) =
        query_seeded(&crs, TARGET_INDEX, &encoded_db.config, &sk, &mut sampler).expect("query");
    let response = respond_seeded_inspiring(&crs, &encoded_db, &query).expect("respond");
    let start = usize::try_from(TARGET_INDEX).unwrap() * ENTRY_SIZE;
    Served {
        crs,
        state,
        response,
        row: database[start..start + ENTRY_SIZE].to_vec(),
    }
}

fn single_limb() -> Served {
    serve(vec![raven_inspire::math::mod_q::DEFAULT_Q])
}

fn relabelled(response: &ServerResponse, build: impl Fn(Vec<u64>) -> Poly) -> ServerResponse {
    ServerResponse {
        ciphertext: RlweCiphertext::from_parts(
            build(response.ciphertext.a.coeffs().to_vec()),
            build(response.ciphertext.b.coeffs().to_vec()),
        ),
        column_ciphertexts: Vec::new(),
        packing_mode: response.packing_mode,
        packed_coefficients: response.packed_coefficients,
    }
}

#[test]
fn the_served_rung_and_an_unswitched_response_decode() {
    let served = single_limb();
    let switched = mod_switch_response_checked(
        &served.crs.params,
        &served.response,
        MOD_SWITCH_TARGET_36BIT,
    )
    .expect("switch");
    // The wire form, not the in-memory one: what a server sends is what gets recognised.
    let wire = ServerResponse::from_binary(&switched.to_binary().expect("serialize"))
        .expect("deserialize");
    assert_eq!(
        extract_response_rust(&served.crs, &served.state, &wire, ENTRY_SIZE).expect("served rung"),
        served.row
    );
    assert_eq!(
        extract_response_rust(&served.crs, &served.state, &served.response, ENTRY_SIZE)
            .expect("unswitched"),
        served.row
    );
}

#[test]
fn an_unswitched_two_limb_response_decodes() {
    let served = serve(DEFAULT_Q_2CRT_30BIT.to_vec());
    assert_eq!(
        extract_response_rust(&served.crs, &served.state, &served.response, ENTRY_SIZE)
            .expect("two-limb unswitched"),
        served.row
    );
}

/// The extractor implements this target; no server here serves it, so the client does not
/// take it. One schema, one switched layout.
#[test]
fn an_implemented_but_unserved_target_is_refused() {
    let served = single_limb();
    let switched = mod_switch_response_checked(
        &served.crs.params,
        &served.response,
        MOD_SWITCH_TARGET_45BIT,
    )
    .expect("switch");
    let err = extract_response_rust(&served.crs, &served.state, &switched, ENTRY_SIZE)
        .expect_err("a 45-bit response is not the served layout");
    assert!(err.contains("served mod-switch target"), "{err}");
}

#[test]
fn a_composite_modulus_is_refused_in_bounded_time() {
    let served = single_limb();
    let switched = mod_switch_response_checked(
        &served.crs.params,
        &served.response,
        MOD_SWITCH_TARGET_36BIT,
    )
    .expect("switch");
    let forged = relabelled(&switched, |coeffs| {
        Poly::from_coeffs(
            coeffs.into_iter().map(|c| c % COMPOSITE_36BIT).collect(),
            COMPOSITE_36BIT,
        )
    });
    // Through the codec: the forgery has to survive the wire to matter.
    let forged = ServerResponse::from_binary(&forged.to_binary().expect("serialize"))
        .expect("the codec accepts any modulus; recognising it is the client's job");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(extract_response_rust(
            &served.crs,
            &served.state,
            &forged,
            ENTRY_SIZE,
        ));
    });
    let err = rx
        .recv_timeout(REFUSAL_BOUND)
        .expect("the client must return: on wasm nothing can interrupt it")
        .expect_err("a composite modulus must not decode");
    assert!(err.contains("68719309313"), "{err}");
}

#[test]
fn a_forged_two_limb_response_is_refused_not_panicked_on() {
    let served = single_limb();
    let switched = mod_switch_response_checked(
        &served.crs.params,
        &served.response,
        MOD_SWITCH_TARGET_36BIT,
    )
    .expect("switch");
    let forged = relabelled(&switched, |coeffs| {
        let limbs: Vec<u64> = DEFAULT_Q_2CRT_30BIT
            .iter()
            .flat_map(|&m| coeffs.iter().map(move |&c| c % m))
            .collect();
        Poly::from_crt_coeffs(limbs, &DEFAULT_Q_2CRT_30BIT)
    });
    let outcome = std::panic::catch_unwind(|| {
        extract_response_rust(&served.crs, &served.state, &forged, ENTRY_SIZE)
    })
    .expect("a forged limb count must be refused, not trap the client");
    let err = outcome.expect_err("limbs the session does not have must not decode");
    assert!(err.contains("2 limb(s)"), "{err}");
}
