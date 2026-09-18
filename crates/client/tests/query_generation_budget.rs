//! The client's per-query upload budget, asserted in bytes.
//!
//! Raven's client runs in a browser; that is a load-bearing requirement, not an aspiration.
//! What a phone uploads per query is therefore a correctness property of the product, and
//! nothing in the tree asserted it: a grep for any client query-size assertion returns
//! nothing, and the bench harness measures the SERVER-side wire shape rather than what the
//! shipped WASM client actually emits.
//!
//! Bytes rather than wall-clock, deliberately. A microsecond budget measures the runner and
//! flakes on shared CI; a serialized length is platform-invariant, so this runs natively and
//! blocks per commit.
//!
//! The number this pins is dominated by the session handshake: after the client uploads its
//! packing keys once, `query_seeded` carries only the returned handle. This test is where that
//! per-query bandwidth win stays locked.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use raven_client::build_seeded_query_rust_with_noise_seed;
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::InspireParams;
use raven_inspire::{setup as inspire_setup, ClientSession, ServerSessionHandle};

const ENTRY_BYTES: usize = 32;
const PINNED_NOISE_SEED: [u8; 32] = [0x5a; 32];

/// Small ring so the test is fast. The budget below is asserted for THIS shape; the
/// production shape is gated separately by the byte-exact bench gate, which reproduced
/// `query_bytes` byte-identically across four months and two machines.
fn test_params() -> InspireParams {
    InspireParams {
        ring_dim: 256,
        q: 1_152_921_504_606_830_593,
        crt_moduli: vec![1_152_921_504_606_830_593],
        p: 65_537,
        sigma: 6.4,
        gadget_base: 1 << 20,
        query_gadget_len: 3,
        packing_gadget_len: 3,
        security_level: raven_inspire::params::SecurityLevel::Bits128,
    }
}

/// Closed form for a seeded query's serialized size under bincode 1.3 legacy fixint.
///
/// `Poly{coeffs: Vec<u64>, moduli: Vec<u64>, q, dim, crt_q0_inv_mod_q1, is_ntt}`
/// (`crates/inspire/src/math/poly.rs:48-55`) is `8*d*k + 8*k + 41`; a seeded RLWE row adds its
/// 32-byte seed; the exact fold query carries one row; `ClientPackingKeys` is `ell` polynomials plus
/// a header, because `z_body` ships empty and `full_key` is false
/// (`inspiring2.rs:604-629`, `:684-690`). Derivation recorded at `ORCH-JOURNAL.md:2104-2121`.
///
/// Carried as a model rather than a bare constant because it states the property the budget
/// encodes: a query's size is a function of `ring_dim` and the CRT limb count alone - not of the
/// entry count, record width, or legacy query gadget length.
/// KNOWN BLIND SPOT: `crt_limbs` is unpinned. Every fixture here is single-limb, which is what
/// the shipped `DEFAULT_Q` uses, so dropping the limb factor from the ring term leaves all seven
/// tests green - verified by mutation rather than assumed. Pinning it needs a valid 2-CRT
/// parameter set, which must satisfy `q == product(crt_moduli)` and the NTT congruence, and that
/// is a fixture worth building the day a 2-CRT preset ships. Recorded rather than left to be
/// discovered by the change that breaks it.
const fn poly_bytes(ring_dim: usize, crt_limbs: usize) -> usize {
    (60 * ring_dim * crt_limbs).div_ceil(8) + 8 * crt_limbs + 41
}

const fn packing_key_bytes(ring_dim: usize, crt_limbs: usize, gadget_len: usize) -> usize {
    gadget_len * poly_bytes(ring_dim, crt_limbs) + 25
}

const fn fold_query_bytes(ring_dim: usize, crt_limbs: usize) -> usize {
    8 + 32 + poly_bytes(ring_dim, crt_limbs) + 24
}

/// Legacy pre-handshake query shape, retained to state the removed cost.
const fn query_bytes_with_inlined_keys(d: usize, k: usize, packing_ell: usize) -> usize {
    4 + fold_query_bytes(d, k) + 4 + (1 + packing_key_bytes(d, k, packing_ell)) + 1
}

/// What it would upload once the session handshake has a client half.
const fn query_bytes_with_session_handle(d: usize, k: usize) -> usize {
    4 + fold_query_bytes(d, k) + 4 + 1 + 9
}

/// Anchored to the exact one-row query at `ring_dim = 2048` and one CRT limb.
#[test]
fn the_size_model_predicts_the_shipped_query_exactly() {
    assert_eq!(
        query_bytes_with_session_handle(2048, 1),
        15_491,
        "the model must reproduce the production query size measured on the wire"
    );
    assert_eq!(
        packing_key_bytes(2048, 1, 3),
        46_252,
        "and the keys the shipped client uploads once before it"
    );
    assert_eq!(
        query_bytes_with_inlined_keys(2048, 1, 3),
        61_735,
        "so skipping the handshake would still inline the one-time packing keys"
    );
}

/// Serialized upload for one query at the fixture shape, measured rather than assumed.
fn measured_query_bytes() -> usize {
    measured_query_bytes_at(256, 3)
}

/// Measured upload at an arbitrary ring and gadget width, so the model's two free coefficients
/// can be pinned independently rather than jointly at one point.
fn measured_query_bytes_at(ring_dim: usize, gadget_len: usize) -> usize {
    let mut params = test_params();
    params.ring_dim = ring_dim;
    params.query_gadget_len = gadget_len;
    let db: Vec<u8> = (0..params.ring_dim * ENTRY_BYTES)
        .map(|i| u8::try_from(i % 251).expect("< 251"))
        .collect();
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &db, ENTRY_BYTES, &mut sampler).expect("setup");
    let mut session_sampler = GaussianSampler::new(params.sigma);
    let mut session = ClientSession::new(crs, sk, &mut session_sampler).expect("session");
    session
        .install_server_session_handle(ServerSessionHandle(7))
        .expect("install remote handle");

    let (_state, query) = build_seeded_query_rust_with_noise_seed(
        &session,
        &params,
        &encoded_db.config,
        0,
        PINNED_NOISE_SEED,
    )
    .expect("query");

    bincode::serialize(&query).expect("serialize").len()
}

/// The budget. A change that moves the per-query upload must move this line, which makes
/// the cost visible in review rather than discovered by a user on a phone.
///
/// Derived by measurement at `ring_dim = 256`, not by arithmetic: 2,051 B. bincode writes
/// fixed-width fields over fixed-length vectors, so the length does not vary with the random
/// values in the query and this is a stable number, not a sample.
const QUERY_UPLOAD_BUDGET_BYTES: usize = 2_051;

#[test]
fn one_query_upload_stays_within_its_budget() {
    let measured = measured_query_bytes();
    assert!(
        measured <= QUERY_UPLOAD_BUDGET_BYTES,
        "per-query upload grew to {measured} B, past the {QUERY_UPLOAD_BUDGET_BYTES} B budget. \
         This is what a browser client sends on EVERY query. If the growth is intended, move \
         the budget deliberately and say why in the commit message."
    );
}

/// The budget must not silently rot upward either: a budget far above the real cost stops
/// gating. If this fails, the cost went DOWN and the budget should be lowered to lock the win.
#[test]
fn the_budget_still_tracks_the_real_cost() {
    let measured = measured_query_bytes();
    let slack = QUERY_UPLOAD_BUDGET_BYTES.saturating_sub(measured);
    assert!(
        slack * 20 <= QUERY_UPLOAD_BUDGET_BYTES,
        "per-query upload fell to {measured} B against a {QUERY_UPLOAD_BUDGET_BYTES} B budget \
         ({slack} B of slack, over 5%). Lower the budget to lock the improvement in, or a later \
         regression will hide inside the gap."
    );
}

/// The shipped client installs the remote handle before emitting a query, so inline keys and
/// a handle are mutually exclusive on the wire.
#[test]
fn registered_query_carries_the_handle_and_no_inline_packing_keys() {
    let params = test_params();
    let db: Vec<u8> = (0..params.ring_dim * ENTRY_BYTES)
        .map(|i| u8::try_from(i % 251).expect("< 251"))
        .collect();
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &db, ENTRY_BYTES, &mut sampler).expect("setup");
    let mut session_sampler = GaussianSampler::new(params.sigma);
    let mut session = ClientSession::new(crs, sk, &mut session_sampler).expect("session");
    let handle = ServerSessionHandle((1u64 << 32) + 91);
    session
        .install_server_session_handle(handle)
        .expect("install remote handle");
    let (_state, query) = build_seeded_query_rust_with_noise_seed(
        &session,
        &params,
        &encoded_db.config,
        0,
        PINNED_NOISE_SEED,
    )
    .expect("query");

    let total = bincode::serialize(&query).expect("serialize").len();

    assert_eq!(query.session_handle, Some(handle));
    assert!(query.inspiring_packing_keys.is_none());
    assert_eq!(total, query_bytes_with_session_handle(256, 1));
    assert_eq!(
        query_bytes_with_inlined_keys(256, 1, 3) - total,
        5_924,
        "the one-time upload must remove the full inline-key option from each later query"
    );
}

/// One fixture pins both free coefficients jointly, which any two compensating errors satisfy.
/// These pin them separately: F2 moves only the ring, F3 moves only the gadget width. A
/// prediction that misses here means the MODEL is wrong, and that is the finding - not a number
/// to adjust until it agrees.
#[test]
fn the_model_predicts_a_wider_ring() {
    assert_eq!(
        measured_query_bytes_at(512, 3),
        query_bytes_with_session_handle(512, 1),
        "doubling the ring must move the query by exactly the modelled amount"
    );
}

#[test]
fn the_model_predicts_a_wider_gadget() {
    assert_eq!(
        measured_query_bytes_at(256, 4),
        query_bytes_with_session_handle(256, 1),
        "legacy query gadget width does not change the exact one-row query"
    );
}

/// And the fixture the budget itself is measured at.
#[test]
fn the_model_predicts_the_fixture_query() {
    assert_eq!(
        measured_query_bytes(),
        query_bytes_with_session_handle(256, 1)
    );
}
