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
//! The number this pins is dominated by a design fact, not by noise: `register_client_session`
//! (`crates/client/src/lib.rs:263-279`) validates parameter drift and never sets a session
//! handle, so `query_seeded` takes its `None` branch (`crates/inspire/src/pir/session.rs:223-226`)
//! and inlines the full `ClientPackingKeys` into EVERY query, forever. Shipping the client
//! half of the session handshake is what moves this number, and when it does, this test is
//! where the win is recorded.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use raven_client::build_seeded_query_rust_with_noise_seed;
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::InspireParams;
use raven_inspire::{setup as inspire_setup, ClientSession};

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
        gadget_len: 3,
        security_level: raven_inspire::params::SecurityLevel::Bits128,
    }
}

/// Closed form for a seeded query's serialized size under bincode 1.3 legacy fixint.
///
/// `Poly{coeffs: Vec<u64>, moduli: Vec<u64>, q, dim, crt_q0_inv_mod_q1, is_ntt}`
/// (`crates/inspire/src/math/poly.rs:48-55`) is `8*d*k + 8*k + 41`; a seeded RLWE row adds its
/// 32-byte seed; a seeded RGSW carries `2*ell` rows; `ClientPackingKeys` is `ell` polynomials plus
/// a header, because `z_body` ships empty and `full_key` is false
/// (`inspiring2.rs:604-629`, `:684-690`). Derivation recorded at `ORCH-JOURNAL.md:2104-2121`.
///
/// Carried as a model rather than a bare constant because it states the property the budget
/// encodes: **a query's size is a function of `ring_dim`, the CRT limb count and `gadget_len`
/// ALONE** - not of the entry count, not of the record width. That is why one budget covers every
/// cell, and why a parameter change is the only thing that can move it.
/// KNOWN BLIND SPOT: `crt_limbs` is unpinned. Every fixture here is single-limb, which is what
/// the shipped `DEFAULT_Q` uses, so dropping the limb factor from the ring term leaves all seven
/// tests green - verified by mutation rather than assumed. Pinning it needs a valid 2-CRT
/// parameter set, which must satisfy `q == product(crt_moduli)` and the NTT congruence, and that
/// is a fixture worth building the day a 2-CRT preset ships. Recorded rather than left to be
/// discovered by the change that breaks it.
const fn poly_bytes(ring_dim: usize, crt_limbs: usize) -> usize {
    8 * ring_dim * crt_limbs + 8 * crt_limbs + 41
}

const fn packing_key_bytes(ring_dim: usize, crt_limbs: usize, gadget_len: usize) -> usize {
    gadget_len * poly_bytes(ring_dim, crt_limbs) + 25
}

const fn rgsw_bytes(ring_dim: usize, crt_limbs: usize, gadget_len: usize) -> usize {
    8 + 2 * gadget_len * (32 + poly_bytes(ring_dim, crt_limbs)) + 24
}

/// What the shipped client uploads: no session handle, so the keys ride along.
const fn query_bytes_with_inlined_keys(d: usize, k: usize, ell: usize) -> usize {
    4 + rgsw_bytes(d, k, ell) + 4 + (1 + packing_key_bytes(d, k, ell)) + 1
}

/// What it would upload once the session handshake has a client half.
const fn query_bytes_with_session_handle(d: usize, k: usize, ell: usize) -> usize {
    4 + rgsw_bytes(d, k, ell) + 4 + 1 + 9
}

/// Anchored to production, not to itself. 98,840 B is the `query_bytes` every real artifact reports
/// at the shipped `ring_dim = 2048`, single CRT limb, `gadget_len = 3` - reproduced byte-identically
/// across a 16x entries range, a 16x width range, four months and two machines. The same closed form
/// predicts `response_bytes = 32,879`, which matches every artifact too.
#[test]
fn the_size_model_predicts_the_shipped_query_exactly() {
    assert_eq!(
        query_bytes_with_session_handle(2048, 1, 3),
        98_840,
        "the model must reproduce the production query size measured on the wire"
    );
    assert_eq!(
        packing_key_bytes(2048, 1, 3),
        49_324,
        "and the keys the shipped client inlines on top of it"
    );
    assert_eq!(
        query_bytes_with_inlined_keys(2048, 1, 3),
        148_156,
        "so a real browser query is 1.4989x what the bench harness measures"
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
    params.gadget_len = gadget_len;
    let db: Vec<u8> = (0..params.ring_dim * ENTRY_BYTES)
        .map(|i| u8::try_from(i % 251).expect("< 251"))
        .collect();
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &db, ENTRY_BYTES, &mut sampler).expect("setup");
    let mut session_sampler = GaussianSampler::new(params.sigma);
    let session = ClientSession::new(crs, sk, &mut session_sampler).expect("session");

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
/// Derived by measurement at `ring_dim = 256`, not by arithmetic: 19,132 B. bincode writes
/// fixed-width fields over fixed-length vectors, so the length does not vary with the random
/// values in the query and this is a stable number, not a sample.
const QUERY_UPLOAD_BUDGET_BYTES: usize = 19_132;

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

/// Names WHY the budget is what it is: the shipped client has no session handle, so every
/// query carries a full copy of the packing keys. That is the cost the server-side handshake
/// already at `POST /v1/instance/:id/session` would remove, and it currently has no client.
///
/// Asserts presence and share, not dominance: the keys' fraction of a query is a function of
/// `ring_dim` (6,316 of 19,132 B here at 256; the production ring is 2048), so a dominance
/// claim would be an arithmetic accident of the fixture rather than a property.
#[test]
fn every_query_carries_a_full_copy_of_the_packing_keys() {
    let params = test_params();
    let db: Vec<u8> = (0..params.ring_dim * ENTRY_BYTES)
        .map(|i| u8::try_from(i % 251).expect("< 251"))
        .collect();
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &db, ENTRY_BYTES, &mut sampler).expect("setup");
    let mut session_sampler = GaussianSampler::new(params.sigma);
    let session = ClientSession::new(crs, sk, &mut session_sampler).expect("session");
    let (_state, query) = build_seeded_query_rust_with_noise_seed(
        &session,
        &params,
        &encoded_db.config,
        0,
        PINNED_NOISE_SEED,
    )
    .expect("query");

    let keys = query
        .inspiring_packing_keys
        .as_ref()
        .expect("the shipped client inlines packing keys because no session handle is set");
    let key_bytes = bincode::serialize(keys).expect("serialize keys").len();
    let total = bincode::serialize(&query).expect("serialize").len();

    assert!(
        query.session_handle.is_none(),
        "no client sets a session handle today; if one does, this budget must be re-derived \
         downward because the keys stop being inlined"
    );
    assert!(
        key_bytes > 0 && key_bytes < total,
        "the packing keys ({key_bytes} B) are inlined into every {total} B query and are the \
         cost the session handshake would remove"
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
        query_bytes_with_inlined_keys(512, 1, 3),
        "doubling the ring must move the query by exactly the modelled amount"
    );
}

#[test]
fn the_model_predicts_a_wider_gadget() {
    assert_eq!(
        measured_query_bytes_at(256, 4),
        query_bytes_with_inlined_keys(256, 1, 4),
        "a fourth gadget digit adds two RGSW rows and one packing-key poly, and nothing else"
    );
}

/// And the fixture the budget itself is measured at.
#[test]
fn the_model_predicts_the_fixture_query() {
    assert_eq!(
        measured_query_bytes(),
        query_bytes_with_inlined_keys(256, 1, 3)
    );
}
