//! The Rust entry points hold a caller-built session to the parameter floors, as the wasm exports
//! hold a served one, through this crate's re-export.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#![cfg(not(target_arch = "wasm32"))]

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, ShardConfig};
use raven_inspire::setup as inspire_setup;
use raven_inspire::ClientSession;
use raven_inspire_client_wasm::{
    build_padded_batch_rust, build_seeded_query_rust, deserialize_client_session_rust,
    PaddedBatchError,
};

const ENTRY_BYTES: usize = 32;
const RING_REFUSAL: &str = "ring_dim 256 is outside [2048, 4096]";

fn below_floor() -> InspireParams {
    InspireParams {
        ring_dim: 256,
        ..InspireParams::secure_128_d2048()
    }
}

fn session_at(params: &InspireParams) -> (ClientSession, ShardConfig) {
    let db = vec![7u8; params.ring_dim * ENTRY_BYTES];
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded, sk) = inspire_setup(params, &db, ENTRY_BYTES, &mut sampler).expect("setup");
    let session = ClientSession::new(crs, sk, &mut sampler).expect("session");
    (session, encoded.config)
}

#[test]
fn a_query_under_a_sub_floor_session_is_refused() {
    let params = below_floor();
    let (session, config) = session_at(&params);
    let refusal = build_seeded_query_rust(&session, &params, &config, 0).expect_err("refused");
    assert!(refusal.contains(RING_REFUSAL), "{refusal}");
    // The session's own params are checked too, not only the ones passed beside it.
    let shipped = InspireParams::secure_128_d2048();
    let refusal = build_seeded_query_rust(&session, &shipped, &config, 0).expect_err("refused");
    assert!(refusal.contains(RING_REFUSAL), "{refusal}");
}

#[test]
fn a_padded_batch_under_sub_floor_params_is_refused() {
    let params = below_floor();
    let (session, config) = session_at(&params);
    match build_padded_batch_rust(&session, &params, &config, &[0], 1 << 20) {
        Err(PaddedBatchError::Configuration { detail }) => {
            assert!(detail.contains(RING_REFUSAL), "{detail}");
        }
        other => panic!("expected a floor refusal, got {other:?}"),
    }
}

#[test]
fn a_cached_session_under_sub_floor_params_is_refused_before_it_is_read() {
    let params_bin = bincode::serialize(&below_floor()).expect("params");
    let bundle =
        bincode::serialize(&(params_bin, Vec::<u8>::new(), Vec::<u8>::new())).expect("bundle");
    let refusal = deserialize_client_session_rust(&bundle, &[], &[]).expect_err("refused");
    assert!(
        refusal.contains(&format!(
            "parameter floor refused inspire_params: {RING_REFUSAL}"
        )),
        "{refusal}"
    );
}
