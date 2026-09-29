//! Browser session registration crosses the WASM boundary as versioned packing keys
//! followed by one opaque server handle.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_client::{
    build_client_session, build_instance_params_blob, build_seeded_query,
    client_packing_keys_versioned, install_server_session_handle, WasmSeededQueryOutput,
};
use raven_inspire::inspiring::ClientPackingKeys;
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, SecurityLevel, ShardConfig};
use raven_inspire::{setup, SeededClientQuery, ServerSessionHandle};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

const ENTRY_BYTES: usize = 32;

fn params() -> InspireParams {
    InspireParams {
        ring_dim: 256,
        q: 1_152_921_504_606_830_593,
        crt_moduli: vec![1_152_921_504_606_830_593],
        p: 65_537,
        sigma: 6.4,
        gadget_base: 1 << 20,
        query_gadget_len: 3,
        packing_gadget_len: 3,
        security_level: SecurityLevel::Bits128,
    }
}

fn session_fixture() -> (raven_client::ClientSessionHandle, ShardConfig) {
    let params = params();
    let database = vec![7u8; 2 * params.ring_dim * ENTRY_BYTES];
    let mut sampler = GaussianSampler::with_seed(params.sigma, 19);
    let (crs, encoded, _secret_key) =
        setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("setup");
    let params_bincode = bincode::serialize(&params).expect("serialize params");
    let shard_bincode = bincode::serialize(&encoded.config).expect("serialize shard config");
    let bundle = build_instance_params_blob(&params_bincode, &shard_bincode).expect("bundle");
    let crs_bincode = crs.to_versioned_bytes().expect("versioned CRS");
    let session = build_client_session(&bundle, &crs_bincode).expect("client session");
    (session, encoded.config)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn wasm_exports_upload_versioned_keys_then_install_the_returned_handle() {
    let (mut session, shard_config) = session_fixture();

    let registration = client_packing_keys_versioned(&session).expect("registration body");
    assert_eq!(registration.get(..2), Some([0, 8].as_slice()));
    let keys: ClientPackingKeys =
        bincode::deserialize(registration.get(2..).expect("versioned body")).expect("packing keys");
    assert!(
        !keys.y_body.is_empty(),
        "registration must carry real packing keys"
    );

    let issued = ServerSessionHandle((1u64 << 32) + 77);
    install_server_session_handle(&mut session, issued.0).expect("install handle");
    let shard_bincode = bincode::serialize(&shard_config).expect("serialize shard config");
    let query_bundle = build_seeded_query(&session, &shard_bincode, 3).expect("seeded query");
    let output: WasmSeededQueryOutput = bincode::deserialize(&query_bundle).expect("query output");
    let query: SeededClientQuery = bincode::deserialize(&output.query_bytes).expect("query");

    assert_eq!(query.session_handle, Some(issued));
    assert!(
        query.inspiring_packing_keys.is_none(),
        "registered queries must never inline the uploaded packing keys"
    );
}
