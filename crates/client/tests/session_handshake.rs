//! Browser session registration crosses the WASM boundary as versioned packing keys
//! followed by one opaque server handle.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_client::{
    build_client_session, build_instance_params_blob, build_padded_batch, build_seeded_query,
    client_packing_keys_versioned, install_server_session_handle, retarget_seeded_query_shard,
    WasmPaddedBatchOutput, WasmSeededQueryOutput,
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn wasm_retargets_only_the_clear_seeded_query_shard() {
    let (mut session, shard_config) = session_fixture();
    install_server_session_handle(&mut session, 91).expect("install handle");
    let shard_bincode = bincode::serialize(&shard_config).expect("serialize shard config");
    let query_bundle = build_seeded_query(&session, &shard_bincode, 7).expect("seeded query");
    let output: WasmSeededQueryOutput = bincode::deserialize(&query_bundle).expect("query output");
    let original: SeededClientQuery =
        bincode::deserialize(&output.query_bytes).expect("original query");

    let retargeted_bytes =
        retarget_seeded_query_shard(&output.query_bytes, 23).expect("retarget query");
    let retargeted: SeededClientQuery =
        bincode::deserialize(&retargeted_bytes).expect("retargeted query");
    assert_eq!(original.shard_id, 0);
    assert_eq!(retargeted.shard_id, 23);

    let mut expected = original;
    expected.shard_id = 23;
    assert_eq!(
        bincode::serialize(&retargeted).expect("serialize retargeted"),
        bincode::serialize(&expected).expect("serialize expected"),
        "the typed retarget must not alter encrypted query material or the session handle"
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn wasm_padded_batch_is_ready_to_post_and_keeps_caller_order_metadata() {
    let (mut session, shard_config) = session_fixture();
    install_server_session_handle(&mut session, 91).expect("install handle");
    let shard_bincode = bincode::serialize(&shard_config).expect("serialize shard config");
    let targets = vec![3u64, 11, 42];
    let targets_bincode = bincode::serialize(&targets).expect("serialize targets");

    let encoded = build_padded_batch(&session, &shard_bincode, &targets_bincode, 1_000_000)
        .expect("padded batch");
    let output: WasmPaddedBatchOutput = bincode::deserialize(&encoded).expect("decode output");
    assert_eq!(output.query_batch_bytes.get(..2), Some([0, 8].as_slice()));
    let queries: Vec<SeededClientQuery> = bincode::deserialize(
        output
            .query_batch_bytes
            .get(2..)
            .expect("versioned batch body"),
    )
    .expect("decode query vector");
    assert_eq!(queries.len(), 4);
    assert_eq!(output.client_states_bincode.len(), targets.len());
    assert_eq!(output.response_slots.len(), targets.len());
    assert!(output.query_batch_bytes.len() <= 1_000_000);

    let caller_indices = output
        .client_states_bincode
        .iter()
        .map(|bytes| {
            bincode::deserialize::<raven_inspire::ClientState>(bytes)
                .expect("decode caller state")
                .index
        })
        .collect::<Vec<_>>();
    assert_eq!(caller_indices, targets);
    assert!(output
        .response_slots
        .iter()
        .all(|slot| usize::try_from(*slot).expect("u32 fits usize") < queries.len()));
}
