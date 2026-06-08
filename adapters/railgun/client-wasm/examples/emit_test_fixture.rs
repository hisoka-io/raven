//! Emit the binary fixture the SDK privacy-invariant TS test reads.
//!
//! Run: `cargo run --release --example emit_test_fixture --manifest-path
//! adapters/railgun/client-wasm/Cargo.toml -- <out-dir>`

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::format_push_string,
    clippy::cast_possible_truncation,
    clippy::manual_assert,
    clippy::used_underscore_items
)]

use std::fs;
use std::path::Path;

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::InspireParams;
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::setup as inspire_setup;
use raven_inspire_client_wasm::{build_seeded_query_rust, extract_response_rust};

const ENTRY_BYTES: usize = 32;
const NUM_FIXTURE_INDICES: u32 = 5;

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

fn bc_for(idx: u32) -> [u8; 32] {
    let mut bc = [0u8; 32];
    bc[0] = 0xBC;
    bc[28..32].copy_from_slice(&idx.to_le_bytes());
    bc
}

#[derive(serde::Serialize)]
struct FixtureMeta {
    entry_size: usize,
    list_key_hex: String,
    target_indices: Vec<u32>,
    bcs_hex: Vec<String>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        panic!("usage: emit_test_fixture <out-dir>");
    }
    let out = Path::new(&args[1]);
    fs::create_dir_all(out).expect("mkdir out");

    let params = test_params();

    // Row shape [status, bc[1..32]] mirrors the production T1 PerListStatus encoder.
    let num_entries = params.ring_dim;
    let mut db = vec![0u8; num_entries * ENTRY_BYTES];
    for idx in 0..(num_entries as u32) {
        let bc = bc_for(idx);
        let row_start = (idx as usize) * ENTRY_BYTES;
        let row_end = row_start + ENTRY_BYTES;
        let row = &mut db[row_start..row_end];
        row[0] = (idx % 4) as u8;
        row[1..32].copy_from_slice(&bc[1..32]);
    }

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &db, ENTRY_BYTES, &mut sampler).expect("setup");

    let inspire_params_bin = bincode::serialize(&params).expect("serialize params");
    let crs_bin = bincode::serialize(&crs).expect("serialize crs");
    let shard_config_bin = bincode::serialize(&encoded_db.config).expect("serialize shard");
    let sk_bin = bincode::serialize(&sk).expect("serialize sk");

    // WasmInstanceParamsBundle fields are crate-private; hand-build the bincode shape.
    let params_bundle_bin =
        bincode_three_byte_vecs(&inspire_params_bin, &shard_config_bin, &sk_bin);

    fs::write(out.join("inspire_params.bin"), &inspire_params_bin).expect("write params");
    fs::write(out.join("crs.bin"), &crs_bin).expect("write crs");
    fs::write(out.join("shard_config.bin"), &shard_config_bin).expect("write shard");
    fs::write(out.join("params_bundle.bin"), &params_bundle_bin).expect("write bundle");

    let list_key: [u8; 32] = [0x42u8; 32];
    fs::write(out.join("list_key.bin"), list_key).expect("write list_key");

    let mut sampler_session = GaussianSampler::new(params.sigma);
    let session = raven_inspire::ClientSession::new(crs.clone(), sk.clone(), &mut sampler_session)
        .expect("session");
    let cache = raven_inspire::ServerInspiringCache::new(&crs, &encoded_db).expect("cache");
    let store = raven_inspire::ServerSessionStore::new();

    let mut bcs_hex = Vec::new();
    for idx in 0..NUM_FIXTURE_INDICES {
        let bc = bc_for(idx);
        bcs_hex.push(hex_encode(&bc));
        fs::write(out.join(format!("bc_for_idx_{idx}.bin")), bc).expect("write bc");

        let (state, query) =
            build_seeded_query_rust(&session, &params, &encoded_db.config, u64::from(idx))
                .expect("build query");
        let resp = raven_inspire::respond_seeded_inspiring_cached_with_session(
            &crs,
            &encoded_db,
            &query,
            &cache,
            Some(&store),
        )
        .expect("respond");

        let plain = extract_response_rust(&crs, &state, &resp, ENTRY_BYTES).expect("extract");
        assert_eq!(
            plain[0],
            (idx % 4) as u8,
            "status byte mismatch at idx {idx}"
        );

        let resp_bin = bincode::serialize(&resp).expect("serialize response");
        fs::write(out.join(format!("response_for_idx_{idx}.bin")), resp_bin).expect("write resp");
    }

    let meta = FixtureMeta {
        entry_size: ENTRY_BYTES,
        list_key_hex: hex_encode(&list_key),
        target_indices: (0..NUM_FIXTURE_INDICES).collect(),
        bcs_hex,
    };
    let meta_json = serde_json::to_vec_pretty(&meta).expect("serialize meta");
    fs::write(out.join("fixture.json"), meta_json).expect("write meta");

    drop(_unused_witness((crs, encoded_db)));
    let _ = RlweSecretKey::clone(&sk);
    println!("OK: fixture written to {}", out.display());
}

fn _unused_witness<T>(t: T) -> T {
    t
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Bincode matching crate-private `WasmInstanceParamsBundle`: 3 `Vec<u8>` fields, u64 LE length prefix, no headers.
fn bincode_three_byte_vecs(a: &[u8], b: &[u8], c: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + a.len() + b.len() + c.len());
    out.extend_from_slice(
        &u64::try_from(a.len())
            .expect("a.len fits u64")
            .to_le_bytes(),
    );
    out.extend_from_slice(a);
    out.extend_from_slice(
        &u64::try_from(b.len())
            .expect("b.len fits u64")
            .to_le_bytes(),
    );
    out.extend_from_slice(b);
    out.extend_from_slice(
        &u64::try_from(c.len())
            .expect("c.len fits u64")
            .to_le_bytes(),
    );
    out.extend_from_slice(c);
    out
}
