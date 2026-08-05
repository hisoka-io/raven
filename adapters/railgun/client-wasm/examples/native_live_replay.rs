//! Replay a PIR query against a running operator server and print the recovered row.
//!
//! Transport is the caller's, so the example needs no HTTP dependency:
//!
//! ```text
//! curl -sH "Authorization: Bearer $TOKEN" $ENDPOINT/v1/instance/$ID/params -o params.bin
//! cargo run --release --example native_live_replay \
//!   --manifest-path adapters/railgun/client-wasm/Cargo.toml \
//!   -- mkquery params.bin <flat-index> <work-dir>
//! curl -sH "Authorization: Bearer $TOKEN" -H 'content-type: application/octet-stream' \
//!   --data-binary @<work-dir>/query.wire $ENDPOINT/v1/instance/$ID/query -o response.wire
//! cargo run --release --example native_live_replay \
//!   --manifest-path adapters/railgun/client-wasm/Cargo.toml \
//!   -- extract <work-dir> response.wire
//! ```
//!
//! `mkquery` pins the RLWE key seed and the Gaussian noise seed, so the same
//! `(params.bin, flat-index)` always yields the same `query.wire`. Two servers
//! holding the same snapshot are therefore comparable byte for byte on the response.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::indexing_slicing
)]

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, ShardConfig};
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::{
    extract_inspiring, ClientSession, ClientState, PackingMode, SeededClientQuery, ServerCrs,
    ServerResponse, SessionResidue,
};

const WIRE_SCHEMA_PREFIX_LEN: usize = 2;
const WIRE_SCHEMA_VERSION: u16 = 1;
const KEY_SEED: [u8; 32] = *b"raven-native-live-replay-key-001";
const NOISE_SEED: [u8; 32] = *b"raven-native-live-replay-noise01";

#[derive(serde::Serialize, serde::Deserialize)]
struct InstanceParamsWire {
    wire_schema_version: u16,
    crs_bincode: Vec<u8>,
    shard_config_bincode: Vec<u8>,
    inspire_params_bincode: Vec<u8>,
    entry_size: usize,
    variant: String,
    epoch: u64,
}

fn strip_envelope(bytes: &[u8], what: &str) -> Vec<u8> {
    assert!(
        bytes.len() >= WIRE_SCHEMA_PREFIX_LEN,
        "{what}: {} bytes is shorter than the 2-byte schema prefix",
        bytes.len()
    );
    let version = u16::from_be_bytes([bytes[0], bytes[1]]);
    assert_eq!(
        version, WIRE_SCHEMA_VERSION,
        "{what}: wire schema {version} != expected {WIRE_SCHEMA_VERSION}"
    );
    bytes[WIRE_SCHEMA_PREFIX_LEN..].to_vec()
}

fn add_envelope(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(WIRE_SCHEMA_PREFIX_LEN + body.len());
    out.extend_from_slice(&WIRE_SCHEMA_VERSION.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn read_params(path: &Path) -> InstanceParamsWire {
    let raw = fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    bincode::deserialize(&strip_envelope(&raw, "params")).expect("decode InstanceParams")
}

fn session_from(params: &InstanceParamsWire) -> (ClientSession, InspireParams, ShardConfig) {
    let inspire_params: InspireParams =
        bincode::deserialize(&params.inspire_params_bincode).expect("decode InspireParams");
    let shard_config: ShardConfig =
        bincode::deserialize(&params.shard_config_bincode).expect("decode ShardConfig");
    let crs = ServerCrs::from_versioned_bytes(&params.crs_bincode).expect("decode wire CRS");
    let mut key_sampler = GaussianSampler::from_seed(inspire_params.sigma, KEY_SEED);
    let secret_key = RlweSecretKey::generate(&inspire_params, &mut key_sampler);
    let mut session_sampler = GaussianSampler::from_seed(inspire_params.sigma, KEY_SEED);
    let session =
        ClientSession::new(crs, secret_key, &mut session_sampler).expect("build ClientSession");
    (session, inspire_params, shard_config)
}

fn mkquery(params_path: &Path, target_idx: u64, work_dir: &Path) {
    let params = read_params(params_path);
    fs::create_dir_all(work_dir).expect("create work dir");
    let (session, inspire_params, shard_config) = session_from(&params);

    let mut sampler = GaussianSampler::from_seed(inspire_params.sigma, NOISE_SEED);
    let (client_state, mut query) = session
        .query_seeded(target_idx, &shard_config, &mut sampler)
        .expect("query_seeded");
    query.packing_mode = PackingMode::Inspiring;

    let query_body = bincode::serialize(&query).expect("encode SeededClientQuery");
    fs::write(work_dir.join("query.wire"), add_envelope(&query_body)).expect("write query.wire");
    fs::write(
        work_dir.join("client_state.bin"),
        bincode::serialize(&client_state).expect("encode ClientState"),
    )
    .expect("write client_state.bin");
    fs::write(
        work_dir.join("session.bin"),
        bincode::serialize(&session.to_residue()).expect("encode SessionResidue"),
    )
    .expect("write session.bin");
    if work_dir.join("params.bin") != *params_path {
        fs::copy(params_path, work_dir.join("params.bin")).expect("stage params.bin");
    }

    println!(
        "query_wire_bytes={} entry_size={} epoch={} variant={}",
        query_body.len() + WIRE_SCHEMA_PREFIX_LEN,
        params.entry_size,
        params.epoch,
        params.variant
    );
    let _: SeededClientQuery = bincode::deserialize(&query_body).expect("query round-trips");
}

fn extract(work_dir: &Path, response_path: &Path) {
    let params = read_params(&work_dir.join("params.bin"));
    let residue: SessionResidue =
        bincode::deserialize(&fs::read(work_dir.join("session.bin")).expect("read session.bin"))
            .expect("decode SessionResidue");
    let session = ClientSession::from_residue(residue).expect("rehydrate session");

    let mut client_state: ClientState = bincode::deserialize(
        &fs::read(work_dir.join("client_state.bin")).expect("read client_state.bin"),
    )
    .expect("decode ClientState");
    // `rlwe_secret_key` is `#[serde(skip)]`; extract_inspiring reads it.
    client_state.rlwe_secret_key = session.rlwe_secret_key().clone();

    let raw =
        fs::read(response_path).unwrap_or_else(|e| panic!("read {}: {e}", response_path.display()));
    let response: ServerResponse =
        bincode::deserialize(&strip_envelope(&raw, "response")).expect("decode ServerResponse");
    let crs = ServerCrs::from_versioned_bytes(&params.crs_bincode).expect("decode wire CRS");

    let row = extract_response(&crs, &client_state, &response, params.entry_size);
    println!("row_bytes={}", row.len());
    println!("leaf_hex={}", hex_lower(&row[..row.len().min(32)]));
    println!("row_sha256_prefix={}", hex_lower(&row[..row.len().min(64)]));
}

fn extract_response(
    crs: &ServerCrs,
    client_state: &ClientState,
    response: &ServerResponse,
    entry_size: usize,
) -> Vec<u8> {
    extract_inspiring(crs, client_state, response, entry_size).expect("extract_inspiring")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("mkquery") => {
            let usage = "usage: mkquery <params.bin> <flat-index> <work-dir>";
            let params = PathBuf::from(args.get(2).expect(usage));
            let idx: u64 = args.get(3).expect(usage).parse().expect("index parses");
            let dir = PathBuf::from(args.get(4).expect(usage));
            mkquery(&params, idx, &dir);
        }
        Some("extract") => {
            let usage = "usage: extract <work-dir> <response.wire>";
            let dir = PathBuf::from(args.get(2).expect(usage));
            let resp = PathBuf::from(args.get(3).expect(usage));
            extract(&dir, &resp);
        }
        _ => panic!("usage: native_live_replay mkquery|extract ..."),
    }
}
