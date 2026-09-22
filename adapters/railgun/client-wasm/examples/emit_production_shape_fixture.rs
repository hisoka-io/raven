//! Emit the multi-shard fixture at the geometry the deployment serves.
//!
//! `emit_test_fixture` runs at `ring_dim 256`, a 32 B record and one shard; production is
//! `InspireParams::secure_128_d2048` with a 512 B path-10 record and `entries_per_shard
//! = 2048` (`engine/src/orchestrator.rs:174`, `:175`). 512 B is illegal below ring 2048:
//! the InspiRING packing width is `ceil(512/2) = 256` and legal widths are the powers of
//! two up to `ring_dim/2` (`inspiring/inspiring2.rs:132-137`).
//!
//! `crs.bin` is the CRS `GET /v1/instance/{id}/params` ships, not the server's own: the
//! client decodes it and both the session and the extraction run off it here, so the
//! fixture tests the bytes a wallet actually holds.
//!
//! Run: `cargo run --release --example emit_production_shape_fixture --manifest-path
//! adapters/railgun/client-wasm/Cargo.toml -- <out-dir>`

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::cast_possible_truncation,
    clippy::manual_assert,
    clippy::too_many_lines
)]

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::InspireParams;
use raven_inspire::pir::mod_switch::{mod_switch_response_checked, MOD_SWITCH_TARGET_36BIT};
use raven_inspire::setup as inspire_setup;
use raven_inspire::ServerCrs;
use raven_inspire_client_wasm::{build_seeded_query_rust, extract_response_rust};

/// `PATH10_RECORD_BYTES` (`engine/src/pir_table/list.rs:20`).
const ENTRY_BYTES: usize = 512;
/// `PATH10_LEVELS` (`engine/src/pir_table/list.rs:22`).
const ROW_LEVELS: usize = 11;
const NODES_OFFSET: usize = 38;
const NODE_BYTES: usize = 32;
/// `PATH10_MAGIC` (`engine/src/pir_table/list.rs:24`).
const MAGIC: [u8; 4] = *b"RVP2";
const NUM_SHARDS: u64 = 2;

/// Last row of shard 0 and first row of shard 1, plus both outer ends. An off-by-one at
/// 2047/2048 crosses a shard boundary, which is the addressing this fixture exists to pin.
fn target_indices(entries_per_shard: u64) -> Vec<u64> {
    vec![
        0,
        entries_per_shard - 1,
        entries_per_shard,
        entries_per_shard * NUM_SHARDS - 1,
    ]
}

/// Self-identifying leaf: every row's bytes are a function of its own global index, so a
/// substituted row cannot compare equal to the one asked for.
fn bc_for(global_idx: u64) -> [u8; 32] {
    let mut bc = [0u8; 32];
    bc[0] = 0xBC;
    bc[24..32].copy_from_slice(&global_idx.to_le_bytes());
    bc
}

fn sibling_for(global_idx: u64, level: usize) -> [u8; NODE_BYTES] {
    let mut node = [0u8; NODE_BYTES];
    node[0] = 0xAB;
    node[1] = level as u8;
    node[24..32].copy_from_slice(&global_idx.to_le_bytes());
    node
}

/// One row exactly as `PerListPath10Encoder::materialize_shard` lays it out
/// (`engine/src/pir_table/list.rs:246-296`): BC, status, event type, magic, levels 0..10,
/// zero tail. Levels 11..15 are the cleartext addendum and never enter the PIR record.
fn path10_row(global_idx: u64) -> Vec<u8> {
    let mut row = vec![0u8; ENTRY_BYTES];
    row[..32].copy_from_slice(&bc_for(global_idx));
    row[32] = (global_idx % 4) as u8;
    row[33] = (global_idx % 3) as u8;
    row[34..38].copy_from_slice(&MAGIC);
    for level in 0..ROW_LEVELS {
        let start = NODES_OFFSET + level * NODE_BYTES;
        row[start..start + NODE_BYTES].copy_from_slice(&sibling_for(global_idx, level));
    }
    row
}

#[derive(serde::Serialize)]
struct FixtureMeta {
    entry_size: usize,
    ring_dim: usize,
    entries_per_shard: u64,
    num_shards: u64,
    total_entries: u64,
    target_indices: Vec<u64>,
    shard_ids: Vec<u32>,
    local_indices: Vec<u64>,
    bcs_hex: Vec<String>,
    response_modulus: u64,
}

#[derive(serde::Serialize)]
struct ManifestFile {
    name: String,
    bytes: u64,
    sha256: String,
}

#[derive(serde::Serialize)]
struct FixtureManifest {
    generator: &'static str,
    generator_git_commit: String,
    generated_unix_ms: u128,
    inspire_params: InspireParams,
    entry_size: usize,
    num_indices: usize,
    files: Vec<ManifestFile>,
}

fn git_commit() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map_or_else(
            || "unknown".to_string(),
            |o| String::from_utf8_lossy(&o.stdout).trim().to_string(),
        )
}

fn sha256_file(path: &Path) -> String {
    let out = std::process::Command::new("sha256sum")
        .arg(path)
        .output()
        .expect("run sha256sum (coreutils)");
    assert!(
        out.status.success(),
        "sha256sum failed for {}",
        path.display()
    );
    let text = String::from_utf8(out.stdout).expect("sha256sum utf-8");
    text.split_whitespace()
        .next()
        .expect("sha256sum output shape")
        .to_string()
}

/// The CRS `/v1/instance/{id}/params` ships, byte-for-byte: a duplicate of the private
/// `crs_wire_bytes` in `adapters/railgun/http/src/admin.rs:142-158`, which a wasm client
/// crate cannot reach without depending on the axum server. Field-by-field for the same
/// reason the original is: a CRS layout change must fail to compile here rather than
/// silently re-inflate the fixture back past a megabyte.
fn crs_wire_bytes(crs: &ServerCrs) -> Vec<u8> {
    ServerCrs {
        params: crs.params.clone(),
        galois_keys: Vec::new(),
        rgsw_gadget: crs.rgsw_gadget.clone(),
        inspiring_pack_params: None,
        inspiring_packing_key: None,
        inspiring_w_seed: crs.inspiring_w_seed,
        inspiring_v_seed: crs.inspiring_v_seed,
        inspiring_num_columns: crs.inspiring_num_columns,
    }
    .to_versioned_bytes()
    .expect("versioned wire crs")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        panic!("usage: emit_production_shape_fixture <out-dir>");
    }
    let out = Path::new(&args[1]);
    fs::create_dir_all(out).expect("mkdir out");

    let params = InspireParams::secure_128_d2048();
    let entries_per_shard = params.ring_dim as u64;
    let total_entries = entries_per_shard * NUM_SHARDS;

    let mut db = vec![0u8; (total_entries as usize) * ENTRY_BYTES];
    for global_idx in 0..total_entries {
        let start = (global_idx as usize) * ENTRY_BYTES;
        db[start..start + ENTRY_BYTES].copy_from_slice(&path10_row(global_idx));
    }

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, sk) =
        inspire_setup(&params, &db, ENTRY_BYTES, &mut sampler).expect("setup");
    assert_eq!(
        encoded_db.config.num_shards(),
        NUM_SHARDS,
        "the fixture must span more than one shard or it pins nothing about addressing"
    );

    let inspire_params_bin = bincode::serialize(&params).expect("serialize params");
    let crs_bin = crs_wire_bytes(&crs);
    let wire_crs = ServerCrs::from_versioned_bytes(&crs_bin).expect("decode wire crs");
    assert!(
        wire_crs.galois_keys.is_empty(),
        "the shipped CRS must carry no galois keys"
    );
    assert!(
        crs.to_versioned_bytes().expect("versioned crs").len() > 1_000_000,
        "the server's own CRS is over a megabyte at d=2048; if it is not, this fixture is \
         no longer proving that the wire CRS is the small one"
    );
    assert!(
        crs_bin.len() < 4_096,
        "wire CRS must stay under 4 KiB (got {}), as crs_wire_omits_galois_keys.rs:122 pins",
        crs_bin.len()
    );
    let shard_config_bin = bincode::serialize(&encoded_db.config).expect("serialize shard");
    let sk_bin = bincode::serialize(&sk).expect("serialize sk");
    let params_bundle_bin =
        bincode_three_byte_vecs(&inspire_params_bin, &shard_config_bin, &sk_bin);

    fs::write(out.join("inspire_params.bin"), &inspire_params_bin).expect("write params");
    fs::write(out.join("crs.bin"), &crs_bin).expect("write crs");
    fs::write(out.join("shard_config.bin"), &shard_config_bin).expect("write shard");
    fs::write(out.join("params_bundle.bin"), &params_bundle_bin).expect("write bundle");

    let mut sampler_session = GaussianSampler::new(params.sigma);
    let session =
        raven_inspire::ClientSession::new(wire_crs.clone(), sk.clone(), &mut sampler_session)
            .expect("session");
    let cache = raven_inspire::ServerInspiringCache::new(&crs, &encoded_db).expect("cache");
    let store = raven_inspire::ServerSessionStore::new();

    let indices = target_indices(entries_per_shard);
    let mut bcs_hex = Vec::new();
    let mut shard_ids = Vec::new();
    let mut local_indices = Vec::new();

    for &global_idx in &indices {
        let (shard_id, local_index) = encoded_db
            .config
            .try_index_to_shard(global_idx)
            .expect("index within the configured geometry");
        shard_ids.push(shard_id);
        local_indices.push(local_index);
        bcs_hex.push(hex_encode(&bc_for(global_idx)));

        let (state, query) =
            build_seeded_query_rust(&session, &params, &encoded_db.config, global_idx)
                .expect("build query");
        let response = raven_inspire::respond_seeded_inspiring_cached_with_session(
            &crs,
            &encoded_db,
            &query,
            &cache,
            Some(&store),
        )
        .expect("respond");
        // `RavenInspireScheme::respond` switches every response before it reaches the wire
        // (`engine/src/inspire.rs:100`, `WIRE_RESPONSE_MODULUS = MOD_SWITCH_TARGET_36BIT`).
        let response = mod_switch_response_checked(&crs.params, &response, MOD_SWITCH_TARGET_36BIT)
            .expect("mod-switch response");

        let response_bin = response.to_binary().expect("serialize response");
        let response = raven_inspire::ServerResponse::from_binary(&response_bin)
            .expect("deserialize response wire");

        let plain =
            extract_response_rust(&wire_crs, &state, &response, ENTRY_BYTES).expect("extract");
        assert_eq!(
            plain,
            path10_row(global_idx),
            "decoded row disagrees with the path-10 layout at global index {global_idx}"
        );

        let state_bin = bincode::serialize(&state).expect("serialize state");
        fs::write(
            out.join(format!("client_state_for_idx_{global_idx}.bin")),
            state_bin,
        )
        .expect("write state");
        fs::write(
            out.join(format!("expected_plain_for_idx_{global_idx}.bin")),
            &plain,
        )
        .expect("write plain");
        fs::write(
            out.join(format!("response_for_idx_{global_idx}.bin")),
            response_bin,
        )
        .expect("write resp");
    }

    let meta = FixtureMeta {
        entry_size: ENTRY_BYTES,
        ring_dim: params.ring_dim,
        entries_per_shard,
        num_shards: NUM_SHARDS,
        total_entries,
        target_indices: indices.clone(),
        shard_ids,
        local_indices,
        bcs_hex,
        response_modulus: MOD_SWITCH_TARGET_36BIT,
    };
    fs::write(
        out.join("fixture.json"),
        serde_json::to_vec_pretty(&meta).expect("serialize meta"),
    )
    .expect("write meta");

    let mut file_names: Vec<String> = vec![
        "inspire_params.bin".into(),
        "crs.bin".into(),
        "shard_config.bin".into(),
        "params_bundle.bin".into(),
        "fixture.json".into(),
    ];
    for global_idx in &indices {
        file_names.push(format!("client_state_for_idx_{global_idx}.bin"));
        file_names.push(format!("expected_plain_for_idx_{global_idx}.bin"));
        file_names.push(format!("response_for_idx_{global_idx}.bin"));
    }
    let files = file_names
        .into_iter()
        .map(|name| {
            let path = out.join(&name);
            let bytes = fs::metadata(&path).expect("stat emitted file").len();
            let sha256 = sha256_file(&path);
            ManifestFile {
                name,
                bytes,
                sha256,
            }
        })
        .collect();
    let manifest = FixtureManifest {
        generator: "emit_production_shape_fixture",
        generator_git_commit: git_commit(),
        generated_unix_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_millis(),
        inspire_params: params.clone(),
        entry_size: ENTRY_BYTES,
        num_indices: indices.len(),
        files,
    };
    fs::write(
        out.join("fixture_manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");

    println!("OK: production-shape fixture written to {}", out.display());
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").expect("writing to a String cannot fail");
    }
    s
}

/// Bincode shape of the crate-private `WasmInstanceParamsBundle`: 3 `Vec<u8>`, u64 LE
/// length prefixes, no header.
fn bincode_three_byte_vecs(a: &[u8], b: &[u8], c: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + a.len() + b.len() + c.len());
    for part in [a, b, c] {
        out.extend_from_slice(
            &u64::try_from(part.len())
                .expect("len fits u64")
                .to_le_bytes(),
        );
        out.extend_from_slice(part);
    }
    out
}
