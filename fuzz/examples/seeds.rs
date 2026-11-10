//! Writes one honest body per target into `<corpus>/<target>/`, built by the same public encoders a
//! wallet uses, so a run starts past the framing and into the validation behind it.
//!
//!   cargo run --release --manifest-path fuzz/Cargo.toml --example seeds -- fuzz/corpus

use std::fs;
use std::path::{Path, PathBuf};

use howl_wire::{
    KeySource, P16Batch, P16Query, RequestPrefix, CELL_BYTES, P16_KEY_BYTES, P16_QUERY_BYTES,
    PARAM_SET_D2048_CELL256, ROWS_PER_SHARD,
};
use raven_fuzz::{HOWL_PIRS, RAILGUN_ENTRY_BYTES};
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, ShardConfig};
use raven_inspire::{setup, ClientSession, ServerCrs};
use raven_railgun_http::versioned::{wire_schema_for, write_versioned_as};
use raven_railgun_http::InstanceParams;

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

/// Writes a seed after proving it passes its target's whole decode path: a seed the decoder
/// refuses would start the run at the framing again.
fn put(corpus: &Path, target: &str, name: &str, bytes: &[u8]) -> Fallible<()> {
    let path = match target {
        "railgun_session_body" => raven_fuzz::railgun_session_body,
        "railgun_batch_body" => raven_fuzz::railgun_batch_body,
        "railgun_params_blob" => raven_fuzz::railgun_params_blob,
        "inspire_crs_blob" => raven_fuzz::inspire_crs_blob,
        "howl_session_body" => raven_fuzz::howl_session_body,
        "howl_notes_body" => raven_fuzz::howl_notes_body,
        "howl_answer" => raven_fuzz::howl_answer,
        other => return Err(format!("no target {other}").into()),
    };
    path(bytes).map_err(|e| format!("seed {target}/{name} is refused at {e}"))?;
    let dir = corpus.join(target);
    fs::create_dir_all(&dir)?;
    fs::write(dir.join(name), bytes)?;
    println!("{target}/{name}: {} B", bytes.len());
    Ok(())
}

fn railgun(corpus: &Path, params: InspireParams, tag: &str) -> Fallible<()> {
    let schema = wire_schema_for(&params);
    // two rows' worth of cells: enough for a CRS and a shard, nothing is answered
    let database = vec![0u8; params.ring_dim * RAILGUN_ENTRY_BYTES];
    let mut sampler = GaussianSampler::from_os_entropy(params.sigma)?;
    let (crs, encoded, _) = setup(&params, &database, RAILGUN_ENTRY_BYTES, &mut sampler)?;
    // the CRS as GET .../params serves it: no Galois keys, no server-side packing state
    let crs_bytes = ServerCrs {
        galois_keys: Vec::new(),
        inspiring_pack_params: None,
        inspiring_packing_key: None,
        ..crs.clone()
    }
    .to_versioned_bytes()?;
    put(corpus, "inspire_crs_blob", tag, &crs_bytes)?;
    let instance = InstanceParams {
        wire_schema_version: schema,
        crs_bincode: crs_bytes,
        shard_config_bincode: bincode::serialize(&encoded.config)?,
        inspire_params_bincode: bincode::serialize(&params)?,
        entry_size: RAILGUN_ENTRY_BYTES,
        variant: "inspiring".to_owned(),
        epoch: 1,
    };
    put(
        corpus,
        "railgun_params_blob",
        tag,
        &write_versioned_as(&instance, schema)?,
    )?;
    let session = ClientSession::with_fresh_secret(crs)?;
    let keys = session
        .packing_keys()
        .ok_or("the CRS packs, so the session has keys")?;
    put(
        corpus,
        "railgun_session_body",
        tag,
        &write_versioned_as(keys, schema)?,
    )?;
    let (_, one) = session.query_seeded_fresh(3, &encoded.config)?;
    let (_, two) = session.query_seeded_fresh(5, &encoded.config)?;
    put(
        corpus,
        "railgun_batch_body",
        &format!("{tag}-one"),
        &write_versioned_as(&one, schema)?,
    )?;
    put(
        corpus,
        "railgun_batch_body",
        &format!("{tag}-two"),
        &write_versioned_as(&vec![one, two], schema)?,
    )?;
    Ok(())
}

fn howl(corpus: &Path) -> Fallible<()> {
    for pir in HOWL_PIRS.iter() {
        let set = pir.param_set();
        let prefix = RequestPrefix { param_set: set }.encode();
        let body = |payload: &[u8]| [prefix.as_slice(), payload].concat();
        let (key, batch) = if set == PARAM_SET_D2048_CELL256 {
            let session = ClientSession::with_fresh_secret(ServerCrs::from_versioned_bytes(
                pir.crs_bytes(),
            )?)?;
            let keys = session
                .packing_keys()
                .ok_or("set 1 packs, so the session has keys")?;
            // the node's own shard geometry for set 1
            let shards = ShardConfig::for_ring_dim(2048, CELL_BYTES, ROWS_PER_SHARD)?;
            let (_, batch) = session.query_batch_fresh(&[0, 1], &shards)?;
            (bincode::serialize(keys)?, bincode::serialize(&batch)?)
        } else {
            // key-mask version (the node's set-2 crs), mask seed, then all-zero key rows
            let mut key = vec![0; P16_KEY_BYTES];
            key[..2].copy_from_slice(pir.crs_bytes());
            let query = || P16Query {
                shard: 0,
                query: vec![0; P16_QUERY_BYTES],
            };
            let batch = P16Batch {
                key: KeySource::Inline(key.clone()),
                queries: vec![query(), query()],
            };
            put(
                corpus,
                "howl_notes_body",
                &format!("set{set}-session"),
                &body(
                    &P16Batch {
                        key: KeySource::Session(1),
                        queries: vec![query()],
                    }
                    .encode(),
                ),
            )?;
            (key, batch.encode())
        };
        put(
            corpus,
            "howl_session_body",
            &format!("set{set}"),
            &body(&key),
        )?;
        put(
            corpus,
            "howl_notes_body",
            &format!("set{set}"),
            &body(&batch),
        )?;
    }
    Ok(())
}

fn main() -> Fallible<()> {
    let corpus = PathBuf::from(std::env::args().nth(1).ok_or("usage: seeds <corpus dir>")?);
    railgun(&corpus, InspireParams::d2048(), "d2048")?;
    railgun(
        &corpus,
        InspireParams::d2048_approximate_gadget(),
        "d2048-approximate-gadget",
    )?;
    howl(&corpus)?;
    // the answers a wallet decodes: the SDK's recorded node responses
    let fixtures =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../adapters/howl-node/sdk/tests/fixtures");
    for entry in fs::read_dir(&fixtures)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "bin") {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or("a fixture name")?;
            put(&corpus, "howl_answer", name, &fs::read(&path)?)?;
        }
    }
    Ok(())
}
