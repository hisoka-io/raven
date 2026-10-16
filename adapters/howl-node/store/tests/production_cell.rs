//! The 246-byte Howl record at production shape: one shard of this store, 2,048 rows of
//! 256 bytes, encoded and queried through InsPIRe at ring dimension 2,048 with the 36-bit
//! response, and every retrieved cell decoded by the record codec.
//!
//! 246 is not a width the engine accepts, which is why the record travels in 256.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

mod support;

use howl_record::{decode, CELL_BYTES, RECORD_BYTES};
use howl_store::{NoteStore, ROWS_PER_SHARD};
use raven_inspire::math::GaussianSampler;
use raven_inspire::pir::mod_switch::{
    extract_inspiring_mod_switched, mod_switch_response_checked, MOD_SWITCH_TARGET_36BIT,
};
use raven_inspire::{query_seeded, respond_seeded_inspiring, setup, InspireParams};
use support::{batch, leaf, CHAIN_ID, POOL};

/// A full first shard and a partly filled second one.
const LEAVES: usize = ROWS_PER_SHARD + 300;

/// First and last row of the sealed shard, interior rows, the first and last filled row of
/// the newest shard, and a row past its last leaf.
const TARGETS: [u64; 8] = [1, 2, 1_337, 2_047, 2_048, 2_049, 2_347, 2_348];

#[test]
fn a_howl_record_survives_the_production_cell() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = NoteStore::open(dir.path(), CHAIN_ID, POOL).expect("open");
    store.append(&batch(0, LEAVES, 1)).expect("append");
    assert_eq!(store.shard_count(), 2);
    let table: Vec<u8> = (0..2)
        .flat_map(|index| store.shard(index).expect("shard").cells)
        .collect();

    let params = InspireParams::secure_128_d2048();
    assert_eq!(
        params.ring_dim, ROWS_PER_SHARD,
        "a shard is one ring of rows"
    );
    let mut sampler = GaussianSampler::with_seed(params.sigma, 0x0b1e);
    let (crs, encoded, secret) =
        setup(&params, &table, CELL_BYTES, &mut sampler).expect("256-byte cells encode");
    assert_eq!(encoded.config.entry_size_bytes, CELL_BYTES);
    assert_eq!(encoded.config.entries_per_shard(), ROWS_PER_SHARD as u64);

    let mut retrieved = Vec::new();
    for target in TARGETS {
        let (state, query) =
            query_seeded(&crs, target, &encoded.config, &secret, &mut sampler).expect("query");
        let response = respond_seeded_inspiring(&crs, &encoded, &query).expect("respond");
        let wire = mod_switch_response_checked(&crs.params, &response, MOD_SWITCH_TARGET_36BIT)
            .expect("36-bit response");
        let cell =
            extract_inspiring_mod_switched(&crs, &state, &wire, CELL_BYTES).expect("extract");
        assert_eq!(cell.len(), CELL_BYTES);

        if target < LEAVES as u64 {
            assert_eq!(cell, leaf(target).cell, "row {target}");
            let record = decode(&cell).expect("the retrieved cell decodes");
            assert_eq!(u64::from(record.leaf_index), target);
            assert!(cell[RECORD_BYTES..].iter().all(|byte| *byte == 0));
        } else {
            assert!(cell.iter().all(|byte| *byte == 0), "row {target} is unused");
        }
        retrieved.push(cell);
    }
    // A cell that answered every index with one row would pass each check above but this.
    for (i, a) in retrieved.iter().enumerate() {
        for b in &retrieved[i + 1..] {
            assert_ne!(a, b, "two targets returned the same cell");
        }
    }
}

#[test]
fn the_bare_record_width_is_not_a_cell() {
    let params = InspireParams::secure_128_d2048();
    let mut sampler = GaussianSampler::with_seed(params.sigma, 1);
    let rows = vec![0u8; ROWS_PER_SHARD * RECORD_BYTES];
    assert!(setup(&params, &rows, RECORD_BYTES, &mut sampler).is_err());
}
