//! Production-cell row identity for `re_encode_shard`, and the loud-fail guard for a
//! buffer wider than one shard.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::EncodedDatabase;
use raven_railgun_engine::inspire::{re_encode_shard, setup_state, InspireServerState};

const ENTRY_BYTES: usize = 32;
const CELL_ROWS: usize = 65_536;

fn row_bytes(row: usize) -> [u8; ENTRY_BYTES] {
    let tag = u32::try_from(row).expect("row fits u32").to_le_bytes();
    let mut out = [0u8; ENTRY_BYTES];
    for (i, b) in out.iter_mut().enumerate() {
        *b = tag[i % 4];
    }
    out
}

fn production_cell() -> (InspireParams, InspireServerState, Vec<u8>) {
    let params = InspireParams::secure_128_d2048();
    let db: Vec<u8> = (0..CELL_ROWS).flat_map(row_bytes).collect();
    let (state, _sk) = setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking)
        .expect("setup_state at production cell");
    (params, state, db)
}

fn shard_coeffs(db: &EncodedDatabase, shard_id: u32) -> Vec<Vec<u64>> {
    db.shards
        .iter()
        .find(|s| s.id == shard_id)
        .unwrap_or_else(|| panic!("shard {shard_id} present"))
        .polynomials
        .iter()
        .map(|p| p.coeffs().to_vec())
        .collect()
}

#[test]
fn production_cell_shards_at_ring_dim_not_at_total_rows() {
    let (params, state, _db) = production_cell();
    let cfg = state.shard_config();
    assert_eq!(
        cfg.entries_per_shard(),
        params.ring_dim as u64,
        "a shard holds exactly ring_dim rows"
    );
    assert_eq!(
        state.encoded_db.shards.len(),
        CELL_ROWS / params.ring_dim,
        "{CELL_ROWS} rows at ring_dim {} must allocate {} shards",
        params.ring_dim,
        CELL_ROWS / params.ring_dim
    );
}

#[test]
fn slot_zero_keeps_first_window_row_identity() {
    let (params, mut state, db) = production_cell();
    let rows_per_shard = params.ring_dim;
    let first_window = shard_coeffs(&state.encoded_db, 0);
    let last_shard_id =
        u32::try_from(state.encoded_db.shards.len() - 1).expect("shard id fits u32");
    let last_window = shard_coeffs(&state.encoded_db, last_shard_id);
    assert_ne!(
        first_window, last_window,
        "the identity assertions below are only discriminating if the windows differ"
    );

    let one_shard = db[..rows_per_shard * ENTRY_BYTES].to_vec();
    re_encode_shard(
        Arc::make_mut(&mut state.encoded_db),
        &params,
        0,
        &one_shard,
        ENTRY_BYTES,
    )
    .expect("re-encoding shard 0 from exactly rows_per_shard rows");

    assert_eq!(
        shard_coeffs(&state.encoded_db, 0),
        first_window,
        "slot 0 must hold rows 0..{rows_per_shard}"
    );
}

#[test]
fn over_wide_buffer_is_rejected_with_actionable_error() {
    let (params, mut state, db) = production_cell();
    let rows_per_shard = params.ring_dim;
    let rebuilt_shards = CELL_ROWS / rows_per_shard;
    let last_shard_id =
        u32::try_from(state.encoded_db.shards.len() - 1).expect("shard id fits u32");
    let first_window = shard_coeffs(&state.encoded_db, 0);
    let last_window = shard_coeffs(&state.encoded_db, last_shard_id);

    let outcome = re_encode_shard(
        Arc::make_mut(&mut state.encoded_db),
        &params,
        0,
        &db,
        ENTRY_BYTES,
    );

    let Err(err) = outcome else {
        let installed = shard_coeffs(&state.encoded_db, 0);
        panic!(
            "SILENT WRONG: re_encode_shard accepted a {CELL_ROWS}-row buffer for a \
             {rows_per_shard}-row shard and returned Ok. slot 0 == first window \
             (rows 0..{rows_per_shard}): {}; slot 0 == LAST window (rows {}..{CELL_ROWS}): {}",
            installed == first_window,
            CELL_ROWS - rows_per_shard,
            installed == last_window,
        );
    };

    let msg = format!("{err}");
    for needle in [
        "re_encode_shard",
        "shard 0",
        &CELL_ROWS.to_string(),
        &rebuilt_shards.to_string(),
        &rows_per_shard.to_string(),
    ] {
        assert!(
            msg.contains(needle),
            "error must name {needle:?} to be actionable; got: {msg}"
        );
    }
    assert!(
        matches!(err, raven_railgun_core::AdapterError::Scheme(_)),
        "must be a typed Scheme error; got {err:?}"
    );
}
