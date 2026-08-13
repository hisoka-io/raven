//! End-to-end note-record test at `ring_dim = 2048`, `entries_per_shard = 2048`,
//! `entry_size = 512` holding a 328-byte record.
//!
//! 328 is not a legal cell width (see `pir_cell_width_law.rs`), so the record
//! runs at the smallest legal width above it. The oracle is independent of the
//! encoder: fields are checked against `Imt::node`, never against the row that
//! produced them.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::items_after_statements
)]

use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::ClientSession;
use raven_railgun_engine::imt::TREE_DEPTH;
use raven_railgun_engine::inspire::{
    apply_wal_entry, build_client_session, build_seeded_query, extract_response, re_encode_shard,
    register_client_session, setup_state, LogicalLeafStore,
};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder, LEAVES_PER_TREE};
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_poseidon::merkle_node;

/// Field offsets, restated rather than shared so a one-sided layout change fails.
const COMMITMENT_OFF: usize = 0;
const LEAF_INDEX_OFF: usize = 32;
const EPH_PUB_OFF: usize = 40;
const CEK_WRAP_OFF: usize = 72;
const CIPHERTEXT_OFF: usize = 104;
const CIPHERTEXT_WORDS: usize = 7;
/// 32 + 8 + 32 + 32 + 7 * 32.
const NOTE_RECORD_BYTES: usize = 328;
/// Smallest legal InsPIRe cell width at `ring_dim = 2048` that holds the record.
const CELL_RECORD_BYTES: usize = 512;

const ENTRIES: usize = LEAVES_PER_TREE as usize;
const ENTRIES_PER_SHARD: u32 = 2048;
const TREE_NUMBER: u32 = 0;
/// Crosses the shard 0 / shard 1 boundary at 2048 so shard routing is covered.
const LEAVES_PRELOADED: u32 = 2100;

fn canonical(seed: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = seed.max(1);
    b
}

fn commitment_for(leaf_index: u32) -> [u8; 32] {
    canonical(
        u8::try_from(leaf_index % 250)
            .unwrap_or(0)
            .saturating_add(1),
    )
}

/// Fixture material distinct per `(leaf_index, field, byte)`, so row aliasing or
/// a byte shift cannot produce a passing comparison.
fn fixture_word(leaf_index: u32, field_tag: u8, word: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (j, slot) in out.iter_mut().enumerate() {
        let mixed = u64::from(leaf_index)
            .wrapping_mul(0x9E37_79B9)
            .wrapping_add(u64::from(field_tag) << 24)
            .wrapping_add((word as u64) << 12)
            .wrapping_add(j as u64 * 31);
        *slot = u8::try_from(mixed % 251).unwrap_or(0);
    }
    out
}

fn eph_pub_for(leaf_index: u32) -> [u8; 32] {
    fixture_word(leaf_index, 1, 0)
}

fn cek_wrap_for(leaf_index: u32) -> [u8; 32] {
    fixture_word(leaf_index, 2, 0)
}

fn ciphertext_word_for(leaf_index: u32, word: usize) -> [u8; 32] {
    fixture_word(leaf_index, 3, word)
}

/// Build one row: the note record zero-padded to the cell width.
fn note_record_row(leaf_index: u32, commitment: [u8; 32]) -> Vec<u8> {
    let mut row = vec![0u8; CELL_RECORD_BYTES];
    let write = |row: &mut Vec<u8>, at: usize, src: &[u8]| {
        let dst = row
            .get_mut(at..at + src.len())
            .expect("note record field in range");
        dst.copy_from_slice(src);
    };
    write(&mut row, COMMITMENT_OFF, &commitment);
    write(
        &mut row,
        LEAF_INDEX_OFF,
        &u64::from(leaf_index).to_be_bytes(),
    );
    write(&mut row, EPH_PUB_OFF, &eph_pub_for(leaf_index));
    write(&mut row, CEK_WRAP_OFF, &cek_wrap_for(leaf_index));
    for word in 0..CIPHERTEXT_WORDS {
        write(
            &mut row,
            CIPHERTEXT_OFF + word * 32,
            &ciphertext_word_for(leaf_index, word),
        );
    }
    row
}

/// Materialize the raw bytes of one shard from the logical store.
fn materialize_db1_shard(store: &LogicalLeafStore, shard_id: u32) -> Vec<u8> {
    let eps = ENTRIES_PER_SHARD as usize;
    let mut buf = vec![0u8; eps * CELL_RECORD_BYTES];
    let base = shard_id as usize * eps;
    for row_offset in 0..eps {
        let leaf_index = u32::try_from(base + row_offset).unwrap_or(u32::MAX);
        let Some(commitment) = store.leaf(TREE_NUMBER, leaf_index) else {
            continue;
        };
        let row = note_record_row(leaf_index, *commitment);
        let start = row_offset * CELL_RECORD_BYTES;
        let dst = buf
            .get_mut(start..start + CELL_RECORD_BYTES)
            .expect("shard row in range");
        dst.copy_from_slice(&row);
    }
    buf
}

fn build_live_state_and_session() -> (
    raven_railgun_engine::inspire::InspireServerState,
    ClientSession,
    LogicalLeafStore,
    InspireParams,
) {
    let params = InspireParams::secure_128_d2048();
    let db = vec![0u8; ENTRIES * CELL_RECORD_BYTES];
    let (server_state, secret_key) =
        setup_state(&params, &db, CELL_RECORD_BYTES, InspireVariant::TwoPacking)
            .expect("setup_state");

    // Drives the IMT and dirty-shard set only; rows are materialized locally.
    let encoder: Arc<dyn PirTableEncoder> = EncoderKind::PerLeafBc { tree_number: 0 }
        .build(CELL_RECORD_BYTES, ENTRIES_PER_SHARD)
        .expect("encoder build");

    let mut store = LogicalLeafStore::new();
    for i in 0..LEAVES_PRELOADED {
        let payload = WalEntryPayload::AppendLeaf {
            tree_number: TREE_NUMBER,
            leaf_index: i,
            commitment: commitment_for(i),
        };
        apply_wal_entry(&mut store, &payload, 100 + u64::from(i), encoder.as_ref())
            .expect("apply leaf");
    }

    let dirty: Vec<u32> = store.dirty_shards().iter().copied().collect();
    assert!(
        dirty.contains(&0) && dirty.contains(&1),
        "fixture must dirty both shard 0 and shard 1; got {dirty:?}"
    );
    let mut encoded_db = (*server_state.encoded_db).clone();
    for shard_id in dirty {
        let bytes = materialize_db1_shard(&store, shard_id);
        re_encode_shard(
            &mut encoded_db,
            &params,
            shard_id,
            &bytes,
            CELL_RECORD_BYTES,
        )
        .expect("re_encode_shard");
    }

    let live_state = raven_railgun_engine::inspire::InspireServerState {
        crs: Arc::clone(&server_state.crs),
        encoded_db: Arc::new(encoded_db),
        cache: Arc::clone(&server_state.cache),
        session_store: Arc::clone(&server_state.session_store),
        variant: server_state.variant,
        entry_size: server_state.entry_size,
    };

    let mut client_session =
        build_client_session((*live_state.crs).clone(), secret_key, &params).expect("client");
    register_client_session(&mut client_session, &live_state).expect("register session");
    (live_state, client_session, store, params)
}

fn pir_query_note_record(
    leaf_index: u32,
    live_state: &raven_railgun_engine::inspire::InspireServerState,
    client_session: &ClientSession,
    params: &InspireParams,
) -> Vec<u8> {
    let (client_state, query) = build_seeded_query(
        client_session,
        live_state.shard_config(),
        u64::from(leaf_index),
        params,
    )
    .expect("build_seeded_query");
    use raven_railgun_engine::PirScheme;
    let response = <raven_railgun_engine::inspire::RavenInspireScheme as PirScheme>::respond(
        live_state, &query,
    )
    .expect("respond");
    extract_response(&live_state.crs, &client_state, &response, CELL_RECORD_BYTES).expect("extract")
}

/// Target leaves: first, low, a shard-0 interior row, the last row of shard 0,
/// the first row of shard 1, and the rightmost populated leaf.
const TARGET_LEAVES: [u32; 6] = [0, 1, 1_337, 2_047, 2_048, LEAVES_PRELOADED - 1];

#[test]
fn db1_note_record_query_recovers_every_field_and_folds_to_root() {
    let (live_state, client_session, store, params) = build_live_state_and_session();
    let imt = store.imt(TREE_NUMBER).expect("tree present");

    let mut recovered_rows: Vec<(u32, Vec<u8>)> = Vec::with_capacity(TARGET_LEAVES.len());

    for leaf_idx in TARGET_LEAVES {
        let plaintext = pir_query_note_record(leaf_idx, &live_state, &client_session, &params);
        let row = plaintext
            .get(..CELL_RECORD_BYTES)
            .expect("row plaintext present");

        // Independent oracle: Imt::node, not the leaf map the row was built from.
        let expected_commitment = imt.node(0, leaf_idx as usize);
        let recovered_commitment = row
            .get(COMMITMENT_OFF..COMMITMENT_OFF + 32)
            .expect("commitment slice");
        assert_eq!(
            recovered_commitment, &expected_commitment,
            "leaf_idx={leaf_idx}: commitment field must byte-equal Imt::node(0, {leaf_idx})"
        );

        let recovered_leaf_index = row
            .get(LEAF_INDEX_OFF..LEAF_INDEX_OFF + 8)
            .expect("leaf index slice");
        assert_eq!(
            recovered_leaf_index,
            &u64::from(leaf_idx).to_be_bytes(),
            "leaf_idx={leaf_idx}: leaf-index field mismatch"
        );

        assert_eq!(
            row.get(EPH_PUB_OFF..EPH_PUB_OFF + 32).expect("eph slice"),
            &eph_pub_for(leaf_idx),
            "leaf_idx={leaf_idx}: ephemeral-public-key field mismatch"
        );
        assert_eq!(
            row.get(CEK_WRAP_OFF..CEK_WRAP_OFF + 32).expect("cek slice"),
            &cek_wrap_for(leaf_idx),
            "leaf_idx={leaf_idx}: wrapped-content-key field mismatch"
        );
        for word in 0..CIPHERTEXT_WORDS {
            let at = CIPHERTEXT_OFF + word * 32;
            assert_eq!(
                row.get(at..at + 32).expect("ciphertext slice"),
                &ciphertext_word_for(leaf_idx, word),
                "leaf_idx={leaf_idx}: ciphertext word {word} mismatch"
            );
        }

        let pad = row
            .get(NOTE_RECORD_BYTES..CELL_RECORD_BYTES)
            .expect("pad slice");
        assert!(
            pad.iter().all(|&b| b == 0),
            "leaf_idx={leaf_idx}: cell padding past the {NOTE_RECORD_BYTES}-byte record must be zero"
        );

        let mut path_idx = leaf_idx as usize;
        let mut current = expected_commitment;
        for level in 0..TREE_DEPTH {
            let sibling_idx_at_level = path_idx ^ 1;
            let bit = path_idx & 1;
            path_idx >>= 1;
            let sibling = imt.node(level, sibling_idx_at_level);
            current = if bit == 1 {
                merkle_node(sibling, current).expect("hash right")
            } else {
                merkle_node(current, sibling).expect("hash left")
            };
        }
        assert_eq!(
            current,
            imt.root(),
            "leaf_idx={leaf_idx}: commitment recovered from PIR does not fold to Imt::root"
        );

        recovered_rows.push((leaf_idx, row.to_vec()));
    }

    // Distinctness rules out a cell that returns the same row for every index.
    for (i, (leaf_a, row_a)) in recovered_rows.iter().enumerate() {
        for (leaf_b, row_b) in recovered_rows.iter().skip(i + 1) {
            assert_ne!(
                row_a, row_b,
                "rows for leaf {leaf_a} and leaf {leaf_b} are byte-identical; \
                 the cell is not resolving distinct indices"
            );
        }
    }
}
