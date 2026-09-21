//! What one retained `LogicalLeafStore` clone costs in RAM at the served shape.
//!
//! The row/addendum pair can only share an epoch if the committed store is retained alongside the
//! published state, and `drive_commit` already clones it for `commit_v6`. Retaining that clone is
//! in-memory only — but `ArcSwap` means two can be resident while readers drain, so the number that
//! decides it is the marginal cost of ONE extra clone, not the size of the process.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::print_stderr)]

use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::{PerListPath10Encoder, PirTableEncoder};
use raven_railgun_persistence::WalEntryPayload;

/// One `per-list-path10` block instance owns a full depth-16 tree.
const LEAVES_PER_BLOCK: u32 = 65_536;
/// Live OFAC/Ethereum population, measured 2026-09-20. A status carries no `list_index`, so the
/// router cannot localize it to a block and every block instance files the whole list.
const WHOLE_LIST_POPULATION: u32 = 358_344;
const ENTRIES_PER_SHARD: u32 = 2_048;
const LIST_KEY: [u8; 32] = [0xab; 32];

/// Distinct and Fr-canonical: the top 16 bytes stay zero, so the value is far below the modulus.
fn bc_for(index: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..20].copy_from_slice(&index.to_be_bytes());
    out[31] = 0x01;
    out
}

/// Resident set size in bytes, read from the kernel rather than modelled.
fn rss_bytes() -> u64 {
    let statm = std::fs::read_to_string("/proc/self/statm").expect("statm");
    let pages: u64 = statm
        .split_whitespace()
        .nth(1)
        .expect("resident field")
        .parse()
        .expect("resident pages");
    pages * 4096
}

fn build_block(encoder: &dyn PirTableEncoder) -> LogicalLeafStore {
    let mut store = LogicalLeafStore::default();
    for index in 0..LEAVES_PER_BLOCK {
        apply_wal_entry(
            &mut store,
            &WalEntryPayload::PpoiListLeafAdded {
                list_key: LIST_KEY,
                list_index: index,
                blinded_commitment: bc_for(index),
                status: 0,
                event_type: raven_railgun_persistence::PpoiEventType::Shield,
                signature: vec![0; 64],
                validated_merkleroot: [0; 32],
            },
            0,
            encoder,
        )
        .expect("append");
    }
    store
}

#[test]
#[ignore = "builds a full 65,536-leaf depth-16 IMT (~1M Poseidon hashes); run by hand when sizing anything that duplicates a per-instance store"]
fn one_retained_clone_costs_this_many_bytes_at_the_served_shape() {
    let encoder =
        PerListPath10Encoder::new(ENTRIES_PER_SHARD, LIST_KEY).expect("per-list-path10 encoder");
    let encoder_ref: Box<dyn PirTableEncoder> =
        Box::new(PerListPath10Encoder::new(ENTRIES_PER_SHARD, LIST_KEY).expect("second encoder"));

    let before_build = rss_bytes();
    let store = build_block(&encoder);
    let after_build = rss_bytes();

    // THE NUMBER. Everything above is the store the process already holds; this is the marginal
    // cost a retained copy adds, and it is the figure to check against the box's memory budget.
    let before_clone = rss_bytes();
    let retained = store.clone();
    let after_clone = rss_bytes();

    let build_delta = after_build.saturating_sub(before_build);
    let clone_delta = after_clone.saturating_sub(before_clone);

    // The deployed shape is bigger than this block's own leaves. `logical_store.rs:340-341`
    // files `ppoi_status` and `ppoi_block_height` UNCONDITIONALLY, before the
    // `if let Some(list_index)` gate at `:343` -- so a block carries the whole list's status
    // maps, and that is what a retained clone duplicates. Measured, not modelled.
    let mut deployed = store.clone();
    let before_status = rss_bytes();
    for index in 0..WHOLE_LIST_POPULATION {
        apply_wal_entry(
            &mut deployed,
            &WalEntryPayload::PpoiStatus {
                list_key: LIST_KEY,
                blinded_commitment: bc_for(index),
                status: 0,
            },
            0,
            &*encoder_ref,
        )
        .expect("status");
    }
    let after_status = rss_bytes();
    let status_delta = after_status.saturating_sub(before_status);

    let before_deployed_clone = rss_bytes();
    let deployed_retained = deployed.clone();
    let after_deployed_clone = rss_bytes();
    let deployed_clone_delta = after_deployed_clone.saturating_sub(before_deployed_clone);

    eprintln!(
        "{{\"whole_list_status_delta_bytes\":{},\"deployed_clone_delta_bytes\":{},\"deployed_clone_delta_mib\":{}}}",
        status_delta,
        deployed_clone_delta,
        deployed_clone_delta / (1024 * 1024),
    );
    assert!(
        deployed_retained.ppoi_imt_root(&LIST_KEY).is_some(),
        "deployed-shape clone must still hold the tree"
    );

    eprintln!(
        "{{\"leaves\":{},\"entries_per_shard\":{},\"build_delta_bytes\":{},\"clone_delta_bytes\":{},\"clone_delta_kib\":{}}}",
        LEAVES_PER_BLOCK,
        ENTRIES_PER_SHARD,
        build_delta,
        clone_delta,
        clone_delta / 1024,
    );

    // Keep both alive across the measurement so neither is dropped early.
    assert_eq!(
        store.ppoi_imt_root(&LIST_KEY).expect("root"),
        retained.ppoi_imt_root(&LIST_KEY).expect("retained root"),
        "the clone must be the same tree it was cloned from"
    );
    assert!(
        clone_delta > 0,
        "a clone of a 65,536-leaf store must cost measurable resident memory; got {clone_delta} B"
    );
}
