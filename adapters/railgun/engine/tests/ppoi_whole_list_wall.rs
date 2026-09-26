//! An instance bound to a WHOLE PPOI list holds one depth-16 IMT, so it serves a list of at
//! most `LEAVES_PER_PPOI_BLOCK` rows and refuses every row past that.
//!
//! The production OFAC list passed that wall long ago, and nothing asserted what happens on
//! the row that crosses it. This pins both directions at the boundary and, in particular,
//! pins that the refusal NAMES the capacity: an operator reading only `consumer stalled` has
//! no way to tell this apart from an upstream outage.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_railgun_engine::inspire::{validate_apply, LogicalLeafStore};
use raven_railgun_engine::orchestrator::LEAVES_PER_PPOI_BLOCK;
use raven_railgun_engine::pir_table::EncoderKind;
use raven_railgun_persistence::{PpoiEventType, WalEntryPayload};

const LIST_KEY: [u8; 32] = [0xab; 32];

/// Canonical BN254 Fr, which `merkle_node` requires, and distinct per row.
fn leaf(list_index: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[28..].copy_from_slice(&list_index.to_be_bytes());
    out
}

fn row(list_index: u32) -> WalEntryPayload {
    WalEntryPayload::PpoiListLeafAdded {
        list_key: LIST_KEY,
        list_index,
        blinded_commitment: leaf(list_index),
        status: 0,
        event_type: PpoiEventType::Shield,
        signature: vec![0u8; 64],
        // The all-zero sentinel: `validate_apply` counts it instead of comparing, which keeps
        // this test on the capacity question and off the upstream-root one.
        validated_merkleroot: [0u8; 32],
    }
}

#[test]
fn a_whole_list_instance_fills_one_tree_and_then_names_the_capacity_it_hit() {
    let encoder = EncoderKind::PerListStatus { list_key: LIST_KEY }
        .build(512, 2048)
        .expect("status encoder");
    let mut store = LogicalLeafStore::new();

    for list_index in 0..LEAVES_PER_PPOI_BLOCK {
        store
            .apply(&row(list_index), 0, encoder.as_ref())
            .unwrap_or_else(|e| panic!("row {list_index} is inside one tree: {e}"));
    }
    assert_eq!(
        store
            .ppoi_imt(&LIST_KEY)
            .map(raven_railgun_engine::imt::Imt::leaf_count),
        Some(LEAVES_PER_PPOI_BLOCK as usize),
        "the last row of the tree must be accepted; a `>=` one early wedges the list a row short"
    );

    // The row that crosses the boundary. It is an ordinary row of the list upstream keeps
    // publishing, and this instance can never hold it.
    let over = LEAVES_PER_PPOI_BLOCK;
    let refused = store
        .apply(&row(over), 0, encoder.as_ref())
        .expect_err("the row past one tree must be refused, not silently dropped");
    let message = refused.to_string();
    assert!(
        message.contains("list_index") && message.contains(&over.to_string()),
        "the refusal must name the row it refused: {message}"
    );
    assert!(
        message.contains("capacity") && message.contains(&LEAVES_PER_PPOI_BLOCK.to_string()),
        "the refusal must name the limit, or an operator cannot tell it from an outage: {message}"
    );

    // ...and it stays refused, which is what makes this permanent rather than a hiccup.
    store
        .apply(&row(over + 1), 0, encoder.as_ref())
        .expect_err("every later row is refused too");

    // The pre-WAL screen refuses the same row, so the refusal lands before anything durable.
    validate_apply(&store, &row(over)).expect_err("the screen ahead of the WAL write refuses it");
}
