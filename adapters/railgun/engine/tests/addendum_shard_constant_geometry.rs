//! A shard whose rows do not all share one upper subtree cannot have a shard-constant addendum.
//!
//! The server derives levels 11..15 once, from the shard's FIRST leaf, and serves them to every row
//! in that shard. That is only sound while the whole shard sits inside one level-11 subtree, i.e.
//! while `entries_per_shard <= 2^PATH10_LEVELS`. At 4,096 rows, leaves 0..2047 and 2048..4095 sit in
//! DIFFERENT level-11 subtrees, so half the shard is served an upper sibling that belongs to the
//! other half — and the client can only reject it as a pinned-root mismatch.
//!
//! Note this is the OPPOSITE direction from the dirty-set property on the same constant, where a
//! wider shard is sound because the affected subtree sits inside one shard. Do not conflate them.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::list::PATH10_LEVELS;
use raven_railgun_engine::pir_table::{PerListPath10Encoder, PirTableEncoder};
use raven_railgun_persistence::WalEntryPayload;

/// Any encoded database will do for the store-level property; identity is what is compared.
fn some_encoded_db() -> std::sync::Arc<raven_inspire::EncodedDatabase> {
    let params = raven_inspire::params::InspireParams::secure_128_d2048();
    let db = raven_railgun_testkit::toy_db(raven_railgun_testkit::TOY_ENTRIES, 32);
    let (state, _sk) = raven_railgun_engine::inspire::setup_state(
        &params,
        &db,
        32,
        raven_inspire::params::InspireVariant::TwoPacking,
    )
    .expect("toy setup_state");
    state.encoded_db
}

const LIST_KEY: [u8; 32] = [0xab; 32];

fn store_with_one_leaf(encoder: &dyn PirTableEncoder) -> LogicalLeafStore {
    let mut store = LogicalLeafStore::default();
    let mut bc = [0u8; 32];
    bc[31] = 0x01;
    apply_wal_entry(
        &mut store,
        &WalEntryPayload::PpoiListLeafAdded {
            list_key: LIST_KEY,
            list_index: 0,
            blinded_commitment: bc,
            status: 0,
            event_type: raven_railgun_persistence::PpoiEventType::Shield,
            signature: vec![0; 64],
            validated_merkleroot: [0; 32],
        },
        0,
        encoder,
    )
    .expect("append");
    store
}

#[test]
fn a_shard_wider_than_one_upper_subtree_yields_no_addendum_rather_than_a_wrong_one() {
    let too_wide = 1u32 << (PATH10_LEVELS + 1); // 4,096
    let encoder = PerListPath10Encoder::new(too_wide, LIST_KEY).expect("encoder still constructs");
    let mut store = store_with_one_leaf(&encoder);

    store.refresh_committed_addenda(&some_encoded_db(), too_wide);

    // Absent, never a wrong one. The batch path turns absence into 503 plus a counter; serving the
    // first leaf's upper siblings to the far half of the shard is the defect this prevents.
    assert!(
        store.committed_addendum(&LIST_KEY, 0).is_none(),
        "a geometry that cannot be shard-constant must yield NO addendum"
    );
}

#[test]
fn the_shipped_geometry_and_everything_narrower_still_derives_one() {
    // `entries_per_shard == ring_dim == 2048` is the shipped shape and is exactly at the bound.
    for width in [512u32, 1_024, 1u32 << PATH10_LEVELS] {
        let encoder = PerListPath10Encoder::new(width, LIST_KEY).expect("encoder");
        let mut store = store_with_one_leaf(&encoder);
        store.refresh_committed_addenda(&some_encoded_db(), width);
        assert!(
            store.committed_addendum(&LIST_KEY, 0).is_some(),
            "width {width} is sound and must still derive an addendum"
        );
    }
}

#[test]
fn the_encoder_itself_still_accepts_the_wider_width_the_dirty_set_property_needs() {
    // The same width is LEGITIMATE for the dirty-set property, where the affected subtree sits
    // inside one shard. The bound belongs to the addendum, not to the encoder.
    assert!(PerListPath10Encoder::new(1u32 << (PATH10_LEVELS + 1), LIST_KEY).is_ok());
    assert!(PerListPath10Encoder::new(0, LIST_KEY).is_err());
}
