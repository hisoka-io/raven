//! A served row and its addendum must derive from one committed state.
//!
//! The row is served from a published snapshot; the addendum used to be read from the LIVE store,
//! which runs a commit cadence ahead (1000 appends / 300 s by default). Between commits the two
//! halves therefore came from different trees, and the client could only reject the pair as a
//! pinned-root mismatch — an error naming the pin rather than the server.
//!
//! The negative control is the load-bearing half of this file: it proves the append really does
//! move the upper siblings, so "the committed addendum did not change" is a property and not an
//! artefact of nothing having happened.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
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

const ENTRIES_PER_SHARD: u32 = 2_048;
const LIST_KEY: [u8; 32] = [0xab; 32];
const ADDENDUM_BYTES: usize = 5 * 32;

fn bc_for(index: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..20].copy_from_slice(&index.to_be_bytes());
    out[31] = 0x01;
    out
}

fn append(store: &mut LogicalLeafStore, encoder: &dyn PirTableEncoder, index: u32) {
    apply_wal_entry(
        store,
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

/// Levels 11..15 of the path for a shard's first leaf, read from the LIVE tree.
fn live_addendum(store: &LogicalLeafStore, shard_id: u32) -> Vec<u8> {
    let proof = store
        .ppoi_merkle_proof(&LIST_KEY, shard_id * ENTRIES_PER_SHARD)
        .expect("live proof");
    proof
        .elements
        .into_iter()
        .skip(11)
        .take(5)
        .flatten()
        .collect()
}

#[test]
fn an_append_after_the_commit_cannot_move_the_addendum_the_row_is_served_with() {
    let encoder = PerListPath10Encoder::new(ENTRIES_PER_SHARD, LIST_KEY).expect("encoder");
    let mut store = LogicalLeafStore::default();

    // Fill shard 0 exactly. Indices must stay contiguous; `checked_imt_append` enforces it.
    for index in 0..ENTRIES_PER_SHARD {
        append(&mut store, &encoder, index);
    }

    let db7 = some_encoded_db();
    store.refresh_committed_addenda(&db7, ENTRIES_PER_SHARD);
    assert!(
        store.committed_addenda_derived_from(&db7),
        "provenance is recorded"
    );
    let committed_at_7 = store
        .committed_addendum(&LIST_KEY, 0)
        .expect("shard 0 addendum")
        .to_vec();
    assert_eq!(
        committed_at_7.len(),
        ADDENDUM_BYTES,
        "an addendum is five sibling hashes; a short one folds to a wrong root"
    );
    assert_eq!(
        committed_at_7,
        live_addendum(&store, 0),
        "at the moment of the commit the two must agree"
    );

    // Shard 0's level-11 sibling IS the subtree covering shard 1, so this append moves it.
    append(&mut store, &encoder, ENTRIES_PER_SHARD);

    // NEGATIVE CONTROL. Without this the assertion below passes even if nothing happened.
    let live_after = live_addendum(&store, 0);
    assert_ne!(
        committed_at_7, live_after,
        "the append must actually move shard 0's upper siblings, or this test proves nothing"
    );

    // THE PROPERTY. The row is served from the epoch-7 snapshot, so the addendum must still be
    // the epoch-7 one — not the live tree's.
    assert_eq!(
        store
            .committed_addendum(&LIST_KEY, 0)
            .expect("still present"),
        committed_at_7.as_slice(),
        "a live append must not reach the addendum a published epoch serves"
    );
    assert!(
        store.committed_addenda_derived_from(&db7),
        "provenance must not drift without a publish"
    );

    // And a new publish re-derives it, so the pair tracks the state rather than freezing forever.
    let db8 = some_encoded_db();
    store.refresh_committed_addenda(&db8, ENTRIES_PER_SHARD);
    assert!(store.committed_addenda_derived_from(&db8));
    assert!(
        !store.committed_addenda_derived_from(&db7),
        "the old state no longer matches"
    );
    assert_eq!(
        store.committed_addendum(&LIST_KEY, 0).expect("re-derived"),
        live_after.as_slice(),
        "after a publish the addendum must be the new committed tree's"
    );
}

#[test]
fn a_shard_with_no_tree_has_no_addendum_rather_than_an_empty_one() {
    let encoder = PerListPath10Encoder::new(ENTRIES_PER_SHARD, LIST_KEY).expect("encoder");
    let mut store = LogicalLeafStore::default();
    append(&mut store, &encoder, 0);
    store.refresh_committed_addenda(&some_encoded_db(), ENTRIES_PER_SHARD);

    // An unknown list key must be ABSENT. `unwrap_or_default()` here would hand the caller an
    // empty addendum that folds to a wrong root with HTTP 200 — the defect, not the refusal.
    assert!(
        store.committed_addendum(&[0xcd; 32], 0).is_none(),
        "an unknown list must refuse, not default"
    );
}
