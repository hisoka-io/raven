//! An absent T1 status must not encode as `Valid`. Byte 0 is the spend-authorizing
//! verdict, so a missing row defaulting to it is fail-open on the one decision this
//! table exists to make.
//!
//! Reachable through a reorg, not a crash. The unwind drives two removals from two
//! independent height maps: `ppoi_block_height` (keyed by blinded commitment) clears
//! `ppoi_status`, while `ppoi_list_leaf_block_height` (keyed by list index) clears
//! `ppoi_index_bc`. A status update lands at a later height than the leaf it describes,
//! so a fork point between the two removes the status and keeps the leaf.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::{PerListStatusEncoder, PirTableEncoder};
use raven_railgun_persistence::WalEntryPayload;

const LIST_KEY: [u8; 32] = [0x7a; 32];
const RECORD: usize = 32;
const EPS: u32 = 2048;

/// Mirrors `poi_status_to_str` / `statusByteToPOIStatus`: 0 Valid, 1 ShieldBlocked,
/// 2 ProofSubmitted, 3 Missing.
const VALID: u8 = 0;
const SHIELD_BLOCKED: u8 = 1;
const MISSING: u8 = 3;

fn enc() -> PerListStatusEncoder {
    PerListStatusEncoder::new(RECORD, EPS, LIST_KEY).expect("encoder")
}

fn bc(seed: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = seed.max(1);
    b
}

fn status_byte_of_row(store: &LogicalLeafStore, list_index: usize) -> u8 {
    let bytes = enc().materialize_shard(0, store);
    *bytes
        .get(list_index * RECORD)
        .expect("row inside the shard buffer")
}

/// The defect: a reorg past a ShieldBlocked status update leaves the leaf in place
/// with its status gone, and the row then reads as the verdict that permits a spend.
#[test]
fn a_reorg_that_drops_a_shield_blocked_status_must_not_leave_the_row_reading_valid() {
    let mut store = LogicalLeafStore::new();
    let commitment = bc(9);

    apply_wal_entry(
        &mut store,
        &WalEntryPayload::PpoiListLeafAdded {
            list_key: LIST_KEY,
            list_index: 0,
            blinded_commitment: commitment,
            status: VALID,
        },
        100,
        &enc(),
    )
    .expect("leaf at height 100");

    apply_wal_entry(
        &mut store,
        &WalEntryPayload::PpoiStatus {
            list_key: LIST_KEY,
            blinded_commitment: commitment,
            status: SHIELD_BLOCKED,
        },
        200,
        &enc(),
    )
    .expect("status at height 200");
    assert_eq!(
        status_byte_of_row(&store, 0),
        SHIELD_BLOCKED,
        "precondition: the row carries the blocking verdict before the reorg"
    );

    // Fork between the leaf (100) and the status update (200): the status is stale and
    // is dropped; the leaf is not, so `ppoi_index_bc` still yields a row to encode.
    apply_wal_entry(
        &mut store,
        &WalEntryPayload::Reorg { height: 150 },
        150,
        &enc(),
    )
    .expect("reorg to 150");

    assert!(
        store.ppoi_status(&LIST_KEY, &commitment).is_none(),
        "precondition: the reorg dropped the status"
    );
    assert!(
        store.ppoi_bc_at(&LIST_KEY, 0).is_some(),
        "precondition: the reorg kept the leaf, so a row is still encoded for it"
    );

    let byte = status_byte_of_row(&store, 0);
    assert_ne!(
        byte, VALID,
        "a commitment whose ShieldBlocked status was rolled back must never encode as \
         Valid: that is the verdict that authorizes a spend, and the wallet cannot tell \
         it from a genuine clean row"
    );
    assert_eq!(
        byte, MISSING,
        "an absent status must encode as Missing, matching what the plaintext shim \
         returns for the same state"
    );
}

/// The PIR row and the plaintext shim must agree. `poi_shim` maps `None` to Missing;
/// the encoder must not map it to Valid.
#[test]
fn the_encoder_agrees_with_the_plaintext_shim_on_an_absent_status() {
    let mut store = LogicalLeafStore::new();
    let commitment = bc(11);
    apply_wal_entry(
        &mut store,
        &WalEntryPayload::PpoiListLeafAdded {
            list_key: LIST_KEY,
            list_index: 0,
            blinded_commitment: commitment,
            status: SHIELD_BLOCKED,
        },
        100,
        &enc(),
    )
    .expect("leaf");
    apply_wal_entry(
        &mut store,
        &WalEntryPayload::Reorg { height: 50 },
        50,
        &enc(),
    )
    .expect("reorg below the leaf");

    // Both maps cleared here, so no row is encoded at all and the buffer stays zero.
    // The case that matters is the asymmetric one above; this pins that a fully
    // unwound list does not resurrect a verdict either.
    assert_eq!(
        status_byte_of_row(&store, 0),
        0,
        "a row for a leaf that no longer exists is zero-filled, and the client's \
         BC-tail binding is what rejects it - not the status byte"
    );
    assert!(
        store.ppoi_bc_at(&LIST_KEY, 0).is_none(),
        "the leaf itself was rolled back"
    );
}

/// A present status still round-trips unchanged.
#[test]
fn a_present_status_is_encoded_verbatim() {
    for status in [VALID, SHIELD_BLOCKED, 2u8] {
        let mut store = LogicalLeafStore::new();
        apply_wal_entry(
            &mut store,
            &WalEntryPayload::PpoiListLeafAdded {
                list_key: LIST_KEY,
                list_index: 0,
                blinded_commitment: bc(3),
                status,
            },
            100,
            &enc(),
        )
        .expect("leaf");
        assert_eq!(
            status_byte_of_row(&store, 0),
            status,
            "a written status must reach the row unchanged"
        );
    }
}
