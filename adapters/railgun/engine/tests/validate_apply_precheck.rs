//! `validate_apply` runs before the WAL write, so anything the IMT would later
//! refuse has to be refused here or the WAL keeps an entry replay cannot apply.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use raven_railgun_core::{AdapterError, InstanceId};
use raven_railgun_engine::imt::TREE_MAX_ITEMS;
use raven_railgun_engine::inspire::{apply_wal_entry, validate_apply, LogicalLeafStore};
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{PerLeafCommitmentEncoder, PirTableEncoder};
use raven_railgun_persistence::{StoreLayout, WalEntryPayload};

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-validate-precheck";

/// Independent restatement of the BN254 scalar field modulus, big-endian.
/// `modulus_vectors_match_the_poseidon_field_boundary` pins it to ark-bn254.
const BN254_FR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

const LIST_KEY: [u8; 32] = [0x42; 32];

fn modulus_minus_one() -> [u8; 32] {
    let mut bytes = BN254_FR_MODULUS_BE;
    bytes[31] = 0x00;
    bytes
}

fn canonical(seed: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = seed.max(1);
    bytes
}

fn enc() -> PerLeafCommitmentEncoder {
    PerLeafCommitmentEncoder::new(32, 2048, 0).expect("test encoder")
}

fn enc_arc() -> Arc<dyn PirTableEncoder> {
    Arc::new(enc())
}

fn append(leaf_index: u32, commitment: [u8; 32]) -> WalEntryPayload {
    WalEntryPayload::AppendLeaf {
        tree_number: 0,
        leaf_index,
        commitment,
    }
}

fn ppoi_leaf(list_index: u32, blinded_commitment: [u8; 32]) -> WalEntryPayload {
    WalEntryPayload::PpoiListLeafAdded {
        list_key: LIST_KEY,
        list_index,
        blinded_commitment,
        status: 1,
    }
}

#[test]
fn modulus_vectors_match_the_poseidon_field_boundary() {
    raven_railgun_poseidon::hash_n(&[modulus_minus_one()])
        .expect("modulus - 1 is the largest canonical Fr");
    let err = raven_railgun_poseidon::hash_n(&[BN254_FR_MODULUS_BE])
        .expect_err("the modulus itself is not a canonical Fr");
    assert!(
        format!("{err}").contains("BN254"),
        "expected an Fr decode refusal, got: {err}"
    );
}

#[test]
fn validate_apply_rejects_a_non_canonical_append_commitment() {
    let store = LogicalLeafStore::new();
    let err = validate_apply(&store, &append(0, BN254_FR_MODULUS_BE))
        .expect_err("a commitment at the modulus must never reach the WAL");
    assert!(
        matches!(err, AdapterError::InvalidQuery(_)),
        "expected InvalidQuery, got {err:?}"
    );
}

#[test]
fn validate_apply_accepts_the_largest_canonical_commitment() {
    let store = LogicalLeafStore::new();
    validate_apply(&store, &append(0, modulus_minus_one()))
        .expect("modulus - 1 is in-field and must pass the pre-check");
}

#[test]
fn validate_apply_rejects_a_non_canonical_ppoi_blinded_commitment() {
    let store = LogicalLeafStore::new();
    let err = validate_apply(&store, &ppoi_leaf(0, BN254_FR_MODULUS_BE))
        .expect_err("a blinded commitment at the modulus must never reach the WAL");
    assert!(
        matches!(err, AdapterError::InvalidQuery(_)),
        "expected InvalidQuery, got {err:?}"
    );
}

/// Ingress rejects with `InvalidQuery` so the caller sees a client-side refusal;
/// replay screens the same value separately and refuses the boot instead.
#[test]
fn apply_wal_entry_classifies_a_non_canonical_commitment_as_invalid_query() {
    let mut store = LogicalLeafStore::new();
    let err = apply_wal_entry(&mut store, &append(0, BN254_FR_MODULUS_BE), 100, &enc())
        .expect_err("a commitment at the modulus must not apply");
    assert!(
        matches!(err, AdapterError::InvalidQuery(_)),
        "expected InvalidQuery, got {err:?}"
    );
}

#[test]
fn validate_apply_rejects_a_leaf_index_at_or_past_tree_capacity() {
    let store = LogicalLeafStore::new();
    let capacity = u32::try_from(TREE_MAX_ITEMS).expect("depth-16 capacity fits u32");
    for leaf_index in [capacity, capacity.saturating_add(5), u32::MAX] {
        let err = validate_apply(&store, &append(leaf_index, canonical(7)))
            .expect_err("an index past capacity must never reach the WAL");
        let msg = format!("{err}");
        assert!(
            msg.contains("capacity") && msg.contains(&TREE_MAX_ITEMS.to_string()),
            "expected a capacity refusal naming {TREE_MAX_ITEMS}, got: {msg}"
        );
    }
}

#[test]
fn validate_apply_rejects_a_ppoi_list_index_at_or_past_tree_capacity() {
    let store = LogicalLeafStore::new();
    let capacity = u32::try_from(TREE_MAX_ITEMS).expect("depth-16 capacity fits u32");
    let err = validate_apply(&store, &ppoi_leaf(capacity, canonical(9)))
        .expect_err("a list index past capacity must never reach the WAL");
    let msg = format!("{err}");
    assert!(
        msg.contains("capacity") && msg.contains(&TREE_MAX_ITEMS.to_string()),
        "expected a capacity refusal naming {TREE_MAX_ITEMS}, got: {msg}"
    );
}

/// A non-canonical leaf can never be encoded, so skipping it on replay leaves
/// the store leaf count behind: every later entry for that tree then fails the
/// contiguity arm of the same screen and the whole tail is discarded. The
/// poisoned entry is laid down FIRST here so a skip would take the three valid
/// entries behind it with it.
#[test]
fn a_wal_holding_a_non_canonical_leaf_refuses_the_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let opened = InspirePersistence::open(
        StoreLayout::open(dir.path()).expect("layout"),
        SCHEME_TAG,
        InstanceId::new("precheck-fatal-replay"),
        SnapshotPolicy::default(),
        enc_arc(),
    )
    .expect("open 1");
    opened
        .persistence
        .apply_event(&append(0, BN254_FR_MODULUS_BE), 100)
        .expect("apply_event writes the WAL without running validate_apply");
    for leaf_index in 1..4u32 {
        let seed = u8::try_from(leaf_index).expect("< 4");
        opened
            .persistence
            .apply_event(
                &append(leaf_index, canonical(seed)),
                100 + u64::from(leaf_index),
            )
            .expect("valid tail entry");
    }
    drop(opened);

    let err = InspirePersistence::open(
        StoreLayout::open(dir.path()).expect("layout 2"),
        SCHEME_TAG,
        InstanceId::new("precheck-fatal-replay"),
        SnapshotPolicy::default(),
        enc_arc(),
    )
    .expect_err("a non-canonical leaf in the WAL must refuse the boot, not skip");
    let msg = format!("{err}");
    assert!(
        msg.contains("seq 0") && msg.contains("BN254"),
        "the refusal must name the offending WAL seq and the reason, got: {msg}"
    );
}

#[test]
fn contiguous_canonical_leaves_still_validate_and_apply() {
    let mut store = LogicalLeafStore::new();
    for leaf_index in 0..4u32 {
        let seed = u8::try_from(leaf_index).expect("< 4");
        let payload = append(leaf_index, canonical(seed));
        validate_apply(&store, &payload).expect("contiguous canonical leaf validates");
        apply_wal_entry(&mut store, &payload, 100 + u64::from(leaf_index), &enc())
            .expect("contiguous canonical leaf applies");
    }
    assert_eq!(store.imt_leaf_count_for(0), 4);
}
