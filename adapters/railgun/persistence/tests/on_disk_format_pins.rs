//! Pins the two on-disk identifiers this crate owns: the snapshot header magic and the
//! bincode encoding of [`WalEntryPayload`].
//!
//! Both are symmetric in-process - the same build writes and reads them - so changing
//! either is invisible to every round-trip test in the tree while silently orphaning
//! every snapshot and WAL frame already on an operator's disk. The expected bytes here
//! are therefore written out by hand, never derived from the types under test.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use raven_railgun_persistence::{
    PpoiEventType, Snapshot, SnapshotId, StoreLayout, WalEntryPayload, SNAPSHOT_MAGIC,
};

/// The bytes an already-deployed snapshot carries in its header.
const ON_DISK_SNAPSHOT_MAGIC: [u8; 16] = *b"RAVEN_RAILGUN_01";

#[test]
fn snapshot_magic_matches_the_bytes_already_on_disk() {
    assert_eq!(
        SNAPSHOT_MAGIC, ON_DISK_SNAPSHOT_MAGIC,
        "changing SNAPSHOT_MAGIC orphans every existing snapshot; it is an operator \
         migration, not a rename"
    );
}

/// The constant is only worth pinning if it is the value the loader actually compares
/// against: a snapshot written under the literal must load under the constant.
#[test]
fn a_snapshot_written_under_the_literal_magic_loads_under_the_constant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("open");
    let payload: Vec<u8> = (0..1024u32).map(|i| (i & 0xFF) as u8).collect();

    Snapshot::build(payload.clone(), ON_DISK_SNAPSHOT_MAGIC)
        .save(&layout, SnapshotId(1))
        .expect("save");
    let loaded = Snapshot::load(&layout, SnapshotId(1), SNAPSHOT_MAGIC).expect("load");

    assert_eq!(loaded.header.magic, ON_DISK_SNAPSHOT_MAGIC);
    assert_eq!(loaded.data, payload);
}

/// `(payload, hand-written bytes)` for one instance of every variant.
///
/// bincode tags an enum with its declaration index as a u32 LE prefix, so reordering the
/// variants - or reordering, widening or narrowing a field - re-points every frame an
/// older build wrote at a different variant, and `replay` reports success on the wrong one.
fn wal_payload_vectors() -> Vec<(WalEntryPayload, Vec<u8>)> {
    let mut append_leaf = vec![0x00, 0x00, 0x00, 0x00];
    append_leaf.extend_from_slice(&0x0102_0304u32.to_le_bytes());
    append_leaf.extend_from_slice(&0x1112_1314u32.to_le_bytes());
    append_leaf.extend_from_slice(&[0xAA; 32]);

    let mut ppoi_status = vec![0x01, 0x00, 0x00, 0x00];
    ppoi_status.extend_from_slice(&[0xBB; 32]);
    ppoi_status.extend_from_slice(&[0xCC; 32]);
    ppoi_status.push(0x03);

    let mut list_leaf_added = vec![0x02, 0x00, 0x00, 0x00];
    list_leaf_added.extend_from_slice(&[0xDD; 32]);
    list_leaf_added.extend_from_slice(&0x2122_2324u32.to_le_bytes());
    list_leaf_added.extend_from_slice(&[0xEE; 32]);
    list_leaf_added.push(0x02);
    list_leaf_added.extend_from_slice(&0u32.to_le_bytes());
    list_leaf_added.extend_from_slice(&64u64.to_le_bytes());
    list_leaf_added.extend_from_slice(&[0xAB; 64]);
    list_leaf_added.extend_from_slice(&[0xAC; 32]);

    let mut reorg = vec![0x03, 0x00, 0x00, 0x00];
    reorg.extend_from_slice(&0x3132_3334_3536_3738u64.to_le_bytes());

    let mut heartbeat = vec![0x04, 0x00, 0x00, 0x00];
    heartbeat.extend_from_slice(&0x4142_4344_4546_4748u64.to_le_bytes());

    vec![
        (
            WalEntryPayload::AppendLeaf {
                tree_number: 0x0102_0304,
                leaf_index: 0x1112_1314,
                commitment: [0xAA; 32],
            },
            append_leaf,
        ),
        (
            WalEntryPayload::PpoiStatus {
                list_key: [0xBB; 32],
                blinded_commitment: [0xCC; 32],
                status: 3,
            },
            ppoi_status,
        ),
        (
            WalEntryPayload::PpoiListLeafAdded {
                list_key: [0xDD; 32],
                list_index: 0x2122_2324,
                blinded_commitment: [0xEE; 32],
                status: 2,
                event_type: PpoiEventType::Shield,
                signature: vec![0xAB; 64],
                validated_merkleroot: [0xAC; 32],
            },
            list_leaf_added,
        ),
        (
            WalEntryPayload::Reorg {
                height: 0x3132_3334_3536_3738,
            },
            reorg,
        ),
        (
            WalEntryPayload::Heartbeat {
                wallclock_unix_ms: 0x4142_4344_4546_4748,
            },
            heartbeat,
        ),
    ]
}

#[test]
fn wal_entry_payload_encodes_to_the_pinned_bytes() {
    for (payload, expected) in wal_payload_vectors() {
        let encoded = bincode::serialize(&payload).expect("serialize");
        assert_eq!(
            encoded, expected,
            "WAL payload encoding changed for {payload:?}; every frame an older build \
             wrote now decodes as something else"
        );
    }
}

/// The direction that actually runs at recovery: bytes an older build left on disk must
/// still decode to the variant that wrote them. A serialize-only pin passes even when
/// both halves moved together.
#[test]
fn pinned_bytes_decode_back_to_the_variant_that_wrote_them() {
    for (expected, bytes) in wal_payload_vectors() {
        let decoded: WalEntryPayload = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(
            decoded, expected,
            "on-disk WAL bytes no longer decode to the variant they were written from"
        );
    }
}

/// Distinct tags, and no variant's encoding is a prefix of another's - either would let a
/// torn or reordered frame decode as a neighbour instead of failing.
#[test]
fn every_variant_carries_a_distinct_tag() {
    let vectors = wal_payload_vectors();
    let mut tags: Vec<[u8; 4]> = Vec::with_capacity(vectors.len());
    for (_, bytes) in &vectors {
        assert!(bytes.len() >= 4, "every encoding carries a 4-byte tag");
        tags.push([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    let mut sorted = tags.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), tags.len(), "two variants share a bincode tag");
}
