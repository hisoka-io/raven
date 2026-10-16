//! Synthetic leaves and a table fingerprint, for tests that need more rows than the chain
//! fixture holds.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use ark_bn254::Fr;
use howl_indexer::{Batch, Checkpoint, Leaf, TREE_DEPTH};
use howl_record::{encode, HowlNoteRecord, LAYOUT_VERSION, RECORD_KIND_INCOMING, RECORD_KIND_SELF};
use howl_store::{NoteStore, LEAF_BLOCK_ROWS};

pub const CHAIN_ID: u64 = 31_337;
pub const POOL: [u8; 20] = [0x5f; 20];

/// Bytes distinct per `(index, field)`, so a shifted or aliased row cannot compare equal.
fn word(index: u64, field: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut state = index
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(u64::from(field) << 56)
        | 1;
    for byte in out.iter_mut().skip(1) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }
    out
}

fn scalar(index: u64, field: u8) -> Fr {
    use ark_ff::PrimeField;
    Fr::from_be_bytes_mod_order(&word(index, field))
}

pub fn leaf(index: u64) -> Leaf {
    let commitment = word(index, 1);
    let incoming = index.is_multiple_of(3);
    let record = HowlNoteRecord {
        layout_version: LAYOUT_VERSION,
        record_kind: if incoming {
            RECORD_KIND_INCOMING
        } else {
            RECORD_KIND_SELF
        },
        leaf_index: u32::try_from(index).expect("u32"),
        commitment_prefix: commitment[..16].try_into().expect("16 bytes"),
        ephemeral_pk_x: if incoming {
            scalar(index, 2)
        } else {
            Fr::from(0u64)
        },
        cek_wrap: if incoming {
            scalar(index, 3)
        } else {
            Fr::from(0u64)
        },
        ciphertext_kept: [4, 5, 6, 7, 8].map(|field| scalar(index, field)),
    };
    Leaf {
        leaf_index: record.leaf_index,
        commitment,
        tag: Some(word(index, 9)),
        cell: encode(&record),
    }
}

/// Leaves `first..first + count`, with a checkpoint that names the table they produce.
pub fn batch(first: u64, count: usize, block: u64) -> Batch {
    let leaf_count = first + count as u64;
    Batch {
        leaves: (first..leaf_count).map(leaf).collect(),
        checkpoint: Checkpoint {
            leaf_count,
            final_block: Some(block),
            root: word(leaf_count, 10),
            frontier: [word(leaf_count, 11); TREE_DEPTH],
        },
        held_back: 0,
    }
}

/// Batches of the given sizes, back to back from leaf 0.
pub fn schedule(sizes: &[usize]) -> Vec<Batch> {
    let mut first = 0;
    sizes
        .iter()
        .enumerate()
        .map(|(block, size)| {
            let made = batch(first, *size, 1_000 + block as u64);
            first += *size as u64;
            made
        })
        .collect()
}

/// Everything a reader can observe of a table.
#[derive(Debug, PartialEq, Eq)]
pub struct Fingerprint {
    pub leaf_count: u64,
    pub resume: Checkpoint,
    pub shards: Vec<(u32, [u8; 32], Vec<u8>)>,
    pub prefixes: Vec<u8>,
    pub leaves: Vec<u8>,
}

pub fn fingerprint(store: &NoteStore) -> Fingerprint {
    let shards = (0..store.shard_count())
        .map(|index| {
            let shard = store.shard(index).expect("shard");
            (shard.rows, shard.digest, shard.cells)
        })
        .collect();
    let mut prefixes = Vec::new();
    loop {
        let part = store
            .prefix_segment((prefixes.len() / 6) as u64)
            .expect("segment");
        prefixes.extend_from_slice(part.rows);
        if part.is_frontier() {
            break;
        }
    }
    let mut leaves = Vec::new();
    for block in 0..=store.leaf_count() / LEAF_BLOCK_ROWS as u64 {
        leaves.extend_from_slice(store.leaf_block(u32::try_from(block).expect("u32")).leaves);
    }
    Fingerprint {
        leaf_count: store.leaf_count(),
        resume: store.resume_point().clone(),
        shards,
        prefixes,
        leaves,
    }
}

/// The table one uninterrupted store holds after each of `batches`.
pub fn references(batches: &[Batch]) -> Vec<Fingerprint> {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = NoteStore::open(dir.path(), CHAIN_ID, POOL).expect("open");
    batches
        .iter()
        .map(|batch| {
            store.append(batch).expect("append");
            fingerprint(&store)
        })
        .collect()
}
