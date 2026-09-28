//! A contiguous run appended in one call must leave every stored node, and the root, byte for
//! byte where per-leaf insertion leaves them, and a non-canonical leaf anywhere in a run must
//! leave the tree untouched. The same holds one level up for `LogicalLeafStore::seed_leaf_run`
//! against `apply` row by row.
//!
//! State is compared through the serialized form, decoded into mirrors whose hash maps become
//! sorted vectors, so a node stored on one side and absent on the other is a failure even where
//! `Imt::node` would return the zero hash for both.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

mod naive_imt;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use proptest::prelude::*;
use proptest::sample::Index;
use raven_railgun_core::AdapterError;
use raven_railgun_engine::imt::{Imt, TREE_DEPTH, TREE_MAX_ITEMS};
use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::{
    PerLeafCommitmentEncoder, PerListPath10Encoder, PirTableEncoder,
};
use raven_railgun_persistence::{PpoiEventMetadata, PpoiEventType, WalEntryPayload};
use serde::{Deserialize, Serialize};

const NON_CANONICAL: [u8; 32] = [0xff; 32];
const LIST_KEY: [u8; 32] = [0x5e; 32];
const TREE: u32 = 3;
/// Four rows a shard: a run spans many shards, so a dirty set that diverges between the two
/// paths shows. At the shipped 2,048 every row of these runs would land in shard 0.
const ROWS_PER_SHARD: u32 = 4;

/// `Imt` as bincode lays it out, with each level's hash map read as a vector of entries.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct ImtMirror {
    leaf_count: usize,
    nodes: Vec<Vec<(usize, [u8; 32])>>,
    zeros: [[u8; 32]; TREE_DEPTH + 1],
}

impl ImtMirror {
    fn sorted(mut self) -> Self {
        for level in &mut self.nodes {
            level.sort_unstable();
        }
        self
    }
}

/// `LogicalLeafStore` as bincode lays it out; the two `serde(skip)` fields are not on the wire.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct StoreMirror {
    leaves: BTreeMap<(u32, u32), [u8; 32]>,
    dirty_shards: BTreeSet<u32>,
    last_block_height: u64,
    leaf_block_height: BTreeMap<(u32, u32), u64>,
    imts: Vec<(u32, ImtMirror)>,
    ppoi_imts: Vec<([u8; 32], ImtMirror)>,
    ppoi_bc_indices: BTreeSet<([u8; 32], [u8; 32], u32)>,
    ppoi_index_bc: BTreeMap<([u8; 32], u32), [u8; 32]>,
    ppoi_event_metadata: BTreeMap<([u8; 32], u32), PpoiEventMetadata>,
    ppoi_list_leaf_block_height: BTreeMap<([u8; 32], u32), u64>,
}

fn decode<T: Serialize, M: for<'a> Deserialize<'a>>(value: &T) -> (Vec<u8>, M) {
    let bytes = bincode::serialize(value).expect("encode");
    let decoded = raven_railgun_persistence::decode_no_trailing(&bytes).expect("mirror decode");
    (bytes, decoded)
}

/// Decodes `value`'s bincode into `M`, and proves `M` covers every byte by re-encoding it.
fn exact_mirror<T: Serialize, M: Serialize + for<'a> Deserialize<'a>>(value: &T) -> M {
    let (bytes, decoded) = decode::<T, M>(value);
    assert_eq!(
        bincode::serialize(&decoded).expect("re-encode"),
        bytes,
        "the mirror no longer matches the serialized layout"
    );
    decoded
}

fn imt_state(tree: &Imt) -> ImtMirror {
    decode::<_, ImtMirror>(tree).1.sorted()
}

fn store_state(store: &LogicalLeafStore) -> StoreMirror {
    let mut state: StoreMirror = exact_mirror(store);
    state.imts = state
        .imts
        .into_iter()
        .map(|(k, imt)| (k, imt.sorted()))
        .collect();
    state.imts.sort_unstable_by_key(|(k, _)| *k);
    state.ppoi_imts = state
        .ppoi_imts
        .into_iter()
        .map(|(k, imt)| (k, imt.sorted()))
        .collect();
    state.ppoi_imts.sort_unstable_by_key(|(k, _)| *k);
    state
}

fn leaf(i: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[3] = 0x11;
    out[24..].copy_from_slice(&(i as u64).to_be_bytes());
    out
}

fn leaves(range: std::ops::Range<usize>) -> Vec<[u8; 32]> {
    range.map(leaf).collect()
}

fn batch_tree(count: usize) -> Imt {
    let mut tree = Imt::new().expect("imt");
    if count > 0 {
        tree.insert_leaves(0, &leaves(0..count))
            .expect("batch seed");
    }
    tree
}

/// Starting points shared by both sides of a case. They cover a start at every alignment
/// the upper levels see, up to a run that ends exactly at capacity.
const BASES: [usize; 5] = [0, 1, 2_047, 32_767, 65_500];

fn base(which: usize) -> Imt {
    static TREES: OnceLock<Vec<Imt>> = OnceLock::new();
    TREES.get_or_init(|| {
        let largest = batch_tree(BASES[BASES.len() - 1]);
        BASES
            .iter()
            .map(|&n| {
                let mut tree = largest.clone();
                tree.truncate_to(n);
                tree
            })
            .collect()
    })[which]
        .clone()
}

fn canonical_leaf() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>().prop_map(|mut b| {
        b[0] %= 0x30;
        b
    })
}

#[derive(Debug, Clone)]
struct ImtCase {
    base: usize,
    truncate_by: usize,
    run: Vec<[u8; 32]>,
    chunks: Vec<usize>,
    bad: Option<(Index, Index)>,
}

fn imt_case() -> impl Strategy<Value = ImtCase> {
    (
        prop_oneof![4 => Just(0usize), 4 => Just(1), 4 => Just(2), 1 => Just(3), 1 => Just(4)],
        prop_oneof![3 => Just(0usize), 1 => 1usize..=40],
        prop::collection::vec(canonical_leaf(), 1..=48),
        prop::collection::vec(1usize..=17, 1..=48),
        prop::option::weighted(0.3, any::<(Index, Index)>()),
    )
        .prop_map(|(base, truncate_by, run, chunks, bad)| ImtCase {
            base,
            truncate_by,
            run,
            chunks,
            bad,
        })
}

fn check_imt_case(case: &ImtCase) -> Result<(), TestCaseError> {
    let mut batched = base(case.base);
    let start = BASES[case.base].saturating_sub(case.truncate_by);
    batched.truncate_to(start);
    let mut per_leaf = batched.clone();

    let room = TREE_MAX_ITEMS - start;
    let run = &case.run[..case.run.len().min(room)];
    let mut chunks: Vec<std::ops::Range<usize>> = Vec::new();
    let mut at = 0;
    for &size in case.chunks.iter().cycle() {
        if at == run.len() {
            break;
        }
        let end = (at + size).min(run.len());
        chunks.push(at..end);
        at = end;
    }

    let bad = case.bad.as_ref().map(|(c, p)| {
        let chunk = &chunks[c.index(chunks.len())];
        chunk.start + p.index(chunk.len())
    });
    let mut run = run.to_vec();
    if let Some(at) = bad {
        run[at] = NON_CANONICAL;
    }

    let mut accepted = 0;
    for chunk in &chunks {
        let refused = bad.is_some_and(|at| chunk.contains(&at));
        let before = refused.then(|| imt_state(&batched));
        let outcome = batched.insert_leaves(start + chunk.start, &run[chunk.clone()]);
        if let Some(before) = before {
            prop_assert!(
                matches!(outcome, Err(AdapterError::Internal(_))),
                "{outcome:?}"
            );
            prop_assert_eq!(
                imt_state(&batched),
                before,
                "a refused run changed the tree"
            );
            break;
        }
        prop_assert!(outcome.is_ok(), "{outcome:?}");
        accepted = chunk.end;
    }
    for (offset, value) in run[..accepted].iter().enumerate() {
        per_leaf
            .insert_leaves(start + offset, std::slice::from_ref(value))
            .expect("per-leaf insert");
    }
    prop_assert_eq!(batched.root(), per_leaf.root());
    prop_assert_eq!(imt_state(&batched), imt_state(&per_leaf));
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn a_run_in_random_batches_matches_per_leaf_insertion(case in imt_case()) {
        check_imt_case(&case)?;
    }
}

/// Every node of every level, as per-leaf insertion stores it: exactly the indices whose
/// subtree holds a leaf.
fn naive_state(count: usize) -> ImtMirror {
    let zeros = naive_imt::zero_chain();
    let levels = naive_imt::naive_levels(&leaves(0..count), &zeros);
    ImtMirror {
        leaf_count: count,
        nodes: levels
            .into_iter()
            .map(|level| level.into_iter().enumerate().collect())
            .collect(),
        zeros,
    }
}

#[test]
fn the_capacity_edges_match_the_naive_rebuild_at_every_node() {
    let full = batch_tree(TREE_MAX_ITEMS);
    let _: ImtMirror = exact_mirror(&full);
    assert_eq!(imt_state(&full), naive_state(TREE_MAX_ITEMS));

    let mut two_short = full.clone();
    two_short.truncate_to(TREE_MAX_ITEMS - 2);
    let before = imt_state(&two_short);
    for refused in [
        vec![leaf(TREE_MAX_ITEMS - 2), NON_CANONICAL],
        vec![NON_CANONICAL, leaf(TREE_MAX_ITEMS - 1)],
        leaves(TREE_MAX_ITEMS - 2..TREE_MAX_ITEMS + 1),
    ] {
        two_short
            .insert_leaves(TREE_MAX_ITEMS - 2, &refused)
            .expect_err("non-canonical, or past capacity");
        assert_eq!(imt_state(&two_short), before);
    }
    for slot in TREE_MAX_ITEMS - 2..TREE_MAX_ITEMS {
        two_short
            .insert_leaves(slot, &[leaf(slot)])
            .expect("the last slots, per leaf");
    }
    assert_eq!(imt_state(&two_short), imt_state(&full));
    assert_eq!(two_short.root(), full.root());

    let err = Imt::new()
        .expect("imt")
        .insert_leaves(0, &leaves(0..TREE_MAX_ITEMS + 1))
        .expect_err("one leaf past capacity");
    assert!(matches!(err, AdapterError::InvalidQuery(_)), "{err:?}");
}

#[test]
fn a_non_canonical_leaf_at_either_end_of_a_full_run_leaves_the_tree_untouched() {
    for at in [0, TREE_MAX_ITEMS - 1] {
        let mut run = leaves(0..TREE_MAX_ITEMS);
        run[at] = NON_CANONICAL;
        let mut tree = Imt::new().expect("imt");
        let before = imt_state(&tree);
        let err = tree.insert_leaves(0, &run).expect_err("non-canonical leaf");
        assert!(matches!(err, AdapterError::Internal(_)), "{err:?}");
        assert_eq!(imt_state(&tree), before, "leaf {at}");
    }
}

// -- LogicalLeafStore::seed_leaf_run against apply, row by row --------------------------------

fn ppoi_row(list_index: u32, bc: [u8; 32], tag: u8) -> WalEntryPayload {
    WalEntryPayload::PpoiListLeafAdded {
        list_key: LIST_KEY,
        list_index,
        blinded_commitment: bc,
        status: 0,
        event_type: PpoiEventType::Shield,
        signature: Vec::new(),
        validated_merkleroot: [tag; 32],
    }
}

fn tree_row(leaf_index: u32, commitment: [u8; 32]) -> WalEntryPayload {
    WalEntryPayload::AppendLeaf {
        tree_number: TREE,
        leaf_index,
        commitment,
    }
}

#[derive(Debug, Clone, Copy)]
enum Planted {
    NonCanonical,
    Gap,
    ForeignTree,
}

#[derive(Debug, Clone)]
struct StoreCase {
    ppoi: bool,
    prior: usize,
    // A small pool so commitments recur within a list, which upstream permits.
    run: Vec<(u8, u8)>,
    heights: Vec<u64>,
    planted: Option<(Index, Planted)>,
}

fn store_case() -> impl Strategy<Value = StoreCase> {
    (
        any::<bool>(),
        0usize..=8,
        prop::collection::vec((0u8..6, 0u8..3), 1..=40),
        prop::collection::vec(1u64..50, 48),
        prop::option::weighted(
            0.4,
            (
                any::<Index>(),
                prop_oneof![
                    Just(Planted::NonCanonical),
                    Just(Planted::Gap),
                    Just(Planted::ForeignTree),
                ],
            ),
        ),
    )
        .prop_map(|(ppoi, prior, run, heights, planted)| StoreCase {
            ppoi,
            prior,
            run,
            heights,
            planted,
        })
}

fn pool_leaf(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[8] = seed;
    out[31] = 0x01;
    out
}

fn check_store_case(case: &StoreCase) -> Result<(), TestCaseError> {
    let encoder: Box<dyn PirTableEncoder> = if case.ppoi {
        Box::new(PerListPath10Encoder::new(ROWS_PER_SHARD, LIST_KEY).expect("encoder"))
    } else {
        Box::new(PerLeafCommitmentEncoder::new(32, ROWS_PER_SHARD, TREE).expect("encoder"))
    };
    let row = |index: usize, (bc, tag): (u8, u8)| {
        let index = index as u32;
        if case.ppoi {
            ppoi_row(index, pool_leaf(bc), tag)
        } else {
            tree_row(index, pool_leaf(bc))
        }
    };
    let total = case.prior + case.run.len();
    let mut rows: Vec<(WalEntryPayload, u64)> = case
        .run
        .iter()
        .enumerate()
        .map(|(i, &spec)| (row(case.prior + i, spec), case.heights[i]))
        .collect();
    // A foreign row first would name the run's tree itself, so it goes after row 0.
    let planted = case.planted.and_then(|(at, kind)| match kind {
        Planted::ForeignTree if rows.len() < 2 => None,
        Planted::ForeignTree => Some((1 + at.index(rows.len() - 1), kind)),
        _ => Some((at.index(rows.len()), kind)),
    });
    if let Some((at, kind)) = planted {
        let index = case.prior + at;
        rows[at].0 = match (kind, &rows[at].0) {
            (Planted::NonCanonical, WalEntryPayload::AppendLeaf { .. }) => {
                tree_row(index as u32, NON_CANONICAL)
            }
            (Planted::NonCanonical, _) => ppoi_row(index as u32, NON_CANONICAL, 0),
            (Planted::Gap, _) => row(total + 1, (0, 0)),
            (Planted::ForeignTree, WalEntryPayload::AppendLeaf { .. }) => {
                WalEntryPayload::AppendLeaf {
                    tree_number: TREE + 1,
                    leaf_index: index as u32,
                    commitment: pool_leaf(1),
                }
            }
            (Planted::ForeignTree, _) => WalEntryPayload::PpoiListLeafAdded {
                list_key: [0x77; 32],
                list_index: index as u32,
                blinded_commitment: pool_leaf(1),
                status: 0,
                event_type: PpoiEventType::Shield,
                signature: vec![],
                validated_merkleroot: [0; 32],
            },
        };
    }

    let mut sequential = LogicalLeafStore::new();
    for i in 0..case.prior {
        apply_wal_entry(
            &mut sequential,
            &row(i, (i as u8 % 6, 0)),
            7,
            encoder.as_ref(),
        )
        .expect("prior row");
    }
    let mut seeded = sequential.clone();
    let before = store_state(&seeded);

    let mut first_refusal = None;
    for (payload, height) in &rows {
        if let Err(e) = apply_wal_entry(&mut sequential, payload, *height, encoder.as_ref()) {
            first_refusal = Some(e.to_string());
            break;
        }
    }
    let outcome = seeded.seed_leaf_run(&rows, encoder.as_ref());

    match planted {
        None => {
            prop_assert!(outcome.is_ok(), "{outcome:?}");
            prop_assert_eq!(store_state(&seeded), store_state(&sequential));
        }
        Some((_, kind)) => {
            let err = outcome.expect_err("a planted row refuses the run");
            prop_assert!(matches!(err, AdapterError::InvalidQuery(_)), "{err:?}");
            if matches!(kind, Planted::NonCanonical | Planted::Gap) {
                prop_assert_eq!(Some(err.to_string()), first_refusal);
            }
            prop_assert_eq!(
                store_state(&seeded),
                before,
                "a refused run changed the store"
            );
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn a_seeded_run_matches_apply_row_by_row(case in store_case()) {
        check_store_case(&case)?;
    }
}

/// The differential above compares the two paths with each other, so a defect in the bookkeeping
/// they share passes it. This holds a seeded run to the rows themselves.
#[test]
fn a_seeded_list_run_records_every_row_it_was_handed() {
    let encoder = PerListPath10Encoder::new(ROWS_PER_SHARD, LIST_KEY).expect("encoder");
    let rows: Vec<(WalEntryPayload, u64)> = (0..10u32)
        .map(|i| {
            (
                ppoi_row(i, pool_leaf(i as u8 % 4), i as u8),
                30 + u64::from(i),
            )
        })
        .collect();
    let mut store = LogicalLeafStore::new();
    store.seed_leaf_run(&rows, &encoder).expect("seed");
    let mut dirtied = BTreeSet::new();
    for i in 0..10u32 {
        let bc = pool_leaf(i as u8 % 4);
        assert_eq!(store.ppoi_bc_at(&LIST_KEY, i), Some(bc), "row {i}");
        assert!(
            store.ppoi_indices_of(&LIST_KEY, &bc).any(|at| at == i),
            "row {i}"
        );
        let meta = store.ppoi_event_metadata(&LIST_KEY, i).expect("metadata");
        assert_eq!(meta.validated_merkleroot, [i as u8; 32], "row {i}");
        dirtied.extend(encoder.affected_shards_for_ppoi_leaf(&LIST_KEY, i));
    }
    assert_eq!(store.dirty_shards(), &dirtied);
    assert_eq!(store.last_block_height(), 39);
}

#[test]
fn an_empty_run_is_a_no_op_and_a_non_leaf_first_row_is_refused() {
    let encoder = PerListPath10Encoder::new(ROWS_PER_SHARD, LIST_KEY).expect("encoder");
    let mut store = LogicalLeafStore::new();
    store.seed_leaf_run(&[], &encoder).expect("empty run");
    let before = store_state(&store);
    let heartbeat = WalEntryPayload::Heartbeat {
        wallclock_unix_ms: 0,
    };
    let err = store
        .seed_leaf_run(
            &[(heartbeat, 1), (ppoi_row(0, pool_leaf(1), 0), 1)],
            &encoder,
        )
        .expect_err("a heartbeat is not a leaf");
    assert!(matches!(err, AdapterError::InvalidQuery(_)), "{err:?}");
    assert_eq!(store_state(&store), before);
}
