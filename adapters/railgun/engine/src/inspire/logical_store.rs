//! Railgun logical rows and IMTs, independent of InsPIRe server state.
//! `materialize_shard_bytes` is the seam into scheme-specific re-encoding.

use crate::Result;
use raven_railgun_core::AdapterError;

/// Materialize a shard buffer: row-major `entries_per_shard x entry_size`,
/// each row `commitment_hash` (32 B) then zero fill.
#[must_use]
pub fn materialize_shard_bytes(
    store: &LogicalLeafStore,
    shard_id: u32,
    entries_per_shard: u32,
    entry_size: usize,
    tree_number: u32,
) -> Vec<u8> {
    let eps = entries_per_shard as usize;
    let total_bytes = eps.saturating_mul(entry_size);
    let mut buf = vec![0u8; total_bytes];
    let shard_start_global = u64::from(shard_id) * u64::from(entries_per_shard);
    let shard_end_global = shard_start_global + u64::from(entries_per_shard);

    // Row index is the leaf index alone, and the tree is a FILTER rather than part of the
    // index. The invariant lives in the encoder's `tree_number` pin, NOT in the router:
    // the multi-instance path scopes by route table but `indexer_to_consumer_bridge` on
    // the single-instance path forwards every tree, so a store can hold more than one.
    // Folding the tree into the index instead would shift an already-tree-local leaf out
    // of its own cell; ignoring it entirely would let a foreign tree overwrite this row.
    for ((tree, leaf), commitment) in store.leaves_iter() {
        if *tree != tree_number {
            continue;
        }
        let global = u64::from(*leaf);
        if global < shard_start_global || global >= shard_end_global {
            continue;
        }
        let in_shard_idx = usize::try_from(global - shard_start_global).unwrap_or(usize::MAX);
        let row_start = in_shard_idx.saturating_mul(entry_size);
        let copy_len = commitment.len().min(entry_size);
        if let (Some(dst), Some(src)) = (
            buf.get_mut(row_start..row_start.saturating_add(copy_len)),
            commitment.get(..copy_len),
        ) {
            dst.copy_from_slice(src);
        }
    }
    buf
}

/// BN254 scalar field modulus, big-endian. IMT leaves are Poseidon field
/// elements, so bytes at or above this never hash.
const BN254_FR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

#[derive(Clone, Copy)]
enum ImtSlot {
    CommitmentTree(u32),
    PpoiList,
}

impl ImtSlot {
    const fn index_field(self) -> &'static str {
        match self {
            Self::CommitmentTree(_) => "leaf_index",
            Self::PpoiList => "list_index",
        }
    }

    fn non_canonical_leaf(self, index: u32, leaf: &[u8; 32]) -> AdapterError {
        let field = self.index_field();
        AdapterError::InvalidQuery(format!(
            "non-canonical Fr leaf at {field} {index}: {leaf:02x?} is at or above \
             the BN254 scalar modulus"
        ))
    }

    fn non_contiguous(self, expected: usize, got: u32) -> AdapterError {
        AdapterError::InvalidQuery(match self {
            Self::CommitmentTree(tree_number) => format!(
                "non-contiguous AppendLeaf: tree {tree_number} expected leaf_index \
                 {expected}, got {got}"
            ),
            Self::PpoiList => format!(
                "non-contiguous PpoiListLeafAdded: list expected list_index \
                 {expected}, got {got}"
            ),
        })
    }
}

/// Everything the IMT would refuse, refused before the WAL write. Capacity is
/// judged on the index alone so the refusal does not depend on store state.
fn checked_imt_append(
    slot: ImtSlot,
    index: u32,
    expected: usize,
    leaf: &[u8; 32],
) -> Result<usize> {
    let field = slot.index_field();
    let index_usize = usize::try_from(index)
        .map_err(|_| AdapterError::InvalidQuery(format!("{field} {index} out of usize range")))?;
    if index_usize >= crate::imt::TREE_MAX_ITEMS {
        return Err(AdapterError::InvalidQuery(format!(
            "{field} {index} is at or past IMT capacity {}",
            crate::imt::TREE_MAX_ITEMS
        )));
    }
    if index_usize != expected {
        return Err(slot.non_contiguous(expected, index));
    }
    if leaf >= &BN254_FR_MODULUS_BE {
        return Err(slot.non_canonical_leaf(index, leaf));
    }
    Ok(index_usize)
}

/// Refuse a payload carrying an IMT leaf that is not a canonical BN254 Fr
/// element. WAL replay runs this before [`apply_wal_entry`]: the value can never
/// hash, so skipping the entry would leave the tree permanently short a leaf and
/// fail the contiguity screen for every later entry on that tree.
///
/// # Errors
/// [`AdapterError::InvalidQuery`] if the payload's leaf is at or above the BN254
/// scalar modulus.
///
/// ```
/// # use raven_railgun_engine::inspire::ensure_canonical_leaf;
/// # use raven_railgun_persistence::WalEntryPayload;
/// let heartbeat = WalEntryPayload::Heartbeat { wallclock_unix_ms: 0 };
/// assert!(ensure_canonical_leaf(&heartbeat).is_ok());
/// ```
pub fn ensure_canonical_leaf(payload: &raven_railgun_persistence::WalEntryPayload) -> Result<()> {
    use raven_railgun_persistence::WalEntryPayload as P;
    let (slot, index, leaf) = match payload {
        P::AppendLeaf {
            tree_number,
            leaf_index,
            commitment,
        } => (
            ImtSlot::CommitmentTree(*tree_number),
            *leaf_index,
            commitment,
        ),
        P::PpoiListLeafAdded {
            list_index,
            blinded_commitment,
            ..
        } => (ImtSlot::PpoiList, *list_index, blinded_commitment),
        P::PpoiStatus { .. } | P::Reorg { .. } | P::Heartbeat { .. } => return Ok(()),
    };
    if leaf >= &BN254_FR_MODULUS_BE {
        return Err(slot.non_canonical_leaf(index, leaf));
    }
    Ok(())
}

/// Sidecar logical-state store; accumulates chain rows and marks shards dirty
/// so commit re-encodes only those. Rebuilt from WAL replay on bootstrap.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogicalLeafStore {
    leaves: std::collections::BTreeMap<(u32, u32), [u8; 32]>,
    ppoi_status: std::collections::BTreeMap<([u8; 32], [u8; 32]), u8>,
    dirty_shards: std::collections::BTreeSet<u32>,
    last_block_height: u64,
    leaf_block_height: std::collections::BTreeMap<(u32, u32), u64>,
    ppoi_block_height: std::collections::BTreeMap<([u8; 32], [u8; 32]), u64>,
    imts: std::collections::HashMap<u32, crate::imt::Imt>,
    ppoi_imts: std::collections::HashMap<[u8; 32], crate::imt::Imt>,
    ppoi_bc_index: std::collections::BTreeMap<([u8; 32], [u8; 32]), u32>,
    ppoi_index_bc: std::collections::BTreeMap<([u8; 32], u32), [u8; 32]>,
    ppoi_list_leaf_block_height: std::collections::BTreeMap<([u8; 32], u32), u64>,
}

impl LogicalLeafStore {
    /// Build an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one WAL payload. Logical mutation only; does not touch `encoded_db`.
    #[allow(clippy::too_many_lines)]
    pub fn apply(
        &mut self,
        payload: &raven_railgun_persistence::WalEntryPayload,
        block_height: u64,
        encoder: &dyn crate::pir_table::PirTableEncoder,
    ) -> Result<()> {
        use raven_railgun_persistence::WalEntryPayload as P;
        match payload {
            P::AppendLeaf {
                tree_number,
                leaf_index,
                commitment,
            } => {
                let expected_idx = self
                    .imts
                    .get(tree_number)
                    .map_or(0, crate::imt::Imt::leaf_count);
                let leaf_idx_usize = checked_imt_append(
                    ImtSlot::CommitmentTree(*tree_number),
                    *leaf_index,
                    expected_idx,
                    commitment,
                )?;

                let imt = match self.imts.entry(*tree_number) {
                    std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
                    std::collections::hash_map::Entry::Vacant(v) => {
                        v.insert(crate::imt::Imt::new()?)
                    }
                };
                imt.insert_leaves(leaf_idx_usize, &[*commitment])?;
                let key = (*tree_number, *leaf_index);
                self.leaves.insert(key, *commitment);
                self.leaf_block_height.insert(key, block_height);
                self.dirty_shards
                    .extend(encoder.affected_shards_for_leaf(*tree_number, *leaf_index));
            }
            P::PpoiStatus {
                list_key,
                blinded_commitment,
                status,
            } => {
                let key = (*list_key, *blinded_commitment);
                self.ppoi_status.insert(key, *status);
                self.ppoi_block_height.insert(key, block_height);
                // A status has a row only after its BC is indexed.
                if let Some(list_index) = self.ppoi_bc_index.get(&key).copied() {
                    self.dirty_shards
                        .extend(encoder.affected_shards_for_ppoi_leaf(list_key, list_index));
                }
            }
            P::PpoiListLeafAdded {
                list_key,
                list_index,
                blinded_commitment,
                status,
            } => {
                let expected_idx = self
                    .ppoi_imts
                    .get(list_key)
                    .map_or(0, crate::imt::Imt::leaf_count);
                let leaf_idx_usize = checked_imt_append(
                    ImtSlot::PpoiList,
                    *list_index,
                    expected_idx,
                    blinded_commitment,
                )?;
                let imt = match self.ppoi_imts.entry(*list_key) {
                    std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
                    std::collections::hash_map::Entry::Vacant(v) => {
                        v.insert(crate::imt::Imt::new()?)
                    }
                };
                imt.insert_leaves(leaf_idx_usize, &[*blinded_commitment])?;
                let bc_key = (*list_key, *blinded_commitment);
                let idx_key = (*list_key, *list_index);
                self.ppoi_bc_index.insert(bc_key, *list_index);
                self.ppoi_index_bc.insert(idx_key, *blinded_commitment);
                self.ppoi_status.insert(bc_key, *status);
                self.ppoi_block_height.insert(bc_key, block_height);
                self.ppoi_list_leaf_block_height
                    .insert(idx_key, block_height);
                self.dirty_shards
                    .extend(encoder.affected_shards_for_ppoi_leaf(list_key, *list_index));
            }
            P::Reorg { height } => {
                let stale_leaves: Vec<(u32, u32)> = self
                    .leaf_block_height
                    .iter()
                    .filter(|(_, &h)| h > *height)
                    .map(|(k, _)| *k)
                    .collect();
                let mut affected_trees: std::collections::BTreeSet<u32> =
                    std::collections::BTreeSet::new();
                for key in stale_leaves {
                    let (tree_number, leaf_index) = key;
                    self.leaves.remove(&key);
                    self.leaf_block_height.remove(&key);
                    self.dirty_shards
                        .extend(encoder.affected_shards_for_leaf(tree_number, leaf_index));
                    affected_trees.insert(tree_number);
                }
                // Surviving count = max remaining leaf_index + 1, scoped to one tree.
                for tree in &affected_trees {
                    let new_count: usize = match self
                        .leaves
                        .range((*tree, 0u32)..(tree.saturating_add(1), 0u32))
                        .next_back()
                    {
                        Some(((_, last_idx), _)) => {
                            usize::try_from(last_idx.saturating_add(1)).unwrap_or(usize::MAX)
                        }
                        None => 0,
                    };
                    if let Some(imt) = self.imts.get_mut(tree) {
                        imt.truncate_to(new_count);
                    }
                }
                let stale_ppoi: Vec<([u8; 32], [u8; 32])> = self
                    .ppoi_block_height
                    .iter()
                    .filter(|(_, &h)| h > *height)
                    .map(|(k, _)| *k)
                    .collect();
                for key in stale_ppoi {
                    self.ppoi_status.remove(&key);
                    self.ppoi_block_height.remove(&key);
                }

                let stale_list_leaves: Vec<([u8; 32], u32)> = self
                    .ppoi_list_leaf_block_height
                    .iter()
                    .filter(|(_, &h)| h > *height)
                    .map(|(k, _)| *k)
                    .collect();
                let mut affected_lists: std::collections::BTreeSet<[u8; 32]> =
                    std::collections::BTreeSet::new();
                for key in stale_list_leaves {
                    let (list_key, list_index) = key;
                    self.ppoi_list_leaf_block_height.remove(&key);
                    if let Some(bc) = self.ppoi_index_bc.remove(&key) {
                        self.ppoi_bc_index.remove(&(list_key, bc));
                    }
                    self.dirty_shards
                        .extend(encoder.affected_shards_for_ppoi_leaf(&list_key, list_index));
                    affected_lists.insert(list_key);
                }
                for list_key in &affected_lists {
                    let new_count: usize = match self
                        .ppoi_index_bc
                        .range((*list_key, 0u32)..)
                        .take_while(|((lk, _), _)| lk == list_key)
                        .last()
                    {
                        Some(((_, last_idx), _)) => {
                            usize::try_from(last_idx.saturating_add(1)).unwrap_or(usize::MAX)
                        }
                        None => 0,
                    };
                    if let Some(imt) = self.ppoi_imts.get_mut(list_key) {
                        imt.truncate_to(new_count);
                    }
                }
            }
            P::Heartbeat { .. } => {}
        }
        self.last_block_height = self.last_block_height.max(block_height);
        Ok(())
    }

    /// Number of leaves currently tracked.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Iterator over all leaves in deterministic `BTreeMap` order.
    pub fn leaves_iter(&self) -> impl Iterator<Item = (&(u32, u32), &[u8; 32])> {
        self.leaves.iter()
    }

    /// Number of PPOI rows currently tracked.
    #[must_use]
    pub fn ppoi_count(&self) -> usize {
        self.ppoi_status.len()
    }

    /// Set of shard ids with pending re-encode work.
    #[must_use]
    pub fn dirty_shards(&self) -> &std::collections::BTreeSet<u32> {
        &self.dirty_shards
    }

    /// Highest block_height seen by `apply`.
    #[must_use]
    pub fn last_block_height(&self) -> u64 {
        self.last_block_height
    }

    /// Look up a leaf by (tree, leaf_index).
    #[must_use]
    pub fn leaf(&self, tree_number: u32, leaf_index: u32) -> Option<&[u8; 32]> {
        self.leaves.get(&(tree_number, leaf_index))
    }

    /// Look up a PPOI status row.
    #[must_use]
    pub fn ppoi_status(&self, list_key: &[u8; 32], blinded_commitment: &[u8; 32]) -> Option<u8> {
        self.ppoi_status
            .get(&(*list_key, *blinded_commitment))
            .copied()
    }

    /// Per-list IMT for `list_key`, or `None` if no leaves applied yet.
    #[must_use]
    pub fn ppoi_imt(&self, list_key: &[u8; 32]) -> Option<&crate::imt::Imt> {
        self.ppoi_imts.get(list_key)
    }

    /// Current root of the per-list IMT, or `None` if no leaves yet.
    #[must_use]
    pub fn ppoi_imt_root(&self, list_key: &[u8; 32]) -> Option<[u8; 32]> {
        self.ppoi_imts.get(list_key).map(crate::imt::Imt::root)
    }

    /// Number of distinct PPOI lists with at least one applied leaf.
    #[must_use]
    pub fn ppoi_list_count(&self) -> usize {
        self.ppoi_imts.len()
    }

    /// Per-list `(blinded_commitment -> list_index)` lookup.
    #[must_use]
    pub fn ppoi_index_of(&self, list_key: &[u8; 32], blinded_commitment: &[u8; 32]) -> Option<u32> {
        self.ppoi_bc_index
            .get(&(*list_key, *blinded_commitment))
            .copied()
    }

    /// Per-list `(list_index -> blinded_commitment)` lookup.
    #[must_use]
    pub fn ppoi_bc_at(&self, list_key: &[u8; 32], list_index: u32) -> Option<[u8; 32]> {
        self.ppoi_index_bc.get(&(*list_key, list_index)).copied()
    }

    /// Per-list `(list_index -> status_byte)` derived view.
    #[must_use]
    pub fn ppoi_status_at(&self, list_key: &[u8; 32], list_index: u32) -> Option<u8> {
        let bc = self.ppoi_bc_at(list_key, list_index)?;
        self.ppoi_status(list_key, &bc)
    }

    /// Iterator over per-list leaves in ascending `list_index` order.
    pub fn ppoi_list_leaves_iter(
        &self,
        list_key: &[u8; 32],
    ) -> impl Iterator<Item = (u32, &[u8; 32])> {
        let lk = *list_key;
        self.ppoi_index_bc
            .range((lk, 0u32)..)
            .take_while(move |((k, _), _)| *k == lk)
            .map(|((_, idx), bc)| (*idx, bc))
    }

    /// Merkle auth path for `(list_key, list_index)`.
    ///
    /// # Errors
    /// [`AdapterError::InvalidQuery`] if no IMT exists or the index is out of range.
    pub fn ppoi_merkle_proof(
        &self,
        list_key: &[u8; 32],
        list_index: u32,
    ) -> Result<raven_railgun_core::MerkleProof> {
        let imt = self.ppoi_imts.get(list_key).ok_or_else(|| {
            AdapterError::InvalidQuery(format!(
                "no per-list IMT for list_key {list_key:?}; no leaves applied yet"
            ))
        })?;
        let idx = usize::try_from(list_index).map_err(|_| {
            AdapterError::InvalidQuery(format!("list_index {list_index} out of usize range"))
        })?;
        imt.merkle_proof(idx)
    }

    /// Drain the dirty-shards set after re-encoding.
    pub fn clear_dirty_shards(&mut self) {
        self.dirty_shards.clear();
    }

    /// Discard a shard id from the dirty set so the commit driver stops
    /// retrying a structurally-unencodable shard; transient errors leave it.
    pub fn drop_dirty_shard(&mut self, shard_id: u32) -> bool {
        self.dirty_shards.remove(&shard_id)
    }

    /// Test-only mutable access to the dirty-shards set for seeding out-of-range ids.
    #[cfg(test)]
    pub fn dirty_shards_mut_for_test(&mut self) -> &mut std::collections::BTreeSet<u32> {
        &mut self.dirty_shards
    }

    /// Merkle auth path for `(tree_number, leaf_index)`.
    ///
    /// # Errors
    /// [`AdapterError::InvalidQuery`] if no IMT exists or the index is out of range.
    pub fn merkle_proof(
        &self,
        tree_number: u32,
        leaf_index: u32,
    ) -> Result<raven_railgun_core::MerkleProof> {
        let imt = self.imts.get(&tree_number).ok_or_else(|| {
            AdapterError::InvalidQuery(format!(
                "no IMT for tree {tree_number}; no leaves applied yet"
            ))
        })?;
        let idx = usize::try_from(leaf_index).map_err(|_| {
            AdapterError::InvalidQuery(format!("leaf_index {leaf_index} out of usize range"))
        })?;
        imt.merkle_proof(idx)
    }

    /// Current root of the per-tree IMT, or `None` if no leaves applied yet.
    #[must_use]
    pub fn imt_root(&self, tree_number: u32) -> Option<[u8; 32]> {
        self.imts.get(&tree_number).map(crate::imt::Imt::root)
    }

    /// Number of trees with at least one applied leaf.
    #[must_use]
    pub fn imt_tree_count(&self) -> usize {
        self.imts.len()
    }

    /// Current leaf count for `tree_number`'s IMT, or 0 if no leaves applied yet.
    #[must_use]
    pub fn imt_leaf_count_for(&self, tree_number: u32) -> usize {
        self.imts
            .get(&tree_number)
            .map_or(0, crate::imt::Imt::leaf_count)
    }

    /// Per-tree IMT, or `None` if no leaves applied yet.
    #[must_use]
    pub fn imt(&self, tree_number: u32) -> Option<&crate::imt::Imt> {
        self.imts.get(&tree_number)
    }
}

/// Apply a WAL payload to a [`LogicalLeafStore`]. Does not touch `encoded_db`.
pub fn apply_wal_entry(
    store: &mut LogicalLeafStore,
    payload: &raven_railgun_persistence::WalEntryPayload,
    block_height: u64,
    encoder: &dyn crate::pir_table::PirTableEncoder,
) -> Result<()> {
    store.apply(payload, block_height, encoder)
}

/// Non-mutating pre-check run before the WAL write. Screens the two IMT-backed
/// variants on index contiguity, tree capacity and leaf Fr-canonicity; the
/// other variants are unconditionally accepted. Runs the same screen
/// [`LogicalLeafStore::apply`] does, so a payload that passes here and is then
/// applied against the same store cannot be refused for one of those reasons.
///
/// # Errors
/// [`AdapterError::InvalidQuery`] on a non-contiguous index, an index at or
/// past IMT capacity, or a leaf at or above the BN254 scalar modulus.
pub fn validate_apply(
    store: &LogicalLeafStore,
    payload: &raven_railgun_persistence::WalEntryPayload,
) -> Result<()> {
    use raven_railgun_persistence::WalEntryPayload as P;
    match payload {
        P::AppendLeaf {
            tree_number,
            leaf_index,
            commitment,
        } => {
            checked_imt_append(
                ImtSlot::CommitmentTree(*tree_number),
                *leaf_index,
                store.imt_leaf_count_for(*tree_number),
                commitment,
            )?;
        }
        P::PpoiListLeafAdded {
            list_key,
            list_index,
            blinded_commitment,
            ..
        } => {
            let expected = store
                .ppoi_imt(list_key)
                .map_or(0, crate::imt::Imt::leaf_count);
            checked_imt_append(ImtSlot::PpoiList, *list_index, expected, blinded_commitment)?;
        }
        P::PpoiStatus { .. } | P::Reorg { .. } | P::Heartbeat { .. } => {}
    }
    Ok(())
}

/// Whether applying this payload APPENDS to an IMT.
///
/// The error run `/health/ready` gates on means leaf application is wedged, and only an IMT
/// append can close the contiguity gap that wedges it. A payload that mutates other store state
/// (`PpoiStatus` writes a status byte and dirties shards) says nothing about that gap, so
/// clearing the run on one reports a wedged tree as healthy.
///
/// Deliberately the same partition [`validate_apply`] screens on: these are exactly the variants
/// that reach `checked_imt_append`, and the two must not drift apart.
#[must_use]
pub(crate) fn appends_to_a_tree(payload: &raven_railgun_persistence::WalEntryPayload) -> bool {
    use raven_railgun_persistence::WalEntryPayload as P;
    match payload {
        P::AppendLeaf { .. } | P::PpoiListLeafAdded { .. } => true,
        P::PpoiStatus { .. } | P::Reorg { .. } | P::Heartbeat { .. } => false,
    }
}
