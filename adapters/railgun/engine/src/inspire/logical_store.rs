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
    // index. The invariant lives in the encoder's `tree_number` pin, NOT in ingest: both
    // ingest paths scope by tree (route table, or `indexer_to_consumer_bridge`), but
    // `LogicalLeafStore::apply` takes any tree, so a store can hold more than one.
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
    // Inert under bincode, which is positional and carries no field names: inserting this
    // field mid-struct shifted every field after it. `LogicalLeafStoreV6` is what reads the
    // bytes written before it existed.
    #[serde(default)]
    ppoi_event_metadata:
        std::collections::BTreeMap<([u8; 32], u32), raven_railgun_persistence::PpoiEventMetadata>,
    ppoi_list_leaf_block_height: std::collections::BTreeMap<([u8; 32], u32), u64>,
    // Upper-sibling addenda as of the last PUBLISHED state, and the epoch they came from. The
    // served row comes from a snapshot while the addendum used to come from this live store,
    // which runs up to a commit cadence ahead (1000 appends / 300 s), so the pair could not be
    // shown to share a state. `serde(skip)`: in-memory only, never on a snapshot or the wire.
    #[serde(skip)]
    committed_addenda: std::collections::BTreeMap<([u8; 32], u32), Vec<u8>>,
    // The encoded database these addenda were derived alongside. THIS is tree provenance, not the
    // epoch: `heartbeat_session_eviction` bumps the epoch every session-eviction interval while
    // carrying `encoded_db` by `Arc::clone`, so an epoch equality check refuses a frozen block
    // forever one hour after boot. A commit replaces the Arc; a heartbeat does not.
    #[serde(skip)]
    committed_addenda_db: Option<std::sync::Arc<raven_inspire::EncodedDatabase>>,
}

/// The `LogicalLeafStore` shape every V6 snapshot on disk was written with, frozen.
///
/// Pinning the V6 read path to the *live* struct is what made a field insertion a data-loss
/// event: bincode is positional, so `ppoi_event_metadata` landing mid-struct reinterpreted
/// `ppoi_list_leaf_block_height`'s bytes as its own.
///
/// This is the shape rather than a guess: field names and types are unchanged at every commit
/// from the one that introduced `SNAPSHOT_V6_MAGIC` to the one before it broke. (The text is
/// not identical — one commit respelled `super::imt::Imt` as `crate::imt::Imt` — but the wire
/// is.) `TREE_DEPTH` is 16 throughout too, which matters because `ZeroValues.levels` is
/// `[[u8; 32]; TREE_DEPTH + 1]`: a change there would move the wire with no struct text
/// changing at all. `tests/fixtures/logical_store_v6.bin` pins the result to bytes.
///
/// **Do not edit this struct** — a V6 snapshot's shape is history, and a new field belongs in
/// `LogicalLeafStore` behind a new magic. Note the banner is not sufficient by itself: the
/// shape is transitively `Imt`'s and `ZeroValues`', so editing either moves V6's wire without
/// touching anything here. The fixture, not the banner, is what actually catches that.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct LogicalLeafStoreV6 {
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

impl LogicalLeafStoreV6 {
    /// Lossless *about the snapshot*: the retained-metadata field postdates every byte V6 ever
    /// wrote, so its absence is a fact rather than data dropped on the floor, and any other fill
    /// would be fabrication.
    ///
    /// It is NOT lossless about the store the engine then serves from. Every leaf the snapshot
    /// covered comes back without metadata, and only leaves replayed from the WAL afterwards get
    /// any — which is why `restore_inspire_state_v6` logs on this arm rather than healing
    /// silently.
    pub(crate) fn into_current(self) -> LogicalLeafStore {
        // Say it happened. A V6 reopen returns every per-list leaf without its retained
        // metadata, and the path encoder skips a row whose metadata is absent -- degraded
        // served content with, until this line, nothing at all in the log.
        if !self.ppoi_index_bc.is_empty() {
            tracing::warn!(
                target = "raven::engine::snapshot",
                list_leaves = self.ppoi_index_bc.len(),
                "V6 snapshot: retained PPOI event metadata is absent by construction; \
                 path-projection rows for leaves covered by this snapshot stay unfilled until \
                 they are re-ingested"
            );
        }
        LogicalLeafStore {
            leaves: self.leaves,
            ppoi_status: self.ppoi_status,
            dirty_shards: self.dirty_shards,
            last_block_height: self.last_block_height,
            leaf_block_height: self.leaf_block_height,
            ppoi_block_height: self.ppoi_block_height,
            imts: self.imts,
            ppoi_imts: self.ppoi_imts,
            ppoi_bc_index: self.ppoi_bc_index,
            ppoi_index_bc: self.ppoi_index_bc,
            ppoi_event_metadata: std::collections::BTreeMap::new(),
            ppoi_list_leaf_block_height: self.ppoi_list_leaf_block_height,
            committed_addenda: std::collections::BTreeMap::new(),
            committed_addenda_db: None,
        }
    }

    /// Refuses rather than writing a V6 snapshot that silently drops retained metadata --
    /// V6 has no field to put it in.
    pub(crate) fn try_from_current(store: &LogicalLeafStore) -> Result<Self> {
        if !store.ppoi_event_metadata.is_empty() {
            return Err(AdapterError::Serialization(format!(
                "refusing to write a V6 snapshot: the store carries {} retained PPOI event \
                 metadata entries and the V6 layout has no field for them. Write V7.",
                store.ppoi_event_metadata.len()
            )));
        }
        Ok(Self {
            leaves: store.leaves.clone(),
            ppoi_status: store.ppoi_status.clone(),
            dirty_shards: store.dirty_shards.clone(),
            last_block_height: store.last_block_height,
            leaf_block_height: store.leaf_block_height.clone(),
            ppoi_block_height: store.ppoi_block_height.clone(),
            imts: store.imts.clone(),
            ppoi_imts: store.ppoi_imts.clone(),
            ppoi_bc_index: store.ppoi_bc_index.clone(),
            ppoi_index_bc: store.ppoi_index_bc.clone(),
            ppoi_list_leaf_block_height: store.ppoi_list_leaf_block_height.clone(),
        })
    }

    /// Mints the shape a pre-`ppoi_event_metadata` build would have written for `store`.
    /// Fixture generation only: dropping the field is exactly what those builds did, because
    /// the field did not exist when they wrote.
    #[cfg(test)]
    pub(crate) fn from_current_dropping_metadata(store: &LogicalLeafStore) -> Self {
        let mut bare = store.clone();
        bare.ppoi_event_metadata.clear();
        Self::try_from_current(&bare).expect("metadata cleared on the line above")
    }
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
                event_type,
                signature,
                validated_merkleroot,
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
                self.ppoi_event_metadata.insert(
                    idx_key,
                    raven_railgun_persistence::PpoiEventMetadata {
                        event_type: *event_type,
                        signature: signature.clone(),
                        validated_merkleroot: *validated_merkleroot,
                    },
                );
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
                    // Dropping a status rewrites the row's verdict byte. Read the index before
                    // the list-leaf pass below removes it.
                    if let Some(list_index) = self.ppoi_bc_index.get(&key).copied() {
                        self.dirty_shards
                            .extend(encoder.affected_shards_for_ppoi_leaf(&key.0, list_index));
                    }
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
                    self.ppoi_event_metadata.remove(&key);
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

    /// Hold the next append on `list_key` to `upstream_root`: `None` when appending `leaf`
    /// gives exactly that root, the divergence otherwise. Compares nothing but the root, so
    /// the index it reports is the only one an append can take, the current leaf count.
    ///
    /// # Errors
    /// [`AdapterError::InvalidQuery`] if the list's tree is full, [`AdapterError::Internal`]
    /// if `leaf` cannot be hashed.
    pub fn ppoi_root_divergence(
        &self,
        list_key: &[u8; 32],
        leaf: &[u8; 32],
        upstream_root: &[u8; 32],
    ) -> Result<Option<crate::ppoi_root::PpoiRootDivergence>> {
        let (leaf_count, local_root) = match self.ppoi_imts.get(list_key) {
            Some(imt) => (imt.leaf_count(), imt.root_after_append(*leaf)?),
            None => (0, crate::imt::Imt::new()?.root_after_append(*leaf)?),
        };
        if &local_root == upstream_root {
            return Ok(None);
        }
        let list_index = u32::try_from(leaf_count).map_err(|_| {
            AdapterError::Internal(format!("per-list leaf count {leaf_count} exceeds u32"))
        })?;
        Ok(Some(crate::ppoi_root::PpoiRootDivergence {
            list_key: *list_key,
            list_index,
            local_root,
            upstream_root: *upstream_root,
        }))
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

    /// Upstream metadata retained atomically with a per-list leaf.
    #[must_use]
    pub fn ppoi_event_metadata(
        &self,
        list_key: &[u8; 32],
        list_index: u32,
    ) -> Option<&raven_railgun_persistence::PpoiEventMetadata> {
        self.ppoi_event_metadata.get(&(*list_key, list_index))
    }

    /// Per-list `(list_index -> status_byte)` derived view.
    #[must_use]
    pub fn ppoi_status_at(&self, list_key: &[u8; 32], list_index: u32) -> Option<u8> {
        let bc = self.ppoi_bc_at(list_key, list_index)?;
        self.ppoi_status(list_key, &bc)
    }

    /// Entry count of the map that a mid-struct field insertion steals the bytes of; the
    /// frozen-V6 tests assert on it directly rather than inferring it from a clean decode.
    #[cfg(test)]
    pub(crate) fn ppoi_list_leaf_block_height_len(&self) -> usize {
        self.ppoi_list_leaf_block_height.len()
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

    /// Re-derive the upper-sibling addendum for every shard of every list this store holds, and
    /// record the encoded database it was derived alongside.
    ///
    /// **`self` MUST be the tree `derived_alongside` was encoded from.** This function cannot
    /// check that and does not try: it records whatever `Arc` it is handed as the provenance of
    /// whatever tree `self` currently holds, so calling it on a store that has run ahead of
    /// `derived_alongside` makes `committed_addenda_derived_from` report consistency for a pair
    /// that folds to a wrong root. Only two call sites satisfy the precondition: `drive_commit`
    /// immediately after `publish_recommitted_state`, and `InspirePersistence::open` on the
    /// snapshot's own store before WAL replay.
    ///
    /// A shard whose proof does not resolve is left ABSENT rather than defaulted: an empty addendum
    /// folds to a wrong root, so the caller must refuse instead of serving one.
    pub fn refresh_committed_addenda(
        &mut self,
        derived_alongside: &std::sync::Arc<raven_inspire::EncodedDatabase>,
        entries_per_shard: u32,
    ) {
        self.committed_addenda.clear();
        self.committed_addenda_db = Some(std::sync::Arc::clone(derived_alongside));
        if entries_per_shard == 0 {
            return;
        }
        // Levels 11..15 are derived ONCE per shard, from its first leaf, and served to every row in
        // it. That holds only while a shard sits inside one level-11 subtree. At twice this bound the
        // two halves of a shard have different upper siblings, and half the rows would fold to a wrong
        // root -- served with HTTP 200 and caught only by the client's pinned root.
        //
        // The bound belongs HERE and not in the encoder's constructor: the same width is legitimate
        // for the dirty-set property, where the affected subtree sits inside one shard. Refusing at
        // construction would reject a sound configuration for an unrelated reason.
        //
        // Leaving the table empty is the refusal: the batch path already returns 503 and increments
        // `raven_railgun_addendum_missing_total` for a shard with no committed addendum.
        let upper_subtree_leaves = 1u32 << crate::pir_table::list::PATH10_LEVELS;
        if entries_per_shard > upper_subtree_leaves {
            tracing::error!(
                target = "raven::engine::addendum",
                entries_per_shard,
                bound = upper_subtree_leaves,
                path10_levels = crate::pir_table::list::PATH10_LEVELS,
                "refusing to derive upper-sibling addenda: a shard this wide spans more than one \
                 level-11 subtree, so no single addendum is correct for all of its rows; raise \
                 PATH10_LEVELS with the record layout or narrow entries_per_shard"
            );
            return;
        }
        let shards = u32::try_from(crate::imt::TREE_MAX_ITEMS)
            .unwrap_or(u32::MAX)
            .saturating_div(entries_per_shard);
        let list_keys: Vec<[u8; 32]> = self.ppoi_imts.keys().copied().collect();
        for list_key in list_keys {
            for shard_id in 0..shards {
                let Some(first) = shard_id.checked_mul(entries_per_shard) else {
                    continue;
                };
                let Ok(proof) = self.ppoi_merkle_proof(&list_key, first) else {
                    continue;
                };
                let addendum: Vec<u8> = proof
                    .elements
                    .into_iter()
                    .skip(crate::pir_table::list::PATH10_LEVELS)
                    .take(crate::imt::TREE_DEPTH - crate::pir_table::list::PATH10_LEVELS)
                    .flatten()
                    .collect();
                self.committed_addenda
                    .insert((list_key, shard_id), addendum);
            }
        }
    }

    /// The upper-sibling addendum for a shard as of [`Self::committed_addenda_epoch`].
    #[must_use]
    pub fn committed_addendum(&self, list_key: &[u8; 32], shard_id: u32) -> Option<&[u8]> {
        self.committed_addenda
            .get(&(*list_key, shard_id))
            .map(Vec::as_slice)
    }

    /// Whether any committed tree has been recorded at all.
    ///
    /// Distinguishes "never seeded" from "seeded against a superseded database", which
    /// [`Self::committed_addenda_derived_from`] collapses into one `false`. A refusal that cannot
    /// say which one it is sends an operator hunting a commit-cadence skew on an instance that
    /// has simply never committed.
    #[must_use]
    pub fn has_committed_addenda_provenance(&self) -> bool {
        self.committed_addenda_db.is_some()
    }

    /// Whether the retained addenda were derived alongside exactly this encoded database.
    ///
    /// Pointer identity is the signal on purpose. A heartbeat republishes the same `Arc` and must
    /// keep serving; a commit publishes a new one and must refuse until the table is refreshed.
    #[must_use]
    pub fn committed_addenda_derived_from(
        &self,
        db: &std::sync::Arc<raven_inspire::EncodedDatabase>,
    ) -> bool {
        self.committed_addenda_db
            .as_ref()
            .is_some_and(|mine| std::sync::Arc::ptr_eq(mine, db))
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
/// A `PpoiListLeafAdded` is also held to the upstream root it carries, and ONLY here:
/// [`LogicalLeafStore::apply`] is what WAL replay runs, replay soft-skips a refused row, and
/// a skipped row leaves the tree a leaf short for good. A row is screened once, ahead of the
/// write that makes it durable. The all-zero root is the one value not compared; it is
/// counted instead.
///
/// # Errors
/// [`AdapterError::InvalidQuery`] on a non-contiguous index, an index at or
/// past IMT capacity, a leaf at or above the BN254 scalar modulus, or a
/// [`crate::ppoi_root::PpoiRootDivergence`].
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
            validated_merkleroot,
            ..
        } => {
            let expected = store
                .ppoi_imt(list_key)
                .map_or(0, crate::imt::Imt::leaf_count);
            checked_imt_append(ImtSlot::PpoiList, *list_index, expected, blinded_commitment)?;
            screen_upstream_root(
                store,
                list_key,
                *list_index,
                blinded_commitment,
                validated_merkleroot,
            )?;
        }
        P::PpoiStatus { .. } | P::Reorg { .. } | P::Heartbeat { .. } => {}
    }
    Ok(())
}

// Runs after the contiguity screen, so `list_index` is the index the append takes. Counted
// here rather than by a caller: a refusal nobody counted is the defect this exists to end.
fn screen_upstream_root(
    store: &LogicalLeafStore,
    list_key: &[u8; 32],
    list_index: u32,
    leaf: &[u8; 32],
    upstream_root: &[u8; 32],
) -> Result<()> {
    if upstream_root == &crate::ppoi_root::NO_UPSTREAM_ROOT {
        metrics::counter!(crate::ppoi_root::PPOI_ROOT_UNASSERTED_TOTAL).increment(1);
        tracing::warn!(
            list_key = %crate::orchestrator::hex_lower_32(list_key),
            list_index,
            "PPOI list row carries the all-zero root; applying it with no upstream root \
             comparison. The upstream feed never serves one"
        );
        return Ok(());
    }
    match store.ppoi_root_divergence(list_key, leaf, upstream_root)? {
        None => Ok(()),
        Some(divergence) => {
            metrics::counter!(crate::ppoi_root::PPOI_ROOT_DIVERGENCE_TOTAL).increment(1);
            Err(divergence.into())
        }
    }
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
