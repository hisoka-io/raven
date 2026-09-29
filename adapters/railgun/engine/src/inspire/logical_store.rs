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
    List([u8; 32]),
}

impl ImtSlot {
    const fn index_field(self) -> &'static str {
        match self {
            Self::CommitmentTree(_) => "leaf_index",
            Self::List(_) => "list_index",
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
            Self::List(_) => format!(
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
    let index_usize = index as usize;
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
            list_key,
            list_index,
            blinded_commitment,
            ..
        } => (ImtSlot::List(*list_key), *list_index, blinded_commitment),
        P::Reorg { .. } | P::Heartbeat { .. } => return Ok(()),
    };
    if leaf >= &BN254_FR_MODULUS_BE {
        return Err(slot.non_canonical_leaf(index, leaf));
    }
    Ok(())
}

/// Identifies one state of a store's list rows within this process. Every store starts with a
/// fresh value, a decoded one included, and takes another whenever a list row is added or
/// removed, so two equal stamps mean the same list rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RowsStamp(u64);

static NEXT_ROWS_STAMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl RowsStamp {
    fn fresh() -> Self {
        Self(NEXT_ROWS_STAMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

impl Default for RowsStamp {
    fn default() -> Self {
        Self::fresh()
    }
}

/// Sidecar logical-state store; accumulates chain rows and marks shards dirty
/// so commit re-encodes only those. Rebuilt from WAL replay on bootstrap.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogicalLeafStore {
    leaves: std::collections::BTreeMap<(u32, u32), [u8; 32]>,
    dirty_shards: std::collections::BTreeSet<u32>,
    last_block_height: u64,
    leaf_block_height: std::collections::BTreeMap<(u32, u32), u64>,
    imts: std::collections::HashMap<u32, crate::imt::Imt>,
    ppoi_imts: std::collections::HashMap<[u8; 32], crate::imt::Imt>,
    // Upstream dropped its unique `(listKey, blindedCommitment)` index and recreated it
    // non-unique, so one commitment may hold several indices and a one-index map lost the
    // earlier one.
    ppoi_bc_indices: std::collections::BTreeSet<([u8; 32], [u8; 32], u32)>,
    ppoi_index_bc: std::collections::BTreeMap<([u8; 32], u32), [u8; 32]>,
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
    #[serde(skip)]
    list_rows_stamp: RowsStamp,
}

impl LogicalLeafStore {
    /// Build an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one WAL payload. Logical mutation only; does not touch `encoded_db`.
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
                let slot = ImtSlot::CommitmentTree(*tree_number);
                let at =
                    checked_imt_append(slot, *leaf_index, self.slot_leaf_count(slot), commitment)?;
                self.append_to_imt(slot, at, &[*commitment])?;
                self.record_appended_leaf(payload, block_height, encoder);
            }
            P::PpoiListLeafAdded {
                list_key,
                list_index,
                blinded_commitment,
                ..
            } => {
                let slot = ImtSlot::List(*list_key);
                let at = checked_imt_append(
                    slot,
                    *list_index,
                    self.slot_leaf_count(slot),
                    blinded_commitment,
                )?;
                self.append_to_imt(slot, at, &[*blinded_commitment])?;
                self.record_appended_leaf(payload, block_height, encoder);
            }
            P::Reorg { height } => self.rewind_past(*height, encoder),
            P::Heartbeat { .. } => {}
        }
        self.last_block_height = self.last_block_height.max(block_height);
        Ok(())
    }

    fn rewind_past(&mut self, height: u64, encoder: &dyn crate::pir_table::PirTableEncoder) {
        let stale_leaves: Vec<(u32, u32)> = self
            .leaf_block_height
            .iter()
            .filter(|(_, &h)| h > height)
            .map(|(k, _)| *k)
            .collect();
        let mut affected_trees: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
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
            let new_count = self
                .leaves
                .range((*tree, 0u32)..(tree.saturating_add(1), 0u32))
                .next_back()
                .map_or(0, |((_, last_idx), _)| *last_idx as usize + 1);
            if let Some(imt) = self.imts.get_mut(tree) {
                imt.truncate_to(new_count);
            }
        }

        let stale_list_leaves: Vec<([u8; 32], u32)> = self
            .ppoi_list_leaf_block_height
            .iter()
            .filter(|(_, &h)| h > height)
            .map(|(k, _)| *k)
            .collect();
        let mut affected_lists: std::collections::BTreeSet<[u8; 32]> =
            std::collections::BTreeSet::new();
        if !stale_list_leaves.is_empty() {
            self.list_rows_stamp = RowsStamp::fresh();
        }
        for key in stale_list_leaves {
            let (list_key, list_index) = key;
            self.ppoi_list_leaf_block_height.remove(&key);
            self.ppoi_event_metadata.remove(&key);
            // Only THIS occurrence. Dropping the commitment's whole lookup unindexes a
            // commitment that a surviving earlier index still holds, and the shim then
            // reports a member of the list as Missing.
            if let Some(bc) = self.ppoi_index_bc.remove(&key) {
                self.ppoi_bc_indices.remove(&(list_key, bc, list_index));
            }
            self.dirty_shards
                .extend(encoder.affected_shards_for_ppoi_leaf(&list_key, list_index));
            affected_lists.insert(list_key);
        }
        for list_key in &affected_lists {
            let new_count = self
                .ppoi_index_bc
                .range((*list_key, 0u32)..)
                .take_while(|((lk, _), _)| lk == list_key)
                .last()
                .map_or(0, |((_, last_idx), _)| *last_idx as usize + 1);
            if let Some(imt) = self.ppoi_imts.get_mut(list_key) {
                imt.truncate_to(new_count);
            }
        }
    }

    fn slot_leaf_count(&self, slot: ImtSlot) -> usize {
        let imt = match slot {
            ImtSlot::CommitmentTree(tree_number) => self.imts.get(&tree_number),
            ImtSlot::List(list_key) => self.ppoi_imts.get(&list_key),
        };
        imt.map_or(0, crate::imt::Imt::leaf_count)
    }

    /// Append in place. `Imt::insert_leaves` refuses with the tree untouched, and a slot with no
    /// tree yet gets one only once the append succeeded, so a refusal leaves the store as it was.
    fn append_to_imt(&mut self, slot: ImtSlot, start: usize, leaves: &[[u8; 32]]) -> Result<()> {
        let existing = match slot {
            ImtSlot::CommitmentTree(tree_number) => self.imts.get_mut(&tree_number),
            ImtSlot::List(list_key) => self.ppoi_imts.get_mut(&list_key),
        };
        if let Some(imt) = existing {
            return imt.insert_leaves(start, leaves);
        }
        let mut imt = crate::imt::Imt::new()?;
        imt.insert_leaves(start, leaves)?;
        match slot {
            ImtSlot::CommitmentTree(tree_number) => self.imts.insert(tree_number, imt),
            ImtSlot::List(list_key) => self.ppoi_imts.insert(list_key, imt),
        };
        Ok(())
    }

    /// Append a contiguous run of `AppendLeaf` rows for one tree, or of `PpoiListLeafAdded` rows
    /// for one list, reaching the state [`Self::apply`] reaches row by row while hashing each tree
    /// node once for the whole run.
    ///
    /// For fixtures and bootstrap only. WAL replay must stay per row: it skips a refused entry and
    /// carries on, where this refuses the whole run.
    ///
    /// # Errors
    /// The error [`Self::apply`] gives the first row it would refuse, or
    /// [`AdapterError::InvalidQuery`] for a row of another kind, tree or list than the first. The
    /// store is then untouched.
    pub fn seed_leaf_run(
        &mut self,
        rows: &[(raven_railgun_persistence::WalEntryPayload, u64)],
        encoder: &dyn crate::pir_table::PirTableEncoder,
    ) -> Result<()> {
        use raven_railgun_persistence::WalEntryPayload as P;
        let slot = match rows.first() {
            None => return Ok(()),
            Some((P::AppendLeaf { tree_number, .. }, _)) => ImtSlot::CommitmentTree(*tree_number),
            Some((P::PpoiListLeafAdded { list_key, .. }, _)) => ImtSlot::List(*list_key),
            Some(_) => {
                return Err(AdapterError::InvalidQuery(
                    "seed_leaf_run: the first row is not a tree leaf".into(),
                ));
            }
        };
        let start = self.slot_leaf_count(slot);

        let mut leaves = Vec::with_capacity(rows.len());
        for (offset, (payload, _)) in rows.iter().enumerate() {
            let (index, leaf) = match (slot, payload) {
                (
                    ImtSlot::CommitmentTree(tree),
                    P::AppendLeaf {
                        tree_number,
                        leaf_index,
                        commitment,
                    },
                ) if tree == *tree_number => (*leaf_index, commitment),
                (
                    ImtSlot::List(list),
                    P::PpoiListLeafAdded {
                        list_key,
                        list_index,
                        blinded_commitment,
                        ..
                    },
                ) if list == *list_key => (*list_index, blinded_commitment),
                _ => {
                    return Err(AdapterError::InvalidQuery(format!(
                        "seed_leaf_run: row {offset} is not a leaf of the first row's tree"
                    )));
                }
            };
            checked_imt_append(slot, index, start.saturating_add(offset), leaf)?;
            leaves.push(*leaf);
        }

        self.append_to_imt(slot, start, &leaves)?;
        for (payload, block_height) in rows {
            self.record_appended_leaf(payload, *block_height, encoder);
            self.last_block_height = self.last_block_height.max(*block_height);
        }
        Ok(())
    }

    /// A copy of `list_key`'s tree, for [`Self::stage_list_row`] to append to while this store
    /// still shows none of the staged rows.
    pub(crate) fn list_tree_copy(&self, list_key: &[u8; 32]) -> Result<crate::imt::Imt> {
        match self.ppoi_imts.get(list_key) {
            Some(imt) => Ok(imt.clone()),
            None => crate::imt::Imt::new(),
        }
    }

    /// Screen a `PpoiListLeafAdded` as [`validate_apply`] does and append its leaf to `staged`,
    /// hashing its path once: the root it is held to is read off the append. A refused row
    /// leaves `staged` as it was.
    ///
    /// # Errors
    /// As [`validate_apply`], judged against `staged`; [`AdapterError::InvalidQuery`] for any
    /// other payload.
    pub(crate) fn stage_list_row(
        staged: &mut crate::imt::Imt,
        payload: &raven_railgun_persistence::WalEntryPayload,
    ) -> Result<()> {
        let raven_railgun_persistence::WalEntryPayload::PpoiListLeafAdded {
            list_key,
            list_index,
            blinded_commitment,
            validated_merkleroot,
            ..
        } = payload
        else {
            return Err(AdapterError::InvalidQuery(
                "only a PpoiListLeafAdded is staged on a list tree".into(),
            ));
        };
        let at = checked_imt_append(
            ImtSlot::List(*list_key),
            *list_index,
            staged.leaf_count(),
            blinded_commitment,
        )?;
        staged.insert_leaves(at, &[*blinded_commitment])?;
        if validated_merkleroot == &crate::ppoi_root::NO_UPSTREAM_ROOT {
            count_unasserted_root(list_key, *list_index);
            return Ok(());
        }
        let local_root = staged.root();
        if &local_root == validated_merkleroot {
            return Ok(());
        }
        staged.truncate_to(at);
        metrics::counter!(crate::ppoi_root::PPOI_ROOT_DIVERGENCE_TOTAL).increment(1);
        Err(crate::ppoi_root::PpoiRootDivergence {
            list_key: *list_key,
            list_index: *list_index,
            local_root,
            upstream_root: *validated_merkleroot,
        }
        .into())
    }

    /// Whether this store already holds `payload`'s list row: `Some(true)` byte for byte,
    /// `Some(false)` a different row at that index, `None` when the index is not held yet.
    pub(crate) fn holds_list_row(
        &self,
        payload: &raven_railgun_persistence::WalEntryPayload,
    ) -> Option<bool> {
        let raven_railgun_persistence::WalEntryPayload::PpoiListLeafAdded {
            list_key,
            list_index,
            blinded_commitment,
            event_type,
            validated_merkleroot,
        } = payload
        else {
            return None;
        };
        let held = self.ppoi_bc_at(list_key, *list_index)?;
        let metadata = self.ppoi_event_metadata(list_key, *list_index);
        Some(
            held == *blinded_commitment
                && metadata.is_some_and(|m| {
                    m.event_type == *event_type && m.validated_merkleroot == *validated_merkleroot
                }),
        )
    }

    /// Install `staged`, built by [`Self::stage_list_row`] from [`Self::list_tree_copy`], as
    /// `list_key`'s tree and record `rows`, the rows staged on it in order.
    ///
    /// # Errors
    /// [`AdapterError::Internal`] when the tree moved since it was copied or `staged` does not
    /// hold exactly `rows` past it; the store is then untouched.
    pub(crate) fn apply_staged_list_rows(
        &mut self,
        list_key: &[u8; 32],
        staged: crate::imt::Imt,
        rows: &[(raven_railgun_persistence::WalEntryPayload, u64)],
        encoder: &dyn crate::pir_table::PirTableEncoder,
    ) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let base = self.slot_leaf_count(ImtSlot::List(*list_key));
        if staged.leaf_count() != base.saturating_add(rows.len()) {
            return Err(AdapterError::Internal(format!(
                "staged list tree holds {} leaves, expected {base} held plus {} staged rows; \
                 the tree moved while its rows were staged",
                staged.leaf_count(),
                rows.len()
            )));
        }
        self.ppoi_imts.insert(*list_key, staged);
        for (payload, block_height) in rows {
            self.record_appended_leaf(payload, *block_height, encoder);
            self.last_block_height = self.last_block_height.max(*block_height);
        }
        Ok(())
    }

    /// Everything a leaf row records besides its IMT append, which the caller has made. The one
    /// copy [`Self::apply`] and [`Self::seed_leaf_run`] share.
    fn record_appended_leaf(
        &mut self,
        payload: &raven_railgun_persistence::WalEntryPayload,
        block_height: u64,
        encoder: &dyn crate::pir_table::PirTableEncoder,
    ) {
        use raven_railgun_persistence::WalEntryPayload as P;
        match payload {
            P::AppendLeaf {
                tree_number,
                leaf_index,
                commitment,
            } => {
                let key = (*tree_number, *leaf_index);
                self.leaves.insert(key, *commitment);
                self.leaf_block_height.insert(key, block_height);
                self.dirty_shards
                    .extend(encoder.affected_shards_for_leaf(*tree_number, *leaf_index));
            }
            P::PpoiListLeafAdded {
                list_key,
                list_index,
                blinded_commitment,
                event_type,
                validated_merkleroot,
                ..
            } => {
                let idx_key = (*list_key, *list_index);
                self.ppoi_bc_indices
                    .insert((*list_key, *blinded_commitment, *list_index));
                self.ppoi_index_bc.insert(idx_key, *blinded_commitment);
                self.ppoi_event_metadata.insert(
                    idx_key,
                    raven_railgun_persistence::PpoiEventMetadata {
                        event_type: *event_type,
                        validated_merkleroot: *validated_merkleroot,
                    },
                );
                self.ppoi_list_leaf_block_height
                    .insert(idx_key, block_height);
                self.dirty_shards
                    .extend(encoder.affected_shards_for_ppoi_leaf(list_key, *list_index));
                self.list_rows_stamp = RowsStamp::fresh();
            }
            P::Reorg { .. } | P::Heartbeat { .. } => {}
        }
    }

    /// The state of this store's list rows, unique in the process: equal stamps mean no list
    /// row was added or removed in between, so a reader can reuse what it derived from them
    /// without walking them again.
    #[must_use]
    pub fn list_rows_stamp(&self) -> u64 {
        self.list_rows_stamp.0
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

    /// Every list_index carrying `blinded_commitment`, ascending.
    ///
    /// Upstream permits a commitment to recur within one list -- it dropped the unique
    /// `(listKey, blindedCommitment)` index and recreated it non-unique -- so this is an
    /// iterator rather than an `Option`.
    pub fn ppoi_indices_of(
        &self,
        list_key: &[u8; 32],
        blinded_commitment: &[u8; 32],
    ) -> impl Iterator<Item = u32> + '_ {
        let lo = (*list_key, *blinded_commitment, 0u32);
        let hi = (*list_key, *blinded_commitment, u32::MAX);
        self.ppoi_bc_indices
            .range(lo..=hi)
            .map(|(_, _, list_index)| *list_index)
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

    /// Entry count of the map that a mid-struct field insertion steals the bytes of; the
    /// frozen-layout test asserts on it directly rather than inferring it from a clean decode.
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
        imt.merkle_proof(list_index as usize)
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

    /// The upper-sibling addendum for a shard as of the last [`Self::refresh_committed_addenda`].
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
        imt.merkle_proof(leaf_index as usize)
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
/// A `PpoiListLeafAdded` is also held to the upstream root it carries, here and in
/// `LogicalLeafStore::stage_list_row`, and never by [`LogicalLeafStore::apply`]: that is what
/// WAL replay runs, replay soft-skips a refused row, and a skipped row leaves the tree a leaf
/// short for good. A row is screened once, ahead of the write that makes it durable. The all-zero root is the one value not compared; it is
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
            let slot = ImtSlot::List(*list_key);
            checked_imt_append(
                slot,
                *list_index,
                store.slot_leaf_count(slot),
                blinded_commitment,
            )?;
            screen_upstream_root(
                store,
                list_key,
                *list_index,
                blinded_commitment,
                validated_merkleroot,
            )?;
        }
        P::Reorg { .. } | P::Heartbeat { .. } => {}
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
        count_unasserted_root(list_key, list_index);
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

fn count_unasserted_root(list_key: &[u8; 32], list_index: u32) {
    metrics::counter!(crate::ppoi_root::PPOI_ROOT_UNASSERTED_TOTAL).increment(1);
    tracing::warn!(
        list_key = %crate::orchestrator::hex_lower_32(list_key),
        list_index,
        "PPOI list row carries the all-zero root; applying it with no upstream root \
         comparison. The upstream feed never serves one"
    );
}

/// Whether applying this payload APPENDS to an IMT.
///
/// The error run `/health/ready` gates on means leaf application is wedged, and only an IMT
/// append can close the contiguity gap that wedges it. Any other payload says nothing about that
/// gap, so clearing the run on one reports a wedged tree as healthy.
///
/// Deliberately the same partition [`validate_apply`] screens on: these are exactly the variants
/// that reach `checked_imt_append`, and the two must not drift apart.
#[must_use]
pub(crate) fn appends_to_a_tree(payload: &raven_railgun_persistence::WalEntryPayload) -> bool {
    use raven_railgun_persistence::WalEntryPayload as P;
    match payload {
        P::AppendLeaf { .. } | P::PpoiListLeafAdded { .. } => true,
        P::Reorg { .. } | P::Heartbeat { .. } => false,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod staged_list_rows_differential {
    //! Staging a list row hashes its path once where `validate_apply` then `apply` hashed it
    //! twice. Row for row, both must accept and refuse alike, with the same error, and leave the
    //! same tree. A synthetic list with planted refusals runs always. A recorded capture runs by
    //! hand: `PPOI_REPLAY_CAPTURE` names its folder, and its first `PPOI_DIFFERENTIAL_ROWS` rows
    //! (default 70,000, into a second block) are compared.

    use super::{apply_wal_entry, validate_apply, LogicalLeafStore};
    use crate::imt::{Imt, TREE_MAX_ITEMS};
    use raven_railgun_persistence::{PpoiEventType, WalEntryPayload};

    const LIST: [u8; 32] = [0x3d; 32];
    /// Staged rows applied to the store together, as one sync covers them.
    const PAGE: usize = 501;

    fn row(index: u32, leaf: [u8; 32], root: [u8; 32]) -> WalEntryPayload {
        WalEntryPayload::PpoiListLeafAdded {
            list_key: LIST,
            list_index: index,
            blinded_commitment: leaf,
            event_type: PpoiEventType::Transact,
            validated_merkleroot: root,
        }
    }

    /// Feeds `deliveries`, block-local, through both paths and compares them after every row.
    /// Returns how many rows both accepted.
    fn differ(deliveries: &[WalEntryPayload]) -> usize {
        let encoder = crate::pir_table::EncoderKind::PerListPath10 { list_key: LIST }
            .build(512, 2048)
            .expect("encoder");
        let mut old = LogicalLeafStore::new();
        let mut new = LogicalLeafStore::new();
        let mut staged = new.list_tree_copy(&LIST).expect("tree");
        let mut staged_rows = Vec::new();
        for (at, payload) in deliveries.iter().enumerate() {
            let before = old.ppoi_imt_root(&LIST);
            let old_outcome = validate_apply(&old, payload)
                .and_then(|()| apply_wal_entry(&mut old, payload, 0, encoder.as_ref()));
            let new_outcome = LogicalLeafStore::stage_list_row(&mut staged, payload);
            assert_eq!(
                old_outcome.as_ref().map_err(ToString::to_string),
                new_outcome.as_ref().map_err(ToString::to_string),
                "delivery {at}: {payload:?}"
            );
            if new_outcome.is_ok() {
                staged_rows.push((payload.clone(), 0));
            }
            let old_root = old.ppoi_imt_root(&LIST);
            assert_eq!(
                Some(staged.root()),
                old_root.or(before),
                "root after delivery {at}"
            );
            if staged_rows.len() == PAGE || at + 1 == deliveries.len() {
                new.apply_staged_list_rows(&LIST, staged, &staged_rows, encoder.as_ref())
                    .expect("apply staged");
                staged_rows.clear();
                staged = new.list_tree_copy(&LIST).expect("tree");
            }
        }
        assert_eq!(
            old.ppoi_list_leaves_iter(&LIST).collect::<Vec<_>>(),
            new.ppoi_list_leaves_iter(&LIST).collect::<Vec<_>>()
        );
        let held = old.ppoi_imt(&LIST).map_or(0, Imt::leaf_count);
        for index in 0..u32::try_from(held).expect("u32") {
            assert_eq!(
                old.ppoi_event_metadata(&LIST, index),
                new.ppoi_event_metadata(&LIST, index)
            );
        }
        assert_eq!(old.ppoi_imt_root(&LIST), new.ppoi_imt_root(&LIST));
        assert_eq!(old.dirty_shards(), new.dirty_shards());
        held
    }

    fn leaf(index: u32) -> [u8; 32] {
        let mut leaf = [0u8; 32];
        leaf[0] = 0x07;
        leaf[28..].copy_from_slice(&index.to_be_bytes());
        leaf
    }

    #[test]
    fn staging_matches_validate_then_apply_row_for_row() {
        let mut tree = Imt::new().expect("imt");
        let roots: Vec<[u8; 32]> = (0..3_000u32)
            .map(|index| {
                tree.insert_leaves(index as usize, &[leaf(index)])
                    .expect("append");
                tree.root()
            })
            .collect();
        let good = |index: u32| row(index, leaf(index), roots[index as usize]);
        let mut wrong_root = roots[700];
        wrong_root[31] ^= 1;
        let mut non_canonical = [0xffu8; 32];
        non_canonical[31] = 0;
        let mut deliveries: Vec<WalEntryPayload> = (0..700).map(good).collect();
        deliveries.extend([
            row(700, leaf(700), wrong_root),
            row(701, leaf(701), roots[701]),
            good(700),
        ]);
        deliveries.extend((701..1_200).map(good));
        deliveries.extend([
            good(1_300),
            good(1_199),
            row(1_200, non_canonical, roots[1_200]),
        ]);
        deliveries.extend((1_200..1_600).map(good));
        deliveries.push(row(1_600, leaf(1_600), [0; 32]));
        deliveries.extend((1_601..3_000).map(good));
        deliveries.push(row(
            u32::try_from(TREE_MAX_ITEMS).expect("u32"),
            leaf(0),
            roots[0],
        ));
        assert_eq!(differ(&deliveries), 3_000, "every good row once");
    }

    /// Rows of a recorded capture folder (`events.bin`), split into blocks at block-local
    /// indices the way the router hands them to each block's instance.
    fn capture_blocks(folder: &str, rows: usize) -> Vec<Vec<WalEntryPayload>> {
        const HEADER: usize = 64;
        const ROW: usize = 133;
        let bytes =
            std::fs::read(std::path::Path::new(folder).join("events.bin")).expect("events.bin");
        let mut blocks: Vec<Vec<WalEntryPayload>> = Vec::new();
        for chunk in bytes[HEADER..].as_chunks::<ROW>().0.iter().take(rows) {
            let index = u32::from_le_bytes(chunk[..4].try_into().expect("index"));
            let (block, local) = crate::orchestrator::split_ppoi_index(index);
            if blocks.len() <= block as usize {
                blocks.push(Vec::new());
            }
            blocks[block as usize].push(row(
                local,
                chunk[5..37].try_into().expect("commitment"),
                chunk[37..69].try_into().expect("root"),
            ));
        }
        blocks
    }

    #[test]
    #[ignore = "cost: stages recorded rows both ways, about 400 s for the whole list; run by hand with PPOI_REPLAY_CAPTURE naming a capture folder, when list-row staging or validate_apply changes"]
    fn staging_matches_validate_then_apply_over_a_recorded_capture() {
        let folder = std::env::var("PPOI_REPLAY_CAPTURE")
            .expect("PPOI_REPLAY_CAPTURE must name a capture folder");
        let rows = std::env::var("PPOI_DIFFERENTIAL_ROWS")
            .ok()
            .map_or(70_000, |n| n.parse().expect("PPOI_DIFFERENTIAL_ROWS"));
        let blocks = capture_blocks(&folder, rows);
        assert_eq!(blocks.iter().map(Vec::len).sum::<usize>(), rows);
        for (at, block) in blocks.iter().enumerate() {
            assert_eq!(
                differ(block),
                block.len(),
                "block {at}: a recorded row was refused"
            );
        }
    }
}
