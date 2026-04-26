use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use bytes::Bytes;

use crate::error::Error;
use crate::storage::{Row, Snapshot, StorageBackend, Transaction};

#[derive(Debug, Default)]
pub struct MemoryStore {
    inner: RwLock<BTreeMap<u64, Bytes>>,
    generation: AtomicU64,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn snapshot_concrete(&self) -> Result<MemorySnapshot, Error> {
        let guard = self
            .inner
            .read()
            .map_err(|_| Error::storage("memory store read lock poisoned"))?;
        let rows: Vec<Row> = guard.iter().map(|(k, v)| (*k, v.clone())).collect();
        Ok(MemorySnapshot {
            rows: Arc::new(rows),
            generation: self.generation(),
        })
    }
}

impl StorageBackend for MemoryStore {
    fn len(&self) -> Result<u64, Error> {
        let guard = self
            .inner
            .read()
            .map_err(|_| Error::storage("memory store read lock poisoned"))?;
        u64::try_from(guard.len()).map_err(|_| Error::storage("memory store size exceeds u64"))
    }

    fn begin(&self) -> Result<Box<dyn Transaction + '_>, Error> {
        Ok(Box::new(MemoryTxn {
            store: self,
            pending: BTreeMap::new(),
        }))
    }

    fn snapshot(&self) -> Result<Box<dyn Snapshot>, Error> {
        Ok(Box::new(self.snapshot_concrete()?))
    }
}

type PendingOp = Option<Bytes>;

struct MemoryTxn<'a> {
    store: &'a MemoryStore,
    pending: BTreeMap<u64, PendingOp>,
}

impl std::fmt::Debug for MemoryTxn<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryTxn")
            .field("pending_ops", &self.pending.len())
            .finish()
    }
}

impl Transaction for MemoryTxn<'_> {
    fn insert(&mut self, key: u64, value: Bytes) -> Result<(), Error> {
        self.pending.insert(key, Some(value));
        Ok(())
    }

    fn remove(&mut self, key: u64) -> Result<(), Error> {
        self.pending.insert(key, None);
        Ok(())
    }

    fn commit(self: Box<Self>) -> Result<u64, Error> {
        let MemoryTxn { store, pending } = *self;

        if pending.is_empty() {
            return Ok(store.generation());
        }

        let mut guard = store
            .inner
            .write()
            .map_err(|_| Error::storage("memory store write lock poisoned"))?;

        for (key, op) in pending {
            match op {
                Some(value) => {
                    guard.insert(key, value);
                }
                None => {
                    guard.remove(&key);
                }
            }
        }

        // Bump generation under the write lock so the returned value identifies this commit.
        let new_gen = store
            .generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        drop(guard);
        Ok(new_gen)
    }
}

#[derive(Debug, Clone)]
pub struct MemorySnapshot {
    rows: Arc<Vec<Row>>,
    generation: u64,
}

impl Snapshot for MemorySnapshot {
    fn generation(&self) -> u64 {
        self.generation
    }

    fn len(&self) -> u64 {
        u64::try_from(self.rows.len()).unwrap_or(u64::MAX)
    }

    fn get(&self, key: u64) -> Result<Option<Bytes>, Error> {
        Ok(match self.rows.binary_search_by_key(&key, |(k, _)| *k) {
            Ok(idx) => self.rows.get(idx).map(|(_, v)| v.clone()),
            Err(_) => None,
        })
    }

    fn scan<'a>(&'a self) -> Box<dyn Iterator<Item = Result<Row, Error>> + 'a> {
        Box::new(self.rows.iter().cloned().map(Ok))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commit(store: &MemoryStore, rows: &[(u64, &[u8])]) -> Result<(), Error> {
        let mut txn = store.begin()?;
        for (k, v) in rows {
            txn.insert(*k, Bytes::copy_from_slice(v))?;
        }
        txn.commit()?;
        Ok(())
    }

    fn b(s: &'static [u8]) -> Bytes {
        Bytes::from_static(s)
    }

    #[test]
    fn empty_store_reports_zero_len() -> Result<(), Error> {
        let store = MemoryStore::new();
        assert_eq!(store.len()?, 0);
        assert!(store.is_empty()?);
        Ok(())
    }

    #[test]
    fn committed_txn_visible_in_snapshot() -> Result<(), Error> {
        let store = MemoryStore::new();
        commit(&store, &[(3, b"gamma"), (1, b"alpha"), (2, b"beta")])?;

        let snap = store.snapshot()?;
        assert_eq!(snap.len(), 3);

        let keys: Vec<u64> = snap
            .scan()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(keys, vec![1, 2, 3]);
        Ok(())
    }

    #[test]
    fn snapshot_isolated_from_later_commit() -> Result<(), Error> {
        let store = MemoryStore::new();
        commit(&store, &[(1, b"alpha")])?;
        let snap = store.snapshot_concrete()?;
        let gen_at_snapshot = snap.generation();

        commit(&store, &[(2, b"beta")])?;

        assert_eq!(snap.len(), 1);
        assert!(snap.get(1)?.is_some());
        assert!(snap.get(2)?.is_none());

        assert_eq!(store.len()?, 2);
        assert!(store.generation() > gen_at_snapshot);
        Ok(())
    }

    #[test]
    fn dropped_txn_rolls_back() -> Result<(), Error> {
        let store = MemoryStore::new();
        commit(&store, &[(1, b"alpha")])?;
        let gen_before = store.generation();

        {
            let mut txn = store.begin()?;
            txn.insert(2, b(b"beta"))?;
            txn.remove(1)?;
        }

        let snap = store.snapshot()?;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap.get(1)?, Some(b(b"alpha")));
        assert_eq!(store.generation(), gen_before);
        Ok(())
    }

    #[test]
    fn mid_txn_snapshot_excludes_uncommitted() -> Result<(), Error> {
        let store = MemoryStore::new();
        commit(&store, &[(1, b"alpha")])?;

        let mut txn = store.begin()?;
        txn.insert(2, b(b"beta"))?;
        txn.insert(3, b(b"gamma"))?;

        let snap_mid = store.snapshot()?;
        assert_eq!(snap_mid.len(), 1);
        assert!(snap_mid.get(2)?.is_none());
        assert!(snap_mid.get(3)?.is_none());

        txn.commit()?;

        let snap_post = store.snapshot()?;
        assert_eq!(snap_post.len(), 3);
        assert!(snap_post.generation() > snap_mid.generation());
        Ok(())
    }

    #[test]
    fn get_handles_reverse_insertion_order() -> Result<(), Error> {
        let store = MemoryStore::new();
        let mut txn = store.begin()?;
        for k in (0..1_000u64).rev() {
            txn.insert(k, Bytes::from(k.to_le_bytes().to_vec()))?;
        }
        txn.commit()?;

        let snap = store.snapshot()?;
        for k in [0u64, 1, 42, 999] {
            assert_eq!(snap.get(k)?.as_deref(), Some(&k.to_le_bytes()[..]));
        }
        assert!(snap.get(10_000)?.is_none());
        Ok(())
    }

    #[test]
    fn last_write_wins_across_txns() -> Result<(), Error> {
        let store = MemoryStore::new();
        commit(&store, &[(7, b"first")])?;
        commit(&store, &[(7, b"second")])?;

        let snap = store.snapshot()?;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap.get(7)?, Some(b(b"second")));
        Ok(())
    }

    #[test]
    fn last_write_wins_within_txn() -> Result<(), Error> {
        let store = MemoryStore::new();
        let mut txn = store.begin()?;
        txn.insert(7, b(b"first"))?;
        txn.insert(7, b(b"second"))?;
        txn.commit()?;

        let snap = store.snapshot()?;
        assert_eq!(snap.get(7)?, Some(b(b"second")));
        Ok(())
    }

    #[test]
    fn remove_deletes_on_commit() -> Result<(), Error> {
        let store = MemoryStore::new();
        commit(&store, &[(1, b"alpha"), (2, b"beta")])?;

        let mut txn = store.begin()?;
        txn.remove(1)?;
        txn.commit()?;

        let snap = store.snapshot()?;
        assert_eq!(snap.len(), 1);
        assert!(snap.get(1)?.is_none());
        assert!(snap.get(2)?.is_some());
        Ok(())
    }

    #[test]
    fn empty_commit_does_not_advance_generation() -> Result<(), Error> {
        let store = MemoryStore::new();
        commit(&store, &[(1, b"alpha")])?;
        let gen_before = store.generation();

        let txn = store.begin()?;
        txn.commit()?;

        assert_eq!(store.generation(), gen_before);
        Ok(())
    }
}
