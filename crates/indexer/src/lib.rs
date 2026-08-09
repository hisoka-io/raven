//! Synchronous single-row facade over a [`StorageBackend`].
//!
//! Every mutating call opens and commits its own transaction, so each advances
//! the backend generation. Batch through [`Indexer::put_many`] to land many rows
//! in one generation.
//!
//! ```
//! use raven_core::{Bytes, Error, MemoryStore};
//! use raven_indexer::Indexer;
//!
//! # fn main() -> Result<(), Error> {
//! let ix = Indexer::new(MemoryStore::new());
//! ix.put_many([(2, Bytes::from_static(b"beta")), (0, Bytes::from_static(b"alpha"))])?;
//!
//! assert_eq!(ix.get(0)?, Some(Bytes::from_static(b"alpha")));
//! let keys: Vec<u64> = ix.scan()?.into_iter().map(|(k, _)| k).collect();
//! assert_eq!(keys, vec![0, 2]);
//! # Ok(())
//! # }
//! ```

#![deny(missing_docs)]

use raven_core::{Bytes, Error, Row, StorageBackend};

/// Owning facade that turns single-row calls into backend transactions.
#[derive(Debug)]
pub struct Indexer<B> {
    backend: B,
}

impl<B: StorageBackend> Indexer<B> {
    /// Take ownership of `backend`.
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Commit one row, replacing any existing value for `key`.
    pub fn put(&self, key: u64, value: Bytes) -> Result<(), Error> {
        let mut txn = self.backend.begin()?;
        txn.insert(key, value)?;
        txn.commit()?;
        Ok(())
    }

    /// Commit every row in one transaction and return the resulting generation.
    pub fn put_many<I>(&self, rows: I) -> Result<u64, Error>
    where
        I: IntoIterator<Item = (u64, Bytes)>,
    {
        let mut txn = self.backend.begin()?;
        for (key, value) in rows {
            txn.insert(key, value)?;
        }
        txn.commit()
    }

    /// Commit a deletion. Deleting an absent key is not an error.
    pub fn delete(&self, key: u64) -> Result<(), Error> {
        let mut txn = self.backend.begin()?;
        txn.remove(key)?;
        txn.commit()?;
        Ok(())
    }

    /// Value at `key` in a fresh snapshot, or `None` if absent.
    pub fn get(&self, key: u64) -> Result<Option<Bytes>, Error> {
        self.backend.snapshot()?.get(key)
    }

    /// Whether `key` is present in a fresh snapshot.
    pub fn exists(&self, key: u64) -> Result<bool, Error> {
        Ok(self.get(key)?.is_some())
    }

    /// Every row of a fresh snapshot, in strictly ascending key order.
    pub fn scan(&self) -> Result<Vec<Row>, Error> {
        self.backend.snapshot()?.scan().collect()
    }

    /// Count of committed rows.
    pub fn len(&self) -> Result<u64, Error> {
        self.backend.len()
    }

    /// Whether no rows are committed.
    pub fn is_empty(&self) -> Result<bool, Error> {
        self.backend.is_empty()
    }

    /// Borrow the wrapped backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_core::MemoryStore;

    fn ix() -> Indexer<MemoryStore> {
        Indexer::new(MemoryStore::new())
    }

    fn b(s: &'static [u8]) -> Bytes {
        Bytes::from_static(s)
    }

    #[test]
    fn put_then_get_roundtrips() -> Result<(), Error> {
        let ix = ix();
        ix.put(1, b(b"a"))?;
        assert_eq!(ix.get(1)?, Some(b(b"a")));
        Ok(())
    }

    #[test]
    fn put_overwrites() -> Result<(), Error> {
        let ix = ix();
        ix.put(1, b(b"a"))?;
        ix.put(1, b(b"b"))?;
        assert_eq!(ix.get(1)?, Some(b(b"b")));
        Ok(())
    }

    #[test]
    fn delete_removes() -> Result<(), Error> {
        let ix = ix();
        ix.put(1, b(b"a"))?;
        ix.delete(1)?;
        assert_eq!(ix.get(1)?, None);
        assert!(!ix.exists(1)?);
        Ok(())
    }

    #[test]
    fn delete_missing_is_noop() -> Result<(), Error> {
        let ix = ix();
        ix.delete(42)?;
        assert_eq!(ix.len()?, 0);
        Ok(())
    }

    #[test]
    fn scan_returns_every_row() -> Result<(), Error> {
        let ix = ix();
        ix.put(1, b(b"a"))?;
        ix.put(2, b(b"b"))?;
        assert_eq!(ix.scan()?.len(), 2);
        Ok(())
    }

    #[test]
    fn len_and_is_empty_track_state() -> Result<(), Error> {
        let ix = ix();
        assert!(ix.is_empty()?);
        ix.put(1, b(b"a"))?;
        assert_eq!(ix.len()?, 1);
        assert!(!ix.is_empty()?);
        Ok(())
    }

    #[test]
    fn put_many_commits_all_rows_in_one_generation() -> Result<(), Error> {
        let ix = ix();
        let gen_before = ix.backend().generation();
        let gen = ix.put_many([(1, b(b"a")), (2, b(b"b")), (3, b(b"c"))])?;
        assert_eq!(ix.len()?, 3);
        assert_eq!(gen, gen_before + 1);
        assert_eq!(ix.get(1)?, Some(b(b"a")));
        assert_eq!(ix.get(2)?, Some(b(b"b")));
        assert_eq!(ix.get(3)?, Some(b(b"c")));
        Ok(())
    }

    #[test]
    fn put_many_empty_does_not_advance_generation() -> Result<(), Error> {
        let ix = ix();
        ix.put(1, b(b"a"))?;
        let gen_before = ix.backend().generation();
        let gen = ix.put_many(std::iter::empty())?;
        assert_eq!(gen, gen_before);
        Ok(())
    }
}
