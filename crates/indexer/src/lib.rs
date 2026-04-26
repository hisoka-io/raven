use raven_core::{Bytes, Error, Row, StorageBackend};

#[derive(Debug)]
pub struct Indexer<B> {
    backend: B,
}

impl<B: StorageBackend> Indexer<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn put(&self, key: u64, value: Bytes) -> Result<(), Error> {
        let mut txn = self.backend.begin()?;
        txn.insert(key, value)?;
        txn.commit()?;
        Ok(())
    }

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

    pub fn delete(&self, key: u64) -> Result<(), Error> {
        let mut txn = self.backend.begin()?;
        txn.remove(key)?;
        txn.commit()?;
        Ok(())
    }

    pub fn get(&self, key: u64) -> Result<Option<Bytes>, Error> {
        self.backend.snapshot()?.get(key)
    }

    pub fn exists(&self, key: u64) -> Result<bool, Error> {
        Ok(self.get(key)?.is_some())
    }

    pub fn scan(&self) -> Result<Vec<Row>, Error> {
        self.backend.snapshot()?.scan().collect()
    }

    pub fn len(&self) -> Result<u64, Error> {
        self.backend.len()
    }

    pub fn is_empty(&self) -> Result<bool, Error> {
        self.backend.is_empty()
    }

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
