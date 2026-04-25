use bytes::Bytes;

use crate::error::Error;

pub type Row = (u64, Bytes);

pub trait StorageBackend: Send + Sync + 'static {
    fn len(&self) -> Result<u64, Error>;
    fn is_empty(&self) -> Result<bool, Error> {
        Ok(self.len()? == 0)
    }

    fn begin(&self) -> Result<Box<dyn Transaction + '_>, Error>;
    fn snapshot(&self) -> Result<Box<dyn Snapshot>, Error>;
}

pub trait Transaction: Send {
    fn insert(&mut self, key: u64, value: Bytes) -> Result<(), Error>;
    fn remove(&mut self, key: u64) -> Result<(), Error>;
    fn commit(self: Box<Self>) -> Result<u64, Error>;
}

pub trait Snapshot: Send + Sync {
    fn generation(&self) -> u64;
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn get(&self, key: u64) -> Result<Option<Bytes>, Error>;
    fn scan<'a>(&'a self) -> Box<dyn Iterator<Item = Result<Row, Error>> + 'a>;
}
