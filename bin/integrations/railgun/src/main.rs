use raven_core::{Bytes, MemoryStore};
use raven_indexer::Indexer;

fn populate<B: raven_core::StorageBackend>(ix: &Indexer<B>) -> Result<(), raven_core::Error> {
    let entries: &[(u64, &[u8])] = &[(1, b"alpha"), (2, b"beta"), (3, b"gamma"), (4, b"delta")];
    for (k, v) in entries {
        ix.put(*k, Bytes::copy_from_slice(v))?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ix = Indexer::new(MemoryStore::new());
    populate(&ix)?;

    println!("railgun: {} rows", ix.len()?);
    for (k, v) in ix.scan()? {
        println!("  {k} -> {}", String::from_utf8_lossy(&v));
    }
    Ok(())
}
