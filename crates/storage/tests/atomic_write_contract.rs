use raven_storage::{atomic_write, fsync_parent_dir};

#[test]
fn durability_helpers_are_available_to_consumers() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("nested").join("state.bin");

    atomic_write(&path, b"durable bytes")?;
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("test path has no parent"))?;
    fsync_parent_dir(parent)?;

    assert_eq!(std::fs::read(path)?, b"durable bytes");
    Ok(())
}
