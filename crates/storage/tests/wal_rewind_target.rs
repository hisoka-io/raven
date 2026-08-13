#![allow(clippy::expect_used, clippy::unwrap_used)]
//! The rewind target after a failed frame write must be the log's byte length.
//!
//! `O_APPEND` leaves the fd offset at 0 until the kernel repositions it on the first
//! write, so on the first append after any reopen of a non-empty log the offset reads
//! 0. A rewind to it truncates the entire log, and because the truncation SUCCEEDS the
//! poison flag stays clear, appends continue, and replay returns a clean empty log.

use std::fs::OpenOptions;
use std::io::{Seek, Write};

/// Opens exactly as `open_wal_owner_only` does, so the offset behaviour under test is
/// the one production gets rather than one a test constructed.
fn open_like_production(path: &std::path::Path) -> std::fs::File {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .expect("open")
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)
            .expect("open")
    }
}

#[test]
fn the_fd_offset_is_zero_after_reopening_a_non_empty_append_log() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("current.log");

    {
        let mut f = open_like_production(&path);
        f.write_all(&vec![0xABu8; 3840]).expect("seed");
        f.sync_all().expect("sync");
    }

    let mut reopened = open_like_production(&path);
    let on_disk = reopened.metadata().expect("metadata").len();
    let offset = reopened.stream_position().expect("stream_position");

    assert_eq!(on_disk, 3840, "precondition: the log is non-empty on disk");
    assert_eq!(
        offset, 0,
        "precondition for the defect: O_APPEND reports offset 0 until the first write"
    );
    assert_ne!(
        offset, on_disk,
        "the fd offset is NOT a safe rewind target: rewinding to it would set_len(0) \
         and destroy every committed frame"
    );
}
