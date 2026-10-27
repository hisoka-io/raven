//! Snapshots on production volumes were written by zstd 0.13; every later
//! build must still load them byte-for-byte. The fixture under
//! `tests/fixtures/zstd-0.13-snap/` was produced by `SnapshotFile::save` on
//! zstd 0.13.3 (libzstd 1.5.7, level 3) and must never be regenerated.
#![cfg(feature = "zstd-compression")]
#![allow(clippy::expect_used, clippy::panic)]

use std::path::Path;

use raven_storage::{PersistenceError, SnapshotFile, SnapshotId, StoreLayout};

const MAGIC: [u8; 16] = *b"ZSTD013FIXTURE01";
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
const HEX: [u8; 16] = *b"0123456789abcdef";
// Above the 128 KiB zstd block cap, so the frame holds more than one block.
const PAYLOAD_LEN: usize = 160 * 1024;

/// 32-byte records: a counter (long matches) plus 4 pseudo-random hex
/// digits (literals), so the frame exercises both sequence and literal paths.
fn payload() -> Vec<u8> {
    let mut out = Vec::with_capacity(PAYLOAD_LEN);
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut i: u64 = 0;
    while out.len() < PAYLOAD_LEN {
        out.extend_from_slice(&i.to_le_bytes());
        out.extend_from_slice(&[0u8; 20]);
        for _ in 0..4 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            out.push(
                HEX.get(usize::try_from(x & 15).unwrap_or(0))
                    .copied()
                    .unwrap_or(b'0'),
            );
        }
        i += 1;
    }
    out.truncate(PAYLOAD_LEN);
    out
}

fn fixture_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/zstd-0.13-snap")
}

/// Copies the fixture into a fresh store so `load` never touches the source tree.
fn stage(dir: &Path) -> StoreLayout {
    let layout = StoreLayout::open(dir).expect("open");
    let dst = layout.snapshot_dir(SnapshotId(1));
    std::fs::create_dir_all(&dst).expect("mkdir");
    for f in ["header.bin", "data.bincode"] {
        std::fs::copy(fixture_dir().join(f), dst.join(f)).expect("copy fixture");
    }
    layout
}

#[test]
fn zstd_013_snapshot_loads_byte_equal() {
    let raw = std::fs::read(fixture_dir().join("data.bincode")).expect("read fixture");
    assert_eq!(
        raw.get(..4),
        Some(&ZSTD_MAGIC[..]),
        "fixture is not a zstd frame"
    );
    assert!(
        raw.len() < PAYLOAD_LEN / 4,
        "fixture not compressed: {}",
        raw.len()
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let layout = stage(dir.path());
    let snap = SnapshotFile::load(&layout, SnapshotId(1), MAGIC).expect("load 0.13 fixture");
    assert_eq!(snap.data, payload());
    assert_eq!(
        usize::try_from(snap.header.data_len).ok(),
        Some(PAYLOAD_LEN)
    );
}

#[test]
fn zstd_013_snapshot_with_one_flipped_byte_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = stage(dir.path());
    let path = layout.snapshot_data_path(SnapshotId(1));
    let mut raw = std::fs::read(&path).expect("read");
    let mid = raw.len() / 2;
    let byte = raw.get_mut(mid).expect("mid byte");
    *byte ^= 0x01;
    std::fs::write(&path, &raw).expect("write");

    let err = SnapshotFile::load(&layout, SnapshotId(1), MAGIC).expect_err("flipped byte");
    assert!(
        matches!(err, PersistenceError::SnapshotCorrupt(_)),
        "got {err:?}"
    );
}
