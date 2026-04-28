//! zstd back-compat: magic-sniff dispatch between zstd-wrapped and legacy bare-bincode payloads.
//! SHA-256 covers the uncompressed payload in both paths; no manifest schema bump required.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::panic,
    clippy::print_stderr,
    clippy::unusual_byte_groupings
)]

use raven_railgun_persistence::snapshot::{Snapshot, SnapshotHeader, SnapshotId, SNAPSHOT_MAGIC};
use raven_railgun_persistence::{PersistenceError, StoreLayout};
use sha2::{Digest, Sha256};

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0F)] as char);
    }
    out
}

/// Hand-write a snap directory with bare-bincode `data.bincode` (no zstd), mimicking older builds.
fn write_legacy_snapshot(
    layout: &StoreLayout,
    id: SnapshotId,
    payload: &[u8],
) -> std::io::Result<()> {
    let dir = layout.snapshot_dir(id);
    std::fs::create_dir_all(&dir)?;

    let header = SnapshotHeader {
        magic: SNAPSHOT_MAGIC,
        data_sha256_hex: bytes_to_hex(&Sha256::digest(payload)),
        data_len: u64::try_from(payload.len()).unwrap_or(u64::MAX),
    };
    let header_bytes = bincode::serialize(&header).expect("ser header");
    std::fs::write(dir.join("header.bin"), &header_bytes)?;
    std::fs::write(dir.join("data.bincode"), payload)?;
    Ok(())
}

#[test]
fn legacy_bincode_payload_loads_via_sniff() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("open");

    let payload: Vec<u8> = (0..4096_u32).map(|i| (i & 0xFF) as u8).collect();
    // First 4 bytes must not accidentally be the zstd magic.
    assert_ne!(&payload[..4], &[0x28, 0xB5, 0x2F, 0xFD]);

    write_legacy_snapshot(&layout, SnapshotId(7), &payload).expect("write legacy");

    let loaded = Snapshot::load(&layout, SnapshotId(7)).expect("legacy load via sniff");
    assert_eq!(loaded.data, payload);
    assert_eq!(loaded.header.magic, SNAPSHOT_MAGIC);
    assert_eq!(loaded.header.data_len, payload.len() as u64);
}

#[test]
fn new_zstd_payload_round_trips_via_save_then_load() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("open");

    let mut payload: Vec<u8> = Vec::with_capacity(64 * 1024);
    payload.extend_from_slice(&[0u8; 256]);
    let mut rng_state: u64 = 0xC0FFEE_DEAD_BEEF_u64;
    for _ in 0..(64 * 1024 - 256) {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        payload.push((rng_state & 0xFF) as u8);
    }

    let snap = Snapshot::build(payload.clone());
    snap.save(&layout, SnapshotId(11)).expect("save");

    let on_disk =
        std::fs::read(layout.snapshot_dir(SnapshotId(11)).join("data.bincode")).expect("read");
    assert_eq!(&on_disk[..4], &[0x28, 0xB5, 0x2F, 0xFD]);

    let loaded = Snapshot::load(&layout, SnapshotId(11)).expect("load round trip");
    assert_eq!(loaded.data, payload);
    assert_eq!(loaded.header.data_len, payload.len() as u64);
}

#[test]
fn corrupt_zstd_returns_typed_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("open");

    // High-entropy payload ensures the zstd frame is large enough to flip a mid-frame byte.
    let mut payload = Vec::with_capacity(32 * 1024);
    let mut rng: u64 = 0xBADD_CAFE_F00D_BEEF_u64;
    for _ in 0..(32 * 1024) {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        payload.push((rng & 0xFF) as u8);
    }
    let snap = Snapshot::build(payload);
    snap.save(&layout, SnapshotId(13)).expect("save");

    let body_path = layout.snapshot_dir(SnapshotId(13)).join("data.bincode");
    let mut on_disk = std::fs::read(&body_path).expect("read body");
    assert!(on_disk.len() > 64, "zstd body unexpectedly tiny: {}", on_disk.len());

    let mid = on_disk.len() / 2;
    on_disk[mid] ^= 0xFF;
    std::fs::write(&body_path, &on_disk).expect("rewrite tampered body");

    let err = Snapshot::load(&layout, SnapshotId(13)).expect_err("tampered zstd body");
    match err {
        PersistenceError::SnapshotCorrupt(msg) => {
            assert!(
                msg.contains("snap-")
                    && (msg.contains("zstd") || msg.contains("SHA-256") || msg.contains("data_len")),
                "expected snap-id + corruption reason; got: {msg}",
            );
        }
        other => panic!("expected SnapshotCorrupt, got {other:?}"),
    }
}

/// Verifies zstd-l3 compresses a production-shaped 170 MiB blob to <= 30% of input size.
#[test]
fn zstd_compression_ratio_at_production_blob() {
    // ~12.5% high-entropy bytes (8 random per 64-byte record) matches the
    // (commitment_hash, leaf_index, tree_number) shape of a partially-filled Railgun tree.
    const TOTAL: usize = 170 * 1024 * 1024;
    let mut payload: Vec<u8> = Vec::with_capacity(TOTAL);
    let mut rng: u64 = 0xDEAD_BEEF_CAFE_F00D_u64;
    while payload.len() + 64 <= TOTAL {
        payload.extend_from_slice(&[
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        for _ in 0..8 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            payload.push((rng & 0xFF) as u8);
        }
    }
    while payload.len() < TOTAL {
        payload.push(0);
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("open");
    let snap = Snapshot::build(payload.clone());
    snap.save(&layout, SnapshotId(101)).expect("save");

    let body_path = layout.snapshot_dir(SnapshotId(101)).join("data.bincode");
    let on_disk_len = std::fs::metadata(&body_path).expect("stat").len() as usize;
    let ratio = on_disk_len as f64 / payload.len() as f64;

    eprintln!(
        "zstd_l3_ratio: input={} on_disk={} ratio={:.4}",
        payload.len(),
        on_disk_len,
        ratio,
    );
    assert!(
        on_disk_len <= 50 * 1024 * 1024,
        "compressed body must be <= 50 MiB at the production cell; got {on_disk_len} bytes \
         (ratio {ratio:.4})",
    );
    assert!(
        ratio <= 0.30,
        "zstd-l3 ratio at production cell must be <= 0.30; got {ratio:.4}",
    );

    // Round-trip sanity.
    let loaded = Snapshot::load(&layout, SnapshotId(101)).expect("load");
    assert_eq!(loaded.data.len(), payload.len());
    assert_eq!(loaded.data, payload);
}
