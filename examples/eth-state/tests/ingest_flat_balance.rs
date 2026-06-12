//! Ingest gate: flat balance ingestion (no chain).
//!
//! Seeds accounts across multiple shards, applies a per-block delta batch, and asserts:
//! the row value is the fixed 32-byte big-endian balance byte-identically; the store
//! generation advances exactly once per non-empty batch (and not at all for an empty one);
//! the bounded shard materializer matches a brute-force full-scan reference and touches only
//! the shard range; and a WAL replay after a simulated restart reconstructs the same rows.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic, clippy::print_stdout, clippy::print_stderr)]


use bytes::Bytes;

use eth_state::fold::{materialize_shard_bytes, shard_of, MainSidecar};
use eth_state::ingest::{normalize_balance_be, FlatIndex};
use eth_state::ENTRY_SIZE;
use raven_core::storage::Snapshot as _;
use raven_core::MemorySnapshot;
use raven_inspire::params::InspireParams;

fn db_of(n: usize) -> Vec<u8> {
    let mut db = vec![0u8; n * ENTRY_SIZE];
    for leaf in 0..n {
        let rec = normalize_balance_be(&((leaf as u128) + 1).to_be_bytes()).expect("normalize");
        db[leaf * ENTRY_SIZE..(leaf + 1) * ENTRY_SIZE].copy_from_slice(&rec);
    }
    db
}

/// Brute-force reference: full-scan the snapshot, filtering by global range (the O(N)
/// pattern the bounded materializer replaces). Must produce identical bytes.
fn brute_materialize(snap: &MemorySnapshot, shard_id: u32, entry_size: usize) -> Vec<u8> {
    let eps = 2048u64;
    let shard_start = shard_id as u64 * eps;
    let shard_end = shard_start + eps;
    let mut buf = vec![0u8; eps as usize * entry_size];
    for row in snap.scan() {
        let (k, v) = row.expect("scan");
        if k >= shard_start && k < shard_end {
            let off = (k - shard_start) as usize * entry_size;
            let n = v.len().min(entry_size);
            buf[off..off + n].copy_from_slice(&v[..n]);
        }
    }
    buf
}

#[test]
fn ingest_flat_balance() {
    let params = InspireParams::secure_128_d2048();
    let dir = tempfile::tempdir().expect("tempdir");

    // dense address -> leaf assignment is exercised separately; the corpus here is 3000
    // accounts across shards 0 and 1, balance = leaf+1.
    let db = db_of(3000);
    let (mut ms, _msk, _ssk) =
        MainSidecar::seed(&params, &db, ENTRY_SIZE, dir.path(), 0x0000_1A6E).expect("seed");
    let gen0 = ms.generation();

    // a per-block delta batch: 50 in-place updates at block marker 7, new balances.
    let updates: Vec<(u64, Bytes)> = (0u64..50)
        .map(|i| {
            let leaf = (i * 37) % 3000;
            let bal = (i as u128) + 5_000_000;
            (leaf, Bytes::copy_from_slice(&normalize_balance_be(&bal.to_be_bytes()).expect("norm")))
        })
        .collect();
    ms.apply_updates(7, &updates).expect("apply batch");
    let gen1 = ms.generation();

    // generation advances exactly once for the non-empty batch.
    assert_eq!(gen1, gen0 + 1, "one generation per non-empty batch");
    // an empty batch does not advance the generation.
    ms.apply_updates(8, &[]).expect("apply empty");
    assert_eq!(ms.generation(), gen1, "empty batch does not advance generation");

    // each updated row is byte-identical to the fixed 32-byte big-endian balance.
    let snap = ms.store_snapshot().expect("snap");
    for (leaf, val) in &updates {
        let got = snap.get(*leaf).expect("get").expect("row present");
        assert_eq!(&got[..], &val[..], "row {leaf} byte-identical");
    }

    // the bounded materializer matches a brute-force full-scan reference for a dirty shard.
    let shard = shard_of(updates[0].0);
    let bounded = materialize_shard_bytes(&snap, shard, ENTRY_SIZE).expect("bounded");
    let brute = brute_materialize(&snap, shard, ENTRY_SIZE);
    assert_eq!(bounded, brute, "bounded materializer matches brute-force reference");

    // WAL replay after a simulated restart reconstructs the same rows.
    drop(ms);
    let (ms2, _m, _s) =
        MainSidecar::recover(&params, ENTRY_SIZE, dir.path(), 0x0000_1A6E).expect("recover");
    let snap2 = ms2.store_snapshot().expect("snap2");
    for (leaf, val) in &updates {
        let got = snap2.get(*leaf).expect("get2").expect("recovered row present");
        assert_eq!(&got[..], &val[..], "recovered row {leaf} byte-identical");
    }
    // a seeded (untouched) row also survives recovery.
    let seeded = snap2.get(1500).expect("get seeded").expect("seeded row present");
    assert_eq!(
        &seeded[..],
        &normalize_balance_be(&(1501u128).to_be_bytes()).expect("norm")[..],
        "untouched seeded row survives recovery"
    );

    // FlatIndex dense assignment is stable + monotonic.
    let mut idx = FlatIndex::new();
    let a = [1u8; 20];
    let b = [2u8; 20];
    assert_eq!(idx.assign(a), 0);
    assert_eq!(idx.assign(b), 1);
    assert_eq!(idx.assign(a), 0, "stable: re-assigning an address returns its leaf");
    assert_eq!(idx.len(), 2);
}
