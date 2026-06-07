//! Wall-clock per-INSERT bench across all six encoder choices.

#![allow(
    clippy::expect_used,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing
)]

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_engine::inspire::{
    apply_wal_entry, re_encode_shard, setup_state, LogicalLeafStore,
};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_persistence::WalEntryPayload;

const ENTRIES_LOG2: usize = 16;
const LEAVES_PER_TREE: u32 = 1u32 << ENTRIES_LOG2;
const SEEDS: usize = 3;
const SAMPLE_INSERTS: u32 = 1000;
const PRELOAD_FRAC_NUM: u32 = 1;
const PRELOAD_FRAC_DEN: u32 = 2;

const LIST_KEY: [u8; 32] = [0xA5; 32];

fn build_synthetic_db(n_entries: usize, entry_bytes: usize) -> Vec<u8> {
    (0..n_entries)
        .flat_map(|i| (0..entry_bytes).map(move |j| ((i * 31 + j * 17) % 251) as u8))
        .collect()
}

fn canonical(seed: u32) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[28..32].copy_from_slice(&seed.to_be_bytes());
    if b[31] == 0 {
        b[31] = 1;
    }
    b
}

fn median(timings: &mut [Duration]) -> Duration {
    timings.sort();
    timings[timings.len() / 2]
}

fn findings_path() -> PathBuf {
    if let Ok(env_dir) = std::env::var("RAVEN_BENCH_FINDINGS_DIR") {
        return PathBuf::from(env_dir).join("per-insert-wall-time.md");
    }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // engine
    p.pop(); // railgun
    p.pop(); // adapters
    p.push("target");
    p.push("bench-findings");
    p.push("per-insert-wall-time.md");
    p
}

// write failure is non-fatal; numbers still print via eprintln
fn append_findings_line(line: &str) {
    let path = findings_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let result = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut f| writeln!(f, "{line}"));
    if let Err(e) = result {
        eprintln!("findings: failed to append to {}: {e}", path.display());
    }
}

#[derive(Clone, Copy)]
enum InsertKind {
    /// Encoder consumes `AppendLeaf` and grows a per-tree IMT.
    PerTreeAppend,
    /// Encoder consumes `PpoiListLeafAdded` and grows a per-list IMT.
    PerListAppend,
}

#[derive(Clone, Copy)]
struct Cell {
    label: &'static str,
    entries: usize,
    entry_bytes: usize,
    encoder_kind: EncoderKind,
    insert_kind: InsertKind,
}

fn payload_for(cell: &Cell, idx: u32) -> WalEntryPayload {
    let bc = canonical(idx.saturating_add(1));
    match cell.insert_kind {
        InsertKind::PerListAppend => WalEntryPayload::PpoiListLeafAdded {
            list_key: LIST_KEY,
            list_index: idx,
            blinded_commitment: bc,
            status: 0,
        },
        InsertKind::PerTreeAppend => WalEntryPayload::AppendLeaf {
            tree_number: 0,
            leaf_index: idx,
            commitment: bc,
        },
    }
}

// returns per-seed median (not mean) per-insert duration and the sample count taken
fn run_one_seed(cell: &Cell, preload_to: u32) -> (Duration, u32) {
    let params = InspireParams::secure_128_d2048();
    let db = build_synthetic_db(cell.entries, cell.entry_bytes);
    let (state, _secret_key) =
        setup_state(&params, &db, cell.entry_bytes, InspireVariant::TwoPacking)
            .expect("setup_state");

    let encoder: Arc<dyn PirTableEncoder> = cell
        .encoder_kind
        .build(cell.entry_bytes, 2048)
        .expect("build encoder");

    let mut store = LogicalLeafStore::new();
    for i in 0..preload_to {
        let payload = payload_for(cell, i);
        apply_wal_entry(&mut store, &payload, 100 + u64::from(i), encoder.as_ref())
            .expect("preload apply");
    }
    store.clear_dirty_shards();

    let mut encoded_db = (*state.encoded_db).clone();
    let cap = LEAVES_PER_TREE.saturating_sub(preload_to);
    let to_take = SAMPLE_INSERTS.min(cap);
    let mut per_insert: Vec<Duration> = Vec::with_capacity(to_take as usize);
    let mut idx = preload_to;
    let mut sampled = 0u32;
    while sampled < to_take {
        let payload = payload_for(cell, idx);
        let started = Instant::now();
        apply_wal_entry(&mut store, &payload, 200 + u64::from(idx), encoder.as_ref())
            .expect("apply_wal_entry");
        let dirty: Vec<u32> = store.dirty_shards().iter().copied().collect();
        for shard_id in dirty {
            let bytes = encoder.materialize_shard(shard_id, &store);
            re_encode_shard(&mut encoded_db, &params, shard_id, &bytes, cell.entry_bytes)
                .expect("re_encode_shard");
        }
        store.clear_dirty_shards();
        per_insert.push(started.elapsed());
        sampled += 1;
        idx += 1;
    }

    if per_insert.is_empty() {
        return (Duration::ZERO, 0);
    }
    (median(&mut per_insert), sampled)
}

fn run_cell(cell: &Cell) {
    let preload_to = (LEAVES_PER_TREE / PRELOAD_FRAC_DEN).saturating_mul(PRELOAD_FRAC_NUM);
    let mut seed_medians: Vec<Duration> = Vec::with_capacity(SEEDS);
    let mut total_samples = 0u32;
    for seed in 0..SEEDS {
        let setup_start = Instant::now();
        let (per_insert_median, sampled) = run_one_seed(cell, preload_to);
        eprintln!(
            "per_insert: cell={} seed={} preload={} samples={} per-insert-median={:?} \
             (full setup+sweep {:?})",
            cell.label,
            seed,
            preload_to,
            sampled,
            per_insert_median,
            setup_start.elapsed()
        );
        seed_medians.push(per_insert_median);
        total_samples = total_samples.max(sampled);
    }
    let across_seeds = median(&mut seed_medians.clone());
    eprintln!(
        "per_insert: cell={} preload=50% samples-per-seed={} 3-seed-median={:?} \
         (raw per-seed: {:?})",
        cell.label, total_samples, across_seeds, seed_medians
    );
    let micros = across_seeds.as_secs_f64() * 1_000_000.0;
    append_findings_line(&format!(
        "- per_insert | encoder=`{}` | preload=50% | samples-per-seed={} | seeds={} | \
         per-seed-medians={:?} | 3-seed-median={micros:.1} μs",
        cell.label, total_samples, SEEDS, seed_medians
    ));
}

#[test]
#[ignore = "production-cell setup is heavy (~12s per encoder x 3 seeds); ~3 minutes total"]
fn per_insert_wall_time_per_encoder_at_50pct_fill() {
    append_findings_line("");
    append_findings_line(
        "## per_insert_wall_time_bench (50 % pre-fill, 1000 inserts/seed, 3 seeds)",
    );
    append_findings_line("");

    let leaf_entries = 1usize << ENTRIES_LOG2;
    let node_entries = 1usize << (ENTRIES_LOG2 + 1);
    let cells = [
        Cell {
            label: "per-leaf-bc 65536x32 tree=0",
            entries: leaf_entries,
            entry_bytes: 32,
            encoder_kind: EncoderKind::PerLeafBc,
            insert_kind: InsertKind::PerTreeAppend,
        },
        Cell {
            label: "per-leaf-path 65536x512 tree=0",
            entries: leaf_entries,
            entry_bytes: 512,
            encoder_kind: EncoderKind::PerLeafPath { tree_number: 0 },
            insert_kind: InsertKind::PerTreeAppend,
        },
        Cell {
            label: "per-node 131072x32 tree=0",
            entries: node_entries,
            entry_bytes: 32,
            encoder_kind: EncoderKind::PerNode { tree_number: 0 },
            insert_kind: InsertKind::PerTreeAppend,
        },
        Cell {
            label: "per-list-status 65536x32 list",
            entries: leaf_entries,
            entry_bytes: 32,
            encoder_kind: EncoderKind::PerListStatus { list_key: LIST_KEY },
            insert_kind: InsertKind::PerListAppend,
        },
        Cell {
            label: "per-list-path 65536x512 list",
            entries: leaf_entries,
            entry_bytes: 512,
            encoder_kind: EncoderKind::PerListPath { list_key: LIST_KEY },
            insert_kind: InsertKind::PerListAppend,
        },
        Cell {
            label: "per-list-node 131072x32 list",
            entries: node_entries,
            entry_bytes: 32,
            encoder_kind: EncoderKind::PerListNode { list_key: LIST_KEY },
            insert_kind: InsertKind::PerListAppend,
        },
    ];
    for cell in &cells {
        run_cell(cell);
    }
}
