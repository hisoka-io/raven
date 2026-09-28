//! Per-shard re-encode cost across cell shapes; per-insert wall time is
//! `dirty_shards x per_shard_re_encode`. Also the logical cost of seeding a whole PPOI
//! block, batched against row by row. Gated, stderr-only.

#![allow(
    clippy::expect_used,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing
)]

use std::time::Instant;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_engine::inspire::{self, apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::orchestrator::LEAVES_PER_PPOI_BLOCK;
use raven_railgun_engine::pir_table::{PerListPath10Encoder, PirTableEncoder};
use raven_railgun_persistence::{PpoiEventType, WalEntryPayload};

const CELLS: &[(u32, usize, &str)] = &[
    (16, 32, "65k_x_32B"),
    (16, 64, "65k_x_64B"),   // gamma=32
    (16, 128, "65k_x_128B"), // gamma=64
    (16, 256, "65k_x_256B"), // gamma=128
    (16, 512, "65k_x_512B"),
    (17, 32, "131k_x_32B"),
];

const SAMPLES: usize = 5;

#[test]
#[ignore = "per-shard re-encode across all cell shapes; ~5-10 minutes. Trigger: changing per-shard \
            re-encode or which shards an insert dirties."]
fn per_shard_re_encode_cost_per_cell() {
    eprintln!("INSERT_BENCH: starting per-shard re-encode cost sweep");
    eprintln!("INSERT_BENCH: cell = (entries, record_bytes); samples per cell = {SAMPLES}");
    eprintln!("INSERT_BENCH: ----- BEGIN -----");

    for (entries_log2, record_bytes, label) in CELLS {
        let entries = 1usize << entries_log2;
        let total_bytes = entries.checked_mul(*record_bytes).expect("overflow");

        eprintln!(
            "INSERT_BENCH: cell={label} entries={entries} record_bytes={record_bytes} \
             total_DB_MiB={total_mib:.2}",
            total_mib = (total_bytes as f64) / (1024.0 * 1024.0)
        );

        let setup_start = Instant::now();
        let params = InspireParams::secure_128_d2048();
        #[allow(clippy::cast_possible_truncation)]
        let mut db: Vec<u8> = (0..entries)
            .flat_map(|i| (0..*record_bytes).map(move |j| ((i * 31 + j * 17) % 251) as u8))
            .collect();
        let (state, _sk) =
            inspire::setup_state(&params, &db, *record_bytes, InspireVariant::TwoPacking)
                .expect("setup_state");
        let setup_elapsed = setup_start.elapsed();
        eprintln!(
            "INSERT_BENCH: cell={label} setup_ms={ms}",
            ms = setup_elapsed.as_secs_f64() * 1000.0
        );

        let mut encoded_db = (*state.encoded_db).clone();
        let total_shards = encoded_db.shards.len();
        let entries_per_shard = encoded_db.config.entries_per_shard() as usize;
        let shard_byte_len = entries_per_shard.checked_mul(*record_bytes).expect("ov");

        eprintln!(
            "INSERT_BENCH: cell={label} total_shards={total_shards} \
             entries_per_shard={entries_per_shard} shard_byte_len={shard_byte_len}",
        );

        let target_shard_id = 0u32;
        let mut samples_ms: Vec<f64> = Vec::with_capacity(SAMPLES);
        for sample_idx in 0..SAMPLES {
            // Vary the buffer each sample to defeat constant-input caching.
            let mut_offset = (sample_idx * 1024) % shard_byte_len.max(1);
            db[mut_offset] = db[mut_offset].wrapping_add(1);

            let shard_bytes = &db[..shard_byte_len];
            let start = Instant::now();
            inspire::re_encode_shard(
                &mut encoded_db,
                &params,
                target_shard_id,
                shard_bytes,
                *record_bytes,
            )
            .expect("re_encode_shard");
            let elapsed = start.elapsed();
            let ms = elapsed.as_secs_f64() * 1000.0;
            samples_ms.push(ms);
            eprintln!("INSERT_BENCH: cell={label} sample={sample_idx} per_shard_re_encode_ms={ms}");
        }

        samples_ms.sort_by(|a, b| a.partial_cmp(b).expect("not NaN"));
        let median = samples_ms[samples_ms.len() / 2];
        let mean: f64 = samples_ms.iter().sum::<f64>() / (samples_ms.len() as f64);
        let min = samples_ms.first().copied().expect("nonempty");
        let max = samples_ms.last().copied().expect("nonempty");
        eprintln!(
            "INSERT_BENCH: cell={label} per_shard_re_encode_ms_summary \
             min={min} median={median} mean={mean} max={max}"
        );

        let full_db_re_encode_ms = median * (total_shards as f64);
        eprintln!(
            "INSERT_BENCH: cell={label} projected_full_DB_re_encode_ms={full_db_re_encode_ms} \
             (= per_shard_median * total_shards)"
        );

        eprintln!("INSERT_BENCH: ---");
    }

    eprintln!("INSERT_BENCH: ----- END -----");
}

/// A block of distinct canonical blinded commitments, one list, one row per slot.
fn ppoi_block_rows() -> Vec<(WalEntryPayload, u64)> {
    (0..LEAVES_PER_PPOI_BLOCK)
        .map(|list_index| {
            let mut bc = [0u8; 32];
            bc[20] = 0x01;
            bc[28..].copy_from_slice(&list_index.to_be_bytes());
            let payload = WalEntryPayload::PpoiListLeafAdded {
                list_key: [0x42; 32],
                list_index,
                blinded_commitment: bc,
                event_type: PpoiEventType::Shield,
                validated_merkleroot: [0; 32],
            };
            (payload, 1_000 + u64::from(list_index))
        })
        .collect()
}

#[test]
#[ignore = "seeds one 65,536-row PPOI block batched and row by row; about 30-60 s. Trigger: \
            changing Imt::insert_leaves, LogicalLeafStore::seed_leaf_run or merkle_node."]
fn ppoi_block_seed_batched_vs_per_row() {
    // Four rows a shard, so every row dirties shards of its own and a dirty-set divergence shows.
    let encoder = PerListPath10Encoder::new(4, [0x42; 32]).expect("encoder");
    let rows = ppoi_block_rows();

    let mut seeded = LogicalLeafStore::new();
    let start = Instant::now();
    seeded
        .seed_leaf_run(&rows, &encoder)
        .expect("seed_leaf_run");
    let seed_s = start.elapsed().as_secs_f64();

    let mut applied = LogicalLeafStore::new();
    let start = Instant::now();
    for (payload, height) in &rows {
        apply_wal_entry(&mut applied, payload, *height, &encoder).expect("apply");
    }
    let apply_s = start.elapsed().as_secs_f64();

    assert_eq!(
        seeded.ppoi_imt_root(&[0x42; 32]),
        applied.ppoi_imt_root(&[0x42; 32]),
        "the batched seed must reach the row-by-row root"
    );
    assert_eq!(
        seeded.dirty_shards(),
        applied.dirty_shards(),
        "the batched seed must dirty the shards row-by-row apply dirties"
    );
    assert_eq!(
        seeded.dirty_shards().len(),
        (LEAVES_PER_PPOI_BLOCK / encoder.entries_per_shard()) as usize
    );
    eprintln!(
        "INSERT_BENCH: ppoi_block rows={rows} seed_leaf_run_s={seed_s:.3} per_row_apply_s={apply_s:.3} \
         speedup={speedup:.1}x",
        rows = rows.len(),
        speedup = apply_s / seed_s
    );
}
