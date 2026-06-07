//! Insert / re-encode cost bench (`#[ignore]`-gated). Measures per-shard
//! re-encode cost across cell shapes; total per-insert wall-clock is
//! `dirty_shards × per_shard_re_encode`. Output is stderr-only.

#![allow(
    clippy::expect_used,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing
)]

use std::time::Instant;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_engine::inspire;

const CELLS: &[(u32, usize, &str)] = &[
    (16, 32, "65k_x_32B"),
    (16, 64, "65k_x_64B"),   // γ=32
    (16, 128, "65k_x_128B"), // γ=64
    (16, 256, "65k_x_256B"), // γ=128
    (16, 512, "65k_x_512B"),
    (17, 32, "131k_x_32B"),
];

const SAMPLES: usize = 5;

#[test]
#[ignore = "per-shard re-encode bench takes ~5-10 minutes across all cells"]
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
