#![allow(clippy::print_stdout)]
//! Throughput of the sigma = 6.4 discrete Gaussian sampler, reported against
//! the raw ChaCha20 word rate so the rejection loop's overhead is readable.

use std::hint::black_box;
use std::time::Instant;

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use raven_isimplepir::query::gauss_sample_sigma_6_4;

const WARMUP_DRAWS: usize = 50_000;
const MEASURED_DRAWS: usize = 500_000;
const BASELINE_WORDS: usize = 20_000_000;

fn draw(rng: &mut ChaCha20Rng, draws: usize) -> i64 {
    let mut accumulator = 0i64;
    for _ in 0..draws {
        accumulator = accumulator.wrapping_add(gauss_sample_sigma_6_4(rng));
    }
    accumulator
}

fn main() {
    let mut rng = ChaCha20Rng::from_seed([0x5a; 32]);
    black_box(draw(&mut rng, WARMUP_DRAWS));

    let start = Instant::now();
    black_box(draw(&mut rng, MEASURED_DRAWS));
    let sampler_seconds = start.elapsed().as_secs_f64();

    let start = Instant::now();
    let mut accumulator = 0u64;
    for _ in 0..BASELINE_WORDS {
        accumulator = accumulator.wrapping_add(rng.next_u64());
    }
    black_box(accumulator);
    let baseline_seconds = start.elapsed().as_secs_f64();

    let draws_per_second = MEASURED_DRAWS as f64 / sampler_seconds;
    let words_per_second = BASELINE_WORDS as f64 / baseline_seconds;
    println!(
        "gauss_sample_sigma_6_4  {draws_per_second:>12.0} draws/s  {:>9.1} ns/draw  ({MEASURED_DRAWS} draws)",
        sampler_seconds * 1e9 / MEASURED_DRAWS as f64
    );
    println!(
        "chacha20 next_u64       {words_per_second:>12.0} words/s  {:>9.1} ns/word ({BASELINE_WORDS} words)",
        baseline_seconds * 1e9 / BASELINE_WORDS as f64
    );
    println!(
        "sampler cost            {:>12.1} next_u64-equivalents per draw",
        words_per_second / draws_per_second
    );
}
