//! Per-hash wall time of `hash_n` against a hasher built fresh for every call.
//! Both paths run interleaved in one process so host load skews them alike. Gated, stderr-only.

#![allow(
    clippy::expect_used,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::indexing_slicing
)]

use std::time::Instant;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use raven_railgun_poseidon::hash_n;

const ARITIES: &[usize] = &[2, 3, 12];
const HASHES_PER_SAMPLE: usize = 4_000;
const SAMPLES: usize = 7;

fn input(seed: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[1] = 0x5a;
    out[24..].copy_from_slice(&seed.to_be_bytes());
    out
}

/// The uncached `hash_n` it replaced, step for step: a hasher built per call, and the same
/// canonical-decode check on every input.
fn fresh_hash(inputs: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = Poseidon::<Fr>::new_circom(inputs.len()).expect("new_circom");
    let mut frs: Vec<Fr> = Vec::with_capacity(inputs.len());
    for buf in inputs {
        let fr = Fr::from_be_bytes_mod_order(buf);
        assert_eq!(fr.into_bigint().to_bytes_be().as_slice(), buf.as_slice());
        frs.push(fr);
    }
    let bytes = hasher.hash(&frs).expect("hash").into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn median_ns_per_hash(samples: &mut [f64]) -> f64 {
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

#[test]
#[ignore = "timing harness, about 10-30 s. Trigger: changing hash_n or bumping light-poseidon."]
fn hash_n_per_call_vs_fresh_hasher() {
    for &arity in ARITIES {
        let inputs: Vec<[u8; 32]> = (0..arity as u64).map(input).collect();
        assert_eq!(hash_n(&inputs).expect("hash_n"), fresh_hash(&inputs));

        let mut cached = Vec::with_capacity(SAMPLES);
        let mut fresh = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let mut acc = inputs.clone();
            let start = Instant::now();
            for _ in 0..HASHES_PER_SAMPLE {
                acc[0] = hash_n(&acc).expect("hash_n");
            }
            cached.push(start.elapsed().as_nanos() as f64 / HASHES_PER_SAMPLE as f64);
            std::hint::black_box(&acc);

            let mut acc = inputs.clone();
            let start = Instant::now();
            for _ in 0..HASHES_PER_SAMPLE {
                acc[0] = fresh_hash(&acc);
            }
            fresh.push(start.elapsed().as_nanos() as f64 / HASHES_PER_SAMPLE as f64);
            std::hint::black_box(&acc);
        }
        let cached_ns = median_ns_per_hash(&mut cached);
        let fresh_ns = median_ns_per_hash(&mut fresh);
        eprintln!(
            "HASH_BENCH: arity={arity} hash_n_ns={cached_ns:.0} fresh_hasher_ns={fresh_ns:.0} \
             saving_pct={saving:.1}",
            saving = 100.0 * (fresh_ns - cached_ns) / fresh_ns
        );
    }
}
