//! `hash_n` reuses one hasher per (thread, arity); every output must equal a hasher built
//! fresh for that call, whatever arities ran before it on the same thread.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use raven_railgun_poseidon::hash_n;

const MAX_ARITY: usize = 12;
const CASES_PER_THREAD: usize = 1_536;

struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

fn to_be32(fr: Fr) -> [u8; 32] {
    let bytes = fr.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// A canonical field element, weighted towards the edges the byte decoding must get right.
fn canonical(rng: &mut SplitMix64) -> [u8; 32] {
    match rng.next() % 8 {
        0 => [0u8; 32],
        1 => to_be32(-Fr::from(1u64)),
        2 => to_be32(Fr::from(rng.next())),
        _ => {
            let mut raw = [0u8; 32];
            for chunk in raw.chunks_mut(8) {
                chunk.copy_from_slice(&rng.next().to_be_bytes());
            }
            to_be32(Fr::from_be_bytes_mod_order(&raw))
        }
    }
}

fn fresh(inputs: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = Poseidon::<Fr>::new_circom(inputs.len()).expect("new_circom");
    let frs: Vec<Fr> = inputs
        .iter()
        .map(|b| Fr::from_be_bytes_mod_order(b))
        .collect();
    to_be32(hasher.hash(&frs).expect("fresh hash"))
}

fn run_cases(seed: u64) {
    let mut rng = SplitMix64(seed);
    let mut seen = [0usize; MAX_ARITY];
    for case in 0..CASES_PER_THREAD {
        // A random arity each step, so every slot is reused after other slots ran.
        let arity = 1 + usize::try_from(rng.next() % MAX_ARITY as u64).expect("arity fits");
        seen[arity - 1] += 1;
        let inputs: Vec<[u8; 32]> = (0..arity).map(|_| canonical(&mut rng)).collect();

        // A refused input between two hashes must not disturb the cached slot.
        if case % 17 == 0 {
            let mut bad = inputs.clone();
            bad[0] = [0xff; 32];
            assert!(hash_n(&bad).is_err(), "non-canonical input must be refused");
        }

        let cached = hash_n(&inputs).expect("cached hash");
        assert_eq!(
            cached,
            fresh(&inputs),
            "seed {seed} case {case} arity {arity}: cached hasher diverged from a fresh one"
        );
    }
    assert!(
        seen.iter().all(|&n| n > 0),
        "every arity must be exercised: {seen:?}"
    );
}

#[test]
fn cached_hash_equals_fresh_hash_at_every_arity() {
    run_cases(0x5eed_0001);
}

#[test]
fn cached_hash_is_per_thread() {
    let handles: Vec<_> = (0..4u64)
        .map(|t| std::thread::spawn(move || run_cases(0x7_0000 + t)))
        .collect();
    for handle in handles {
        handle.join().expect("worker thread");
    }
}

#[test]
fn unsupported_arity_is_refused() {
    assert!(hash_n(&[]).is_err());
    assert!(hash_n(&[[0u8; 32]; MAX_ARITY + 1]).is_err());
    assert_eq!(
        hash_n(&[[0u8; 32]; 2]).expect("arity 2 after refusals"),
        fresh(&[[0u8; 32]; 2])
    );
}

/// BN254 scalar modulus, big-endian.
const MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

#[test]
fn an_input_is_refused_exactly_when_it_is_at_or_above_the_modulus() {
    assert_eq!(to_be32(-Fr::from(1u64)), {
        let mut below = MODULUS_BE;
        below[31] -= 1;
        below
    });
    let mut above = MODULUS_BE;
    above[31] += 1;
    for refused in [MODULUS_BE, above, [0xff; 32]] {
        assert!(hash_n(&[refused, [0u8; 32]]).is_err(), "{refused:02x?}");
        assert!(hash_n(&[[0u8; 32], refused]).is_err(), "{refused:02x?}");
    }

    let mut rng = SplitMix64(0x00de_c0de);
    for _ in 0..4_096 {
        let mut raw = [0u8; 32];
        for chunk in raw.chunks_mut(8) {
            chunk.copy_from_slice(&rng.next().to_be_bytes());
        }
        // Keep the leading limb near the modulus so both verdicts are common.
        raw[0] = 0x30 + u8::from(rng.next().is_multiple_of(2));
        let pair = [[0u8; 32], raw];
        match hash_n(&pair) {
            Ok(hash) => {
                assert!(raw < MODULUS_BE, "accepted {raw:02x?}");
                assert_eq!(hash, fresh(&pair));
            }
            Err(_) => assert!(raw >= MODULUS_BE, "refused {raw:02x?}"),
        }
    }
}
