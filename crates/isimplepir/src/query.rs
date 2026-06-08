//! Client query: `q = A . s + e`; `q[col] += delta`. Client
//! retains `s` for `Extract`.

use rand_core::{RngCore, TryRngCore};
use serde::{Deserialize, Serialize};

use crate::error::{IsimplePirError, Result};
use crate::params::LweParams;
use crate::setup::{derive_a_matrix, SEED_BYTES};

/// 129-entry CDF table at sigma = 6.4 (`simplepir/pir/gauss.go`).
/// Do not modify without recomputing the correctness bound.
pub const CDF_TABLE_SIGMA_6_4: &[f64] = &[
    0.5,
    0.987867,
    0.952345,
    0.895957,
    0.822578,
    0.736994,
    0.644389,
    0.549831,
    0.457833,
    0.372034,
    0.295023,
    0.22831,
    0.172422,
    0.127074,
    0.0913938,
    0.0641467,
    0.0439369,
    0.0293685,
    0.0191572,
    0.0121949,
    0.00757568,
    0.00459264,
    0.00271706,
    0.00156868,
    0.000883826,
    0.000485955,
    0.000260749,
    0.000136536,
    6.97696e-5,
    3.47923e-5,
    1.69316e-5,
    8.041e-6,
    3.72665e-6,
    1.68549e-6,
    7.43923e-7,
    3.20426e-7,
    1.34687e-7,
    5.52484e-8,
    2.21163e-8,
    8.63973e-9,
    3.29371e-9,
    1.22537e-9,
    4.44886e-10,
    1.57625e-10,
    5.45004e-11,
    1.83896e-11,
    6.05535e-12,
    1.94583e-12,
    6.10194e-13,
    1.86736e-13,
    5.57679e-14,
    1.62532e-14,
    4.62263e-15,
    1.28303e-15,
    3.47522e-16,
    9.18597e-17,
    2.36954e-17,
    5.96487e-18,
    1.46533e-18,
    3.5129e-19,
    8.21851e-20,
    1.87637e-20,
    4.18062e-21,
    9.08991e-22,
    1.92875e-22,
    3.99383e-23,
    8.07049e-24,
    1.5915e-24,
    3.06275e-25,
    5.75194e-26,
    1.05418e-26,
    1.88542e-27,
    3.29081e-28,
    5.60522e-29,
    9.31708e-30,
    1.51135e-30,
    2.39247e-31,
    3.69594e-32,
    5.57187e-33,
    8.19735e-34,
    1.17691e-34,
    1.64896e-35,
    2.25463e-36,
    3.00841e-37,
    3.91737e-38,
    4.97795e-39,
    6.1731e-40,
    7.47055e-41,
    8.82266e-42,
    1.01682e-42,
    1.14363e-43,
    1.25523e-44,
    1.34449e-45,
    1.40537e-46,
    1.43357e-47,
    1.42708e-48,
    1.38634e-49,
    1.31429e-50,
    1.21593e-51,
    1.0978e-52,
    9.67246e-54,
    8.31661e-55,
    6.97835e-56,
    5.71421e-57,
    4.56622e-58,
    3.56086e-59,
    2.70987e-60,
    2.01252e-61,
    1.45858e-62,
    1.03161e-63,
    7.12032e-65,
    4.79601e-66,
    3.15252e-67,
    2.02224e-68,
    1.26591e-69,
    7.73344e-71,
    4.6104e-72,
    2.68226e-73,
    1.52287e-74,
    8.4376e-76,
    4.56219e-77,
    2.40727e-78,
    1.23958e-79,
    6.22901e-81,
    3.05465e-82,
    1.46185e-83,
    6.82713e-85,
    3.11152e-86,
    1.3839e-87,
];

/// Discrete Gaussian sample at sigma = 6.4. Mirrors
/// `simplepir/pir/gauss.go:GaussSample`.
pub fn gauss_sample_sigma_6_4<R: RngCore>(rng: &mut R) -> i64 {
    let table_len = CDF_TABLE_SIGMA_6_4.len() as u64;
    loop {
        let x_candidate = rng.next_u64() % table_len;
        // Uniform f64 in [0, 1): 53 significant bits from rng.
        let y: f64 = (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        let idx = x_candidate as usize;
        let Some(&cdf) = CDF_TABLE_SIGMA_6_4.get(idx) else {
            continue;
        };
        if y < cdf {
            let sign_bit = rng.next_u64() & 1;
            let mut x = x_candidate as i64;
            if sign_bit == 0 {
                x = -x;
            }
            return x;
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientState {
    /// LWE secret `s in Z_q^n`.
    pub secret: Vec<u32>,
    pub row: usize,
    pub col: usize,
    /// Copy of `q`, retained for `Extract`.
    pub query_vec: Vec<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientQuery {
    pub query: Vec<u32>,
}

/// Noise is pre-sampled sequentially before the matmul so RNG
/// consumption is the same under scalar and parallel paths.
fn compute_query_vec(
    a_matrix: &[u32],
    secret: &[u32],
    noise: &[u32],
    m: usize,
    n: usize,
) -> Vec<u32> {
    #[cfg(feature = "server")]
    {
        compute_query_vec_parallel(a_matrix, secret, noise, m, n)
    }
    #[cfg(not(feature = "server"))]
    {
        compute_query_vec_scalar(a_matrix, secret, noise, m, n)
    }
}

/// Scalar reference / wasm32 fallback.
#[allow(dead_code)]
fn compute_query_vec_scalar(
    a_matrix: &[u32],
    secret: &[u32],
    noise: &[u32],
    m: usize,
    n: usize,
) -> Vec<u32> {
    let mut q = vec![0u32; m];
    for k in 0..m {
        let a_row_start = k.saturating_mul(n);
        let mut acc: u32 = 0;
        for j in 0..n {
            let a_idx = a_row_start.saturating_add(j);
            let Some(&a_kj) = a_matrix.get(a_idx) else {
                continue;
            };
            let Some(&s_j) = secret.get(j) else {
                continue;
            };
            acc = acc.wrapping_add(a_kj.wrapping_mul(s_j));
        }
        let noise_k = noise.get(k).copied().unwrap_or(0);
        acc = acc.wrapping_add(noise_k);
        if let Some(slot) = q.get_mut(k) {
            *slot = acc;
        }
    }
    q
}

/// Rayon-parallel; same inner order as scalar.
#[cfg(feature = "server")]
fn compute_query_vec_parallel(
    a_matrix: &[u32],
    secret: &[u32],
    noise: &[u32],
    m: usize,
    n: usize,
) -> Vec<u32> {
    use rayon::prelude::*;

    let mut q = vec![0u32; m];
    q.par_iter_mut().enumerate().for_each(|(k, slot)| {
        let a_row_start = k.saturating_mul(n);
        let mut acc: u32 = 0;
        for j in 0..n {
            let a_idx = a_row_start.saturating_add(j);
            let Some(&a_kj) = a_matrix.get(a_idx) else {
                continue;
            };
            let Some(&s_j) = secret.get(j) else {
                continue;
            };
            acc = acc.wrapping_add(a_kj.wrapping_mul(s_j));
        }
        let noise_k = noise.get(k).copied().unwrap_or(0);
        acc = acc.wrapping_add(noise_k);
        *slot = acc;
    });
    q
}

/// Emit an LWE-encrypted query for `idx` (row-major). Caller
/// retains `state` for `Extract`.
pub fn query<R: RngCore>(
    rng: &mut R,
    a_seed: &[u8; SEED_BYTES],
    params: &LweParams,
    idx: usize,
) -> Result<(ClientState, ClientQuery)> {
    let total = params.l.saturating_mul(params.m);
    if idx >= total {
        return Err(IsimplePirError::QueryShape {
            reason: format!(
                "index {idx} out of range for L*M = {}*{} = {}",
                params.l, params.m, total,
            ),
        });
    }
    let row = idx / params.m;
    let col = idx % params.m;

    let a_matrix = derive_a_matrix(a_seed, params)?;

    let mut secret = vec![0u32; params.n];
    let mut buf = [0u8; 4];
    for slot in secret.iter_mut() {
        rng.try_fill_bytes(&mut buf)
            .map_err(|e| IsimplePirError::Randomness(format!("rng fill: {e}")))?;
        *slot = u32::from_le_bytes(buf);
    }

    let mut noise = vec![0u32; params.m];
    for slot in noise.iter_mut() {
        let e_k = gauss_sample_sigma_6_4(rng);
        *slot = e_k as i64 as u32 as u64 as u32;
    }

    let query_vec = compute_query_vec(&a_matrix, &secret, &noise, params.m, params.n);

    let delta = params.delta();
    let mut query_vec = query_vec;
    if let Some(slot) = query_vec.get_mut(col) {
        *slot = slot.wrapping_add(delta);
    }

    Ok((
        ClientState {
            secret,
            row,
            col,
            query_vec: query_vec.clone(),
        },
        ClientQuery { query: query_vec },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn toy_params() -> LweParams {
        LweParams {
            n: crate::params::LWE_DIM,
            log2_q: crate::params::CIPHERTEXT_MODULUS_LOG2,
            p: 991,
            l: 4,
            m: 4,
            bits_per_element: 9,
        }
    }

    #[test]
    fn gauss_sample_stays_within_table_range() {
        let table_len = CDF_TABLE_SIGMA_6_4.len() as i64;
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        for _ in 0..10_000 {
            let x = gauss_sample_sigma_6_4(&mut rng);
            assert!(
                x.abs() < table_len,
                "sampled {x} outside table range [0, {table_len})"
            );
        }
    }

    #[test]
    fn cdf_table_structure_invariants() {
        let len = CDF_TABLE_SIGMA_6_4.len();
        assert_eq!(len, 129, "CDF table must have exactly 129 entries");
        assert!((CDF_TABLE_SIGMA_6_4[0] - 0.5).abs() < 1e-9);
        for i in 2..len {
            let prev = CDF_TABLE_SIGMA_6_4[i - 1];
            let curr = CDF_TABLE_SIGMA_6_4[i];
            assert!(
                curr <= prev,
                "table not monotone at index {i}: prev = {prev}, curr = {curr}"
            );
        }
    }

    #[test]
    fn query_rejects_out_of_range_idx() {
        let params = toy_params();
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let result = query(&mut rng, &[0u8; 32], &params, 9999);
        assert!(matches!(result, Err(IsimplePirError::QueryShape { .. })));
    }

    #[test]
    fn query_determinism_under_fixed_rng_and_seed() {
        let params = toy_params();
        let mut rng1 = ChaCha20Rng::from_seed([7u8; 32]);
        let mut rng2 = ChaCha20Rng::from_seed([7u8; 32]);
        let (s1, q1) = query(&mut rng1, &[11u8; 32], &params, 5).expect("q1");
        let (s2, q2) = query(&mut rng2, &[11u8; 32], &params, 5).expect("q2");
        assert_eq!(s1.secret, s2.secret);
        assert_eq!(q1.query, q2.query);
    }

    #[cfg(feature = "server")]
    #[test]
    fn compute_query_vec_scalar_vs_parallel_byte_identity() {
        use rand_core::RngCore;
        let shapes: &[(usize, usize)] = &[
            (1, 1),
            (4, 4),
            (4, 1024),
            (64, 1024),
            (1024, 1024),
            (2731, 1024),
        ];
        for &(m, n) in shapes {
            let seed: [u8; 32] = {
                let mut s = [0u8; 32];
                s[..8].copy_from_slice(
                    &((m as u64).wrapping_mul(31).wrapping_add(n as u64)).to_le_bytes(),
                );
                s
            };
            let mut rng = ChaCha20Rng::from_seed(seed);
            let a: Vec<u32> = (0..m * n)
                .map(|_| {
                    let mut b = [0u8; 4];
                    rng.fill_bytes(&mut b);
                    u32::from_le_bytes(b)
                })
                .collect();
            let s: Vec<u32> = (0..n)
                .map(|_| {
                    let mut b = [0u8; 4];
                    rng.fill_bytes(&mut b);
                    u32::from_le_bytes(b)
                })
                .collect();
            let e: Vec<u32> = (0..m)
                .map(|_| {
                    let mut b = [0u8; 4];
                    rng.fill_bytes(&mut b);
                    u32::from_le_bytes(b)
                })
                .collect();
            let scalar = compute_query_vec_scalar(&a, &s, &e, m, n);
            let parallel = compute_query_vec_parallel(&a, &s, &e, m, n);
            assert_eq!(
                scalar, parallel,
                "compute_query_vec_scalar vs _parallel diverge at shape (m={m}, n={n})"
            );
            assert_eq!(scalar.len(), m);
        }
    }
}
