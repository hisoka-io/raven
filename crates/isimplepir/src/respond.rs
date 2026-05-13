//! `Answer(DB, q) = DB . q` mod 2^32. Rayon-parallel under
//! `--features server` with AVX2 / AVX-512F dispatch on x86_64;
//! scalar fallback otherwise.

use serde::{Deserialize, Serialize};

use crate::error::{IsimplePirError, Result};
use crate::setup::ServerState;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerResponse {
    pub answer: Vec<u32>,
}

pub fn respond(state: &ServerState, query: &[u32]) -> Result<ServerResponse> {
    let params = &state.params;
    if query.len() != params.m {
        return Err(IsimplePirError::QueryShape {
            reason: format!(
                "query length {} does not match M = {}",
                query.len(),
                params.m,
            ),
        });
    }

    let answer = respond_matmul(&state.db, query, params.l, params.m);
    Ok(ServerResponse { answer })
}

/// `Sum_k row[k] * q[k] mod 2^32`. Defines byte-identity reference.
#[inline]
fn row_dot_scalar(row: &[u32], q: &[u32]) -> u32 {
    let n = row.len().min(q.len());
    let mut acc: u32 = 0;
    for k in 0..n {
        let Some(&d_ik) = row.get(k) else { continue };
        let Some(&q_k) = q.get(k) else { continue };
        acc = acc.wrapping_add(d_ik.wrapping_mul(q_k));
    }
    acc
}

/// AVX2 8-wide row dot.
///
/// # Safety
/// Caller MUST runtime-detect AVX2.
#[cfg(all(feature = "server", target_arch = "x86_64"))]
#[allow(unsafe_code)]
#[target_feature(enable = "avx2")]
unsafe fn row_dot_avx2(row: &[u32], q: &[u32]) -> u32 {
    use core::arch::x86_64::{
        _mm256_add_epi32, _mm256_loadu_si256, _mm256_mullo_epi32, _mm256_setzero_si256,
        _mm256_storeu_si256,
    };
    let n = row.len().min(q.len());
    let mut acc_vec = _mm256_setzero_si256();
    let mut k: usize = 0;

    while k + 8 <= n {
        // SAFETY: ptr.add(k) in-bounds; loadu unaligned-safe.
        #[allow(clippy::cast_ptr_alignment)]
        let d = _mm256_loadu_si256(row.as_ptr().add(k).cast::<core::arch::x86_64::__m256i>());
        #[allow(clippy::cast_ptr_alignment)]
        let qv = _mm256_loadu_si256(q.as_ptr().add(k).cast::<core::arch::x86_64::__m256i>());
        acc_vec = _mm256_add_epi32(acc_vec, _mm256_mullo_epi32(d, qv));
        k += 8;
    }

    let mut lanes = [0u32; 8];
    #[allow(clippy::cast_ptr_alignment)]
    _mm256_storeu_si256(
        lanes.as_mut_ptr().cast::<core::arch::x86_64::__m256i>(),
        acc_vec,
    );
    let mut acc = lanes.iter().fold(0u32, |a, &x| a.wrapping_add(x));

    while k < n {
        let Some(&d_ik) = row.get(k) else { break };
        let Some(&q_k) = q.get(k) else { break };
        acc = acc.wrapping_add(d_ik.wrapping_mul(q_k));
        k += 1;
    }
    acc
}

/// AVX-512F 16-wide row dot.
///
/// # Safety
/// Caller MUST runtime-detect AVX-512F.
#[cfg(all(feature = "server", target_arch = "x86_64"))]
#[allow(unsafe_code)]
#[target_feature(enable = "avx512f")]
unsafe fn row_dot_avx512(row: &[u32], q: &[u32]) -> u32 {
    use core::arch::x86_64::{
        _mm512_add_epi32, _mm512_loadu_si512, _mm512_mullo_epi32, _mm512_reduce_add_epi32,
        _mm512_setzero_si512,
    };
    let n = row.len().min(q.len());
    let mut acc_vec = _mm512_setzero_si512();
    let mut k: usize = 0;

    while k + 16 <= n {
        // SAFETY: ptr.add(k) in-bounds; loadu unaligned-safe.
        #[allow(clippy::cast_ptr_alignment)]
        let d = _mm512_loadu_si512(row.as_ptr().add(k).cast::<core::arch::x86_64::__m512i>());
        #[allow(clippy::cast_ptr_alignment)]
        let qv = _mm512_loadu_si512(q.as_ptr().add(k).cast::<core::arch::x86_64::__m512i>());
        acc_vec = _mm512_add_epi32(acc_vec, _mm512_mullo_epi32(d, qv));
        k += 16;
    }

    let mut acc: u32 = _mm512_reduce_add_epi32(acc_vec) as u32;

    while k < n {
        let Some(&d_ik) = row.get(k) else { break };
        let Some(&q_k) = q.get(k) else { break };
        acc = acc.wrapping_add(d_ik.wrapping_mul(q_k));
        k += 1;
    }
    acc
}

#[cfg(feature = "server")]
#[derive(Clone, Copy)]
enum RowKernel {
    Scalar,
    #[cfg(target_arch = "x86_64")]
    Avx2,
    #[cfg(target_arch = "x86_64")]
    Avx512,
}

/// Below this row width, scalar beats SIMD dispatch overhead.
#[cfg(feature = "server")]
const MIN_SIMD_ROW_LEN: usize = 4096;

/// Row-major `DB . q`; dispatches scalar / AVX2 / AVX-512 per call.
#[cfg(feature = "server")]
fn respond_matmul(db: &[u32], q: &[u32], l: usize, m: usize) -> Vec<u32> {
    use rayon::prelude::*;

    #[cfg(target_arch = "x86_64")]
    let (has_avx512, has_avx2) = (
        std::is_x86_feature_detected!("avx512f"),
        std::is_x86_feature_detected!("avx2"),
    );

    let kernel: RowKernel = {
        if m < MIN_SIMD_ROW_LEN {
            RowKernel::Scalar
        } else {
            #[cfg(target_arch = "x86_64")]
            {
                if has_avx512 {
                    RowKernel::Avx512
                } else if has_avx2 {
                    RowKernel::Avx2
                } else {
                    RowKernel::Scalar
                }
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                RowKernel::Scalar
            }
        }
    };

    (0..l)
        .into_par_iter()
        .map(|i| {
            let row_start = i.saturating_mul(m);
            let row_end = row_start.saturating_add(m);
            let Some(row) = db.get(row_start..row_end) else {
                return 0u32;
            };
            match kernel {
                RowKernel::Scalar => row_dot_scalar(row, q),
                #[cfg(target_arch = "x86_64")]
                RowKernel::Avx2 => {
                    // SAFETY: AVX2 detected.
                    #[allow(unsafe_code)]
                    unsafe {
                        row_dot_avx2(row, q)
                    }
                }
                #[cfg(target_arch = "x86_64")]
                RowKernel::Avx512 => {
                    // SAFETY: AVX-512F detected.
                    #[allow(unsafe_code)]
                    unsafe {
                        row_dot_avx512(row, q)
                    }
                }
            }
        })
        .collect()
}

/// Single-threaded scalar fallback (wasm32, embedded).
#[cfg(not(feature = "server"))]
fn respond_matmul(db: &[u32], q: &[u32], l: usize, m: usize) -> Vec<u32> {
    let mut answer = vec![0u32; l];
    for i in 0..l {
        let row_start = i.saturating_mul(m);
        let row_end = row_start.saturating_add(m);
        let Some(row) = db.get(row_start..row_end) else {
            continue;
        };
        if let Some(slot) = answer.get_mut(i) {
            *slot = row_dot_scalar(row, q);
        }
    }
    answer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matmul_u32_wrapping() {
        let db = vec![u32::MAX, 2, 3, 4];
        let q = vec![1, 1];
        let out = respond_matmul(&db, &q, 2, 2);
        // u32::MAX * 1 + 2 * 1 = u32::MAX + 2 wraps to 1.
        assert_eq!(out[0], 1);
        assert_eq!(out[1], 7);
    }

    #[test]
    fn respond_rejects_wrong_query_length() {
        let params = crate::params::LweParams {
            n: 4,
            log2_q: 32,
            p: 13,
            l: 2,
            m: 3,
            bits_per_element: 4,
        };
        let state = ServerState {
            db: vec![0u32; 6],
            params,
            a_seed: [0u8; 32],
            version: crate::version::HintVersion::INITIAL,
        };
        let short_q = vec![0u32; 2];
        assert!(matches!(
            respond(&state, &short_q),
            Err(IsimplePirError::QueryShape { .. })
        ));
    }

    #[cfg(all(feature = "server", target_arch = "x86_64"))]
    #[test]
    fn avx2_matches_scalar_byte_identity() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }

        use rand_chacha::ChaCha20Rng;
        use rand_core::{RngCore, SeedableRng};

        let lengths: &[usize] = &[
            0, 1, 3, 7, 8, 9, 15, 16, 17, 64, 1000, 1024, 2731, 15447, 21846,
        ];
        let seeds: &[[u8; 32]] = &[[0u8; 32], [0xABu8; 32], [0x5Au8; 32]];

        for &len in lengths {
            for &seed in seeds {
                let mut rng = ChaCha20Rng::from_seed(seed);
                let mut row = vec![0u32; len];
                let mut q = vec![0u32; len];
                for slot in row.iter_mut() {
                    let mut b = [0u8; 4];
                    rng.fill_bytes(&mut b);
                    *slot = u32::from_le_bytes(b);
                }
                for slot in q.iter_mut() {
                    let mut b = [0u8; 4];
                    rng.fill_bytes(&mut b);
                    *slot = u32::from_le_bytes(b);
                }
                let scalar = row_dot_scalar(&row, &q);
                // SAFETY: AVX2 detected.
                #[allow(unsafe_code)]
                let avx2 = unsafe { row_dot_avx2(&row, &q) };
                assert_eq!(
                    scalar, avx2,
                    "row_dot scalar vs avx2 diverge at len={len}, seed={seed:?}"
                );
            }
        }

        // u32-wraparound edge.
        let row = vec![u32::MAX; 17];
        let q = vec![2u32; 17];
        let scalar = row_dot_scalar(&row, &q);
        #[allow(unsafe_code)]
        let avx2 = unsafe { row_dot_avx2(&row, &q) };
        assert_eq!(scalar, avx2);
        assert_eq!(scalar, u32::MAX.wrapping_sub(33));
    }

    #[cfg(all(feature = "server", target_arch = "x86_64"))]
    #[test]
    fn avx512_matches_scalar_byte_identity() {
        if !std::is_x86_feature_detected!("avx512f") {
            return;
        }

        use rand_chacha::ChaCha20Rng;
        use rand_core::{RngCore, SeedableRng};

        let lengths: &[usize] = &[
            0, 1, 3, 7, 15, 16, 17, 31, 32, 33, 64, 1000, 1024, 2731, 15447, 21846,
        ];
        let seeds: &[[u8; 32]] = &[[0u8; 32], [0xABu8; 32], [0x5Au8; 32]];

        for &len in lengths {
            for &seed in seeds {
                let mut rng = ChaCha20Rng::from_seed(seed);
                let mut row = vec![0u32; len];
                let mut q = vec![0u32; len];
                for slot in row.iter_mut() {
                    let mut b = [0u8; 4];
                    rng.fill_bytes(&mut b);
                    *slot = u32::from_le_bytes(b);
                }
                for slot in q.iter_mut() {
                    let mut b = [0u8; 4];
                    rng.fill_bytes(&mut b);
                    *slot = u32::from_le_bytes(b);
                }
                let scalar = row_dot_scalar(&row, &q);
                // SAFETY: AVX-512F detected.
                #[allow(unsafe_code)]
                let avx512 = unsafe { row_dot_avx512(&row, &q) };
                assert_eq!(
                    scalar, avx512,
                    "row_dot scalar vs avx512 diverge at len={len}, seed={seed:?}"
                );
            }
        }

        let row = vec![u32::MAX; 33];
        let q = vec![2u32; 33];
        let scalar = row_dot_scalar(&row, &q);
        #[allow(unsafe_code)]
        let avx512 = unsafe { row_dot_avx512(&row, &q) };
        assert_eq!(scalar, avx512);
        assert_eq!(scalar, u32::MAX.wrapping_sub(65));
    }
}
