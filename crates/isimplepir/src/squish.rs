//! Column-packed DB and packed matmul. When `p <= 2^SQUISH_BASIS`,
//! `SQUISH_COMPRESSION` plaintexts pack into one `u32`, giving a
//! 3x server-side memory cut. `respond_packed` is byte-identical
//! to [`crate::respond::respond`].
//!
//! On `x86_64` with AVX2 / AVX-512F, the per-row dot uses
//! `_mm{256,512}_i32gather_epi32` for stride-3 query reads.

#[cfg(all(feature = "server", target_arch = "x86_64"))]
#[allow(unsafe_code)]
mod simd {
    use super::{SQUISH_BASIS, SQUISH_COMPRESSION};

    /// AVX2 packed row dot. 8 cells / iteration = 24 mul-adds.
    ///
    /// # Safety
    /// Caller MUST runtime-detect AVX2.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn packed_row_dot_avx2(
        packed: &[u32],
        m_packed: usize,
        row: usize,
        query: &[u32],
        original_m: usize,
        mask_u32: u32,
    ) -> u32 {
        use core::arch::x86_64::{
            __m256i, _mm256_add_epi32, _mm256_and_si256, _mm256_i32gather_epi32,
            _mm256_loadu_si256, _mm256_mullo_epi32, _mm256_set1_epi32, _mm256_set_epi32,
            _mm256_setzero_si256, _mm256_srli_epi32, _mm256_storeu_si256,
        };

        let row_start = row.saturating_mul(m_packed);
        let Some(packed_row) = packed.get(row_start..row_start.saturating_add(m_packed)) else {
            return 0;
        };

        let mask_vec = _mm256_set1_epi32(mask_u32 as i32);
        let stride_idx = _mm256_set_epi32(21, 18, 15, 12, 9, 6, 3, 0);

        let mut acc_vec = _mm256_setzero_si256();
        let mut j: usize = 0;
        while j + 8 <= m_packed
            && j.wrapping_add(8).saturating_mul(SQUISH_COMPRESSION) <= original_m
        {
            let base_q = j.saturating_mul(SQUISH_COMPRESSION);
            // SAFETY: j + 8 <= m_packed; 32-byte load fits packed_row[j..j+8].
            #[allow(clippy::cast_ptr_alignment)]
            let cells = _mm256_loadu_si256(packed_row.as_ptr().add(j).cast::<__m256i>());

            let vs_0 = _mm256_and_si256(cells, mask_vec);
            // SAFETY: base_q + 21 < original_m by loop cond.
            let q_0 =
                _mm256_i32gather_epi32::<4>(query.as_ptr().add(base_q).cast::<i32>(), stride_idx);
            acc_vec = _mm256_add_epi32(acc_vec, _mm256_mullo_epi32(vs_0, q_0));

            let vs_1 = _mm256_and_si256(_mm256_srli_epi32::<10>(cells), mask_vec);
            // SAFETY: base_q + 22 < original_m.
            let q_1 = _mm256_i32gather_epi32::<4>(
                query.as_ptr().add(base_q.saturating_add(1)).cast::<i32>(),
                stride_idx,
            );
            acc_vec = _mm256_add_epi32(acc_vec, _mm256_mullo_epi32(vs_1, q_1));

            let vs_2 = _mm256_and_si256(_mm256_srli_epi32::<20>(cells), mask_vec);
            // SAFETY: base_q + 23 < original_m.
            let q_2 = _mm256_i32gather_epi32::<4>(
                query.as_ptr().add(base_q.saturating_add(2)).cast::<i32>(),
                stride_idx,
            );
            acc_vec = _mm256_add_epi32(acc_vec, _mm256_mullo_epi32(vs_2, q_2));

            j += 8;
        }

        let mut lanes = [0u32; 8];
        #[allow(clippy::cast_ptr_alignment)]
        _mm256_storeu_si256(lanes.as_mut_ptr().cast::<__m256i>(), acc_vec);
        let mut acc = lanes.iter().fold(0u32, |a, &x| a.wrapping_add(x));

        while j < m_packed {
            let Some(&cell) = packed_row.get(j) else {
                break;
            };
            for k in 0..SQUISH_COMPRESSION {
                let q_idx = j.saturating_mul(SQUISH_COMPRESSION).saturating_add(k);
                let q_val = query.get(q_idx).copied().unwrap_or(0);
                if q_val == 0 {
                    continue;
                }
                let shift = (k as u32).saturating_mul(SQUISH_BASIS);
                let v = cell.wrapping_shr(shift) & mask_u32;
                acc = acc.wrapping_add(v.wrapping_mul(q_val));
            }
            j += 1;
        }
        acc
    }

    /// AVX-512F packed row dot. 16 cells / iteration = 48 mul-adds.
    ///
    /// # Safety
    /// Caller MUST runtime-detect AVX-512F.
    #[target_feature(enable = "avx512f")]
    pub(super) unsafe fn packed_row_dot_avx512(
        packed: &[u32],
        m_packed: usize,
        row: usize,
        query: &[u32],
        original_m: usize,
        mask_u32: u32,
    ) -> u32 {
        use core::arch::x86_64::{
            __m512i, _mm512_add_epi32, _mm512_and_si512, _mm512_i32gather_epi32,
            _mm512_loadu_si512, _mm512_mullo_epi32, _mm512_reduce_add_epi32, _mm512_set1_epi32,
            _mm512_set_epi32, _mm512_setzero_si512, _mm512_srli_epi32,
        };

        let row_start = row.saturating_mul(m_packed);
        let Some(packed_row) = packed.get(row_start..row_start.saturating_add(m_packed)) else {
            return 0;
        };

        let mask_vec = _mm512_set1_epi32(mask_u32 as i32);
        let stride_idx =
            _mm512_set_epi32(45, 42, 39, 36, 33, 30, 27, 24, 21, 18, 15, 12, 9, 6, 3, 0);

        let mut acc_vec = _mm512_setzero_si512();
        let mut j: usize = 0;
        while j + 16 <= m_packed
            && j.wrapping_add(16).saturating_mul(SQUISH_COMPRESSION) <= original_m
        {
            let base_q = j.saturating_mul(SQUISH_COMPRESSION);
            // SAFETY: j + 16 <= m_packed; 64-byte load fits packed_row[j..j+16].
            #[allow(clippy::cast_ptr_alignment)]
            let cells = _mm512_loadu_si512(packed_row.as_ptr().add(j).cast::<__m512i>());

            let vs_0 = _mm512_and_si512(cells, mask_vec);
            // SAFETY: base_q + 45 < original_m by loop cond.
            let q_0 =
                _mm512_i32gather_epi32::<4>(stride_idx, query.as_ptr().add(base_q).cast::<i32>());
            acc_vec = _mm512_add_epi32(acc_vec, _mm512_mullo_epi32(vs_0, q_0));

            let vs_1 = _mm512_and_si512(_mm512_srli_epi32::<10>(cells), mask_vec);
            // SAFETY: base_q + 46 < original_m.
            let q_1 = _mm512_i32gather_epi32::<4>(
                stride_idx,
                query.as_ptr().add(base_q.saturating_add(1)).cast::<i32>(),
            );
            acc_vec = _mm512_add_epi32(acc_vec, _mm512_mullo_epi32(vs_1, q_1));

            let vs_2 = _mm512_and_si512(_mm512_srli_epi32::<20>(cells), mask_vec);
            // SAFETY: base_q + 47 < original_m.
            let q_2 = _mm512_i32gather_epi32::<4>(
                stride_idx,
                query.as_ptr().add(base_q.saturating_add(2)).cast::<i32>(),
            );
            acc_vec = _mm512_add_epi32(acc_vec, _mm512_mullo_epi32(vs_2, q_2));

            j += 16;
        }

        let mut acc: u32 = _mm512_reduce_add_epi32(acc_vec) as u32;

        while j < m_packed {
            let Some(&cell) = packed_row.get(j) else {
                break;
            };
            for k in 0..SQUISH_COMPRESSION {
                let q_idx = j.saturating_mul(SQUISH_COMPRESSION).saturating_add(k);
                let q_val = query.get(q_idx).copied().unwrap_or(0);
                if q_val == 0 {
                    continue;
                }
                let shift = (k as u32).saturating_mul(SQUISH_BASIS);
                let v = cell.wrapping_shr(shift) & mask_u32;
                acc = acc.wrapping_add(v.wrapping_mul(q_val));
            }
            j += 1;
        }
        acc
    }
}

use serde::{Deserialize, Serialize};

use crate::error::{IsimplePirError, Result};
use crate::params::LweParams;
use crate::respond::ServerResponse;

pub const SQUISH_BASIS: u32 = 10;
pub const SQUISH_COMPRESSION: usize = 3;

/// `data[i * m_packed + j]` holds three plaintexts at bit offsets
/// `0, BASIS, 2*BASIS`. Trailing cell zero-padded when
/// `original_m % SQUISH_COMPRESSION != 0`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SquishedDatabase {
    pub data: Vec<u32>,
    pub l: usize,
    /// `ceil(original_m / SQUISH_COMPRESSION)`.
    pub m_packed: usize,
    pub original_m: usize,
}

/// Pack `l x m` (values in `[0, p)`, `p <= 2^SQUISH_BASIS`).
pub fn squish_db(database: &[u32], params: &LweParams) -> Result<SquishedDatabase> {
    let max_p = 1u32 << SQUISH_BASIS;
    if params.p > max_p {
        return Err(IsimplePirError::InvalidParams {
            reason: format!(
                "squish requires p <= 2^{SQUISH_BASIS} = {max_p}, got p = {}",
                params.p,
            ),
        });
    }

    let expected = params.l.saturating_mul(params.m);
    if database.len() != expected {
        return Err(IsimplePirError::DatabaseShape {
            reason: format!(
                "database length {} does not match L * M = {} * {} = {}",
                database.len(),
                params.l,
                params.m,
                expected,
            ),
        });
    }

    for (i, &v) in database.iter().enumerate() {
        if v >= params.p {
            return Err(IsimplePirError::DatabaseShape {
                reason: format!(
                    "element {i} = {v} exceeds plaintext modulus p = {}",
                    params.p,
                ),
            });
        }
    }

    let m_packed = params
        .m
        .saturating_add(SQUISH_COMPRESSION)
        .saturating_sub(1)
        / SQUISH_COMPRESSION;
    let mut packed = vec![0u32; params.l.saturating_mul(m_packed)];

    for i in 0..params.l {
        let row_start = i.saturating_mul(params.m);
        let packed_row_start = i.saturating_mul(m_packed);
        for j in 0..m_packed {
            let mut cell: u32 = 0;
            for k in 0..SQUISH_COMPRESSION {
                let col = j.saturating_mul(SQUISH_COMPRESSION).saturating_add(k);
                if col >= params.m {
                    break;
                }
                let Some(&v) = database.get(row_start.saturating_add(col)) else {
                    continue;
                };
                let shift = (k as u32).saturating_mul(SQUISH_BASIS);
                cell |= v.wrapping_shl(shift);
            }
            let Some(slot) = packed.get_mut(packed_row_start.saturating_add(j)) else {
                continue;
            };
            *slot = cell;
        }
    }

    Ok(SquishedDatabase {
        data: packed,
        l: params.l,
        m_packed,
        original_m: params.m,
    })
}

/// Inverse of `squish_db`. Test-only; production `respond_packed`
/// consumes `SquishedDatabase` directly.
pub fn unsquish_db(packed: &SquishedDatabase) -> Vec<u32> {
    let mask = (1u32 << SQUISH_BASIS).saturating_sub(1);
    let mut unpacked = vec![0u32; packed.l.saturating_mul(packed.original_m)];

    for i in 0..packed.l {
        let packed_row_start = i.saturating_mul(packed.m_packed);
        let unpacked_row_start = i.saturating_mul(packed.original_m);
        for j in 0..packed.m_packed {
            let Some(&cell) = packed.data.get(packed_row_start.saturating_add(j)) else {
                continue;
            };
            for k in 0..SQUISH_COMPRESSION {
                let col = j.saturating_mul(SQUISH_COMPRESSION).saturating_add(k);
                if col >= packed.original_m {
                    break;
                }
                let shift = (k as u32).saturating_mul(SQUISH_BASIS);
                let v = cell.wrapping_shr(shift) & mask;
                let Some(slot) = unpacked.get_mut(unpacked_row_start.saturating_add(col)) else {
                    continue;
                };
                *slot = v;
            }
        }
    }

    unpacked
}

#[cfg(feature = "server")]
#[derive(Clone, Copy)]
enum PackedKernel {
    Scalar,
    #[cfg(target_arch = "x86_64")]
    Avx2,
    #[cfg(target_arch = "x86_64")]
    Avx512,
}

/// Below this width (packed cells) scalar beats SIMD dispatch.
#[cfg(feature = "server")]
const MIN_PACKED_SIMD_CELLS: usize = 1365;

/// Byte-identical to [`crate::respond::respond`] on the same input.
pub fn respond_packed(packed: &SquishedDatabase, query: &[u32]) -> Result<ServerResponse> {
    if query.len() != packed.original_m {
        return Err(IsimplePirError::QueryShape {
            reason: format!(
                "query length {} does not match original M = {}",
                query.len(),
                packed.original_m,
            ),
        });
    }

    let mask = (1u32 << SQUISH_BASIS).saturating_sub(1);
    let padded_m = packed.m_packed.saturating_mul(SQUISH_COMPRESSION);

    #[cfg(feature = "server")]
    let answer = {
        use rayon::prelude::*;

        #[cfg(target_arch = "x86_64")]
        let (has_avx512, has_avx2) = (
            std::is_x86_feature_detected!("avx512f"),
            std::is_x86_feature_detected!("avx2"),
        );

        let kernel: PackedKernel = {
            if packed.m_packed < MIN_PACKED_SIMD_CELLS {
                PackedKernel::Scalar
            } else {
                #[cfg(target_arch = "x86_64")]
                {
                    if has_avx512 {
                        PackedKernel::Avx512
                    } else if has_avx2 {
                        PackedKernel::Avx2
                    } else {
                        PackedKernel::Scalar
                    }
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    PackedKernel::Scalar
                }
            }
        };

        (0..packed.l)
            .into_par_iter()
            .map(|i| match kernel {
                PackedKernel::Scalar => {
                    packed_row_dot_scalar(&packed.data, packed.m_packed, i, query, padded_m, mask)
                }
                #[cfg(target_arch = "x86_64")]
                PackedKernel::Avx2 => {
                    // SAFETY: AVX2 detected when kernel was resolved.
                    #[allow(unsafe_code)]
                    unsafe {
                        simd::packed_row_dot_avx2(
                            &packed.data,
                            packed.m_packed,
                            i,
                            query,
                            packed.original_m,
                            mask,
                        )
                    }
                }
                #[cfg(target_arch = "x86_64")]
                PackedKernel::Avx512 => {
                    // SAFETY: AVX-512F detected when kernel was resolved.
                    #[allow(unsafe_code)]
                    unsafe {
                        simd::packed_row_dot_avx512(
                            &packed.data,
                            packed.m_packed,
                            i,
                            query,
                            packed.original_m,
                            mask,
                        )
                    }
                }
            })
            .collect()
    };

    #[cfg(not(feature = "server"))]
    let answer = {
        let mut out = vec![0u32; packed.l];
        for i in 0..packed.l {
            if let Some(slot) = out.get_mut(i) {
                *slot =
                    packed_row_dot_scalar(&packed.data, packed.m_packed, i, query, padded_m, mask);
            }
        }
        out
    };

    Ok(ServerResponse { answer })
}

/// Scalar row reference; SIMD kernels match byte-for-byte.
#[inline]
pub(crate) fn packed_row_dot_scalar(
    packed: &[u32],
    m_packed: usize,
    row: usize,
    query: &[u32],
    padded_m: usize,
    mask: u32,
) -> u32 {
    let row_start = row.saturating_mul(m_packed);
    let mut acc: u32 = 0;
    for j in 0..m_packed {
        let Some(&cell) = packed.get(row_start.saturating_add(j)) else {
            continue;
        };
        for k in 0..SQUISH_COMPRESSION {
            let q_idx = j.saturating_mul(SQUISH_COMPRESSION).saturating_add(k);
            if q_idx >= padded_m {
                break;
            }
            let q_val = query.get(q_idx).copied().unwrap_or(0);
            if q_val == 0 {
                continue;
            }
            let shift = (k as u32).saturating_mul(SQUISH_BASIS);
            let v = cell.wrapping_shr(shift) & mask;
            acc = acc.wrapping_add(v.wrapping_mul(q_val));
        }
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::LweParams;

    fn toy_params(l: usize, m: usize, p: u32) -> LweParams {
        LweParams {
            n: 128,
            log2_q: 32,
            p,
            l,
            m,
            bits_per_element: 9,
        }
    }

    #[test]
    fn squish_unsquish_roundtrip_aligned_m() {
        let params = toy_params(2, 6, 991);
        let db: Vec<u32> = (0..(params.l * params.m) as u32)
            .map(|i| i * 7 % params.p)
            .collect();
        let packed = squish_db(&db, &params).expect("squish");
        assert_eq!(packed.m_packed, 2);
        let back = unsquish_db(&packed);
        assert_eq!(back, db);
    }

    #[test]
    fn squish_unsquish_roundtrip_unaligned_m() {
        let params = toy_params(3, 5, 701);
        let db: Vec<u32> = (0..(params.l * params.m) as u32)
            .map(|i| (i * 13 + 2) % params.p)
            .collect();
        let packed = squish_db(&db, &params).expect("squish");
        assert_eq!(packed.m_packed, 2);
        let back = unsquish_db(&packed);
        assert_eq!(back, db);
    }

    #[test]
    fn squish_rejects_p_too_large_for_basis() {
        let params = toy_params(2, 3, 2048);
        let db = vec![0u32; 6];
        match squish_db(&db, &params) {
            Err(IsimplePirError::InvalidParams { .. }) => {}
            other => panic!("expected InvalidParams, got {other:?}"),
        }
    }

    #[test]
    fn squish_rejects_out_of_bound_value() {
        let params = toy_params(2, 3, 991);
        let mut db = vec![0u32; 6];
        db[4] = params.p;
        match squish_db(&db, &params) {
            Err(IsimplePirError::DatabaseShape { .. }) => {}
            other => panic!("expected DatabaseShape, got {other:?}"),
        }
    }

    #[test]
    fn respond_packed_rejects_wrong_query_length() {
        let params = toy_params(2, 3, 991);
        let db: Vec<u32> = vec![0u32; 6];
        let packed = squish_db(&db, &params).expect("squish");
        let short_q = vec![1u32, 2u32];
        match respond_packed(&packed, &short_q) {
            Err(IsimplePirError::QueryShape { .. }) => {}
            other => panic!("expected QueryShape, got {other:?}"),
        }
    }

    #[cfg(feature = "server")]
    fn build_packed_row_and_query(
        m_packed: usize,
        pad: usize,
        seed: u64,
    ) -> (Vec<u32>, Vec<u32>, usize, u32) {
        use rand_core::RngCore;
        let mut seed_bytes = [0u8; 32];
        seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
        let mut rng = ChaCha20Rng::from_seed(seed_bytes);
        let mask: u32 = (1u32 << SQUISH_BASIS).saturating_sub(1);
        let original_m = m_packed
            .saturating_mul(SQUISH_COMPRESSION)
            .saturating_sub(pad);
        let mut packed_row = Vec::with_capacity(m_packed);
        for _ in 0..m_packed {
            let s0 = rng.next_u32() & mask;
            let s1 = rng.next_u32() & mask;
            let s2 = rng.next_u32() & mask;
            packed_row.push(s0 | (s1 << SQUISH_BASIS) | (s2 << (2 * SQUISH_BASIS)));
        }
        let mut query = vec![0u32; original_m];
        for q in query.iter_mut() {
            *q = rng.next_u32();
        }
        (packed_row, query, original_m, mask)
    }

    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    /// 8-lane / 16-lane boundaries + realistic widths.
    const PACKED_TEST_M_PACKED: &[usize] = &[
        0, 1, 2, 5, 7, 8, 9, 15, 16, 17, 24, 25, 64, 1000, 1365, 1366, 7282, 15448,
    ];
    const PACKED_TEST_PADS: &[usize] = &[0, 1, 2];

    #[cfg(all(feature = "server", target_arch = "x86_64"))]
    #[test]
    fn avx2_matches_scalar_packed_byte_identity() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }
        for &seed in &[0u64, 1, 2] {
            for &m_packed in PACKED_TEST_M_PACKED {
                if m_packed == 0 {
                    continue;
                }
                for &pad in PACKED_TEST_PADS {
                    if pad > m_packed.saturating_mul(SQUISH_COMPRESSION) {
                        continue;
                    }
                    let (row, q, original_m, mask) =
                        build_packed_row_and_query(m_packed, pad, seed);
                    let padded_m = m_packed.saturating_mul(SQUISH_COMPRESSION);
                    let scalar = packed_row_dot_scalar(&row, m_packed, 0, &q, padded_m, mask);
                    // SAFETY: AVX2 detected above.
                    #[allow(unsafe_code)]
                    let avx2 = unsafe {
                        simd::packed_row_dot_avx2(&row, m_packed, 0, &q, original_m, mask)
                    };
                    assert_eq!(
                        scalar, avx2,
                        "packed scalar vs avx2 diverge at m_packed={m_packed}, pad={pad}, seed={seed}"
                    );
                }
            }
        }
        // u32-wraparound edge.
        let m_packed = 17usize;
        let mut row = vec![0u32; m_packed];
        let mask: u32 = (1u32 << SQUISH_BASIS).saturating_sub(1);
        for cell in row.iter_mut() {
            *cell = mask | (mask << SQUISH_BASIS) | (mask << (2 * SQUISH_BASIS));
        }
        let q = vec![u32::MAX; m_packed * SQUISH_COMPRESSION];
        let padded_m = m_packed.saturating_mul(SQUISH_COMPRESSION);
        let original_m = padded_m;
        let scalar = packed_row_dot_scalar(&row, m_packed, 0, &q, padded_m, mask);
        #[allow(unsafe_code)]
        let avx2 = unsafe { simd::packed_row_dot_avx2(&row, m_packed, 0, &q, original_m, mask) };
        assert_eq!(scalar, avx2, "wraparound edge: scalar vs avx2");
    }

    #[cfg(all(feature = "server", target_arch = "x86_64"))]
    #[test]
    fn avx512_matches_scalar_packed_byte_identity() {
        if !std::is_x86_feature_detected!("avx512f") {
            return;
        }
        for &seed in &[0u64, 1, 2] {
            for &m_packed in PACKED_TEST_M_PACKED {
                if m_packed == 0 {
                    continue;
                }
                for &pad in PACKED_TEST_PADS {
                    if pad > m_packed.saturating_mul(SQUISH_COMPRESSION) {
                        continue;
                    }
                    let (row, q, original_m, mask) =
                        build_packed_row_and_query(m_packed, pad, seed);
                    let padded_m = m_packed.saturating_mul(SQUISH_COMPRESSION);
                    let scalar = packed_row_dot_scalar(&row, m_packed, 0, &q, padded_m, mask);
                    // SAFETY: AVX-512F detected above.
                    #[allow(unsafe_code)]
                    let avx512 = unsafe {
                        simd::packed_row_dot_avx512(&row, m_packed, 0, &q, original_m, mask)
                    };
                    assert_eq!(
                        scalar, avx512,
                        "packed scalar vs avx512 diverge at m_packed={m_packed}, pad={pad}, seed={seed}"
                    );
                }
            }
        }
        // u32-wraparound edge at 16-lane boundary + scalar tail.
        let m_packed = 33usize;
        let mut row = vec![0u32; m_packed];
        let mask: u32 = (1u32 << SQUISH_BASIS).saturating_sub(1);
        for cell in row.iter_mut() {
            *cell = mask | (mask << SQUISH_BASIS) | (mask << (2 * SQUISH_BASIS));
        }
        let q = vec![u32::MAX; m_packed * SQUISH_COMPRESSION];
        let padded_m = m_packed.saturating_mul(SQUISH_COMPRESSION);
        let original_m = padded_m;
        let scalar = packed_row_dot_scalar(&row, m_packed, 0, &q, padded_m, mask);
        #[allow(unsafe_code)]
        let avx512 =
            unsafe { simd::packed_row_dot_avx512(&row, m_packed, 0, &q, original_m, mask) };
        assert_eq!(scalar, avx512, "wraparound edge: scalar vs avx512");
    }
}
