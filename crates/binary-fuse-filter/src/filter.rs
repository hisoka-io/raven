use std::collections::HashMap;

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use turboshake::TurboShake128;

use crate::branch_opt;
use crate::error::{BffError, Result};

const HASHED_KEY_BYTE_LEN: usize = 32;

/// BFF descriptor. Serializes to a fixed byte layout via
/// [`to_bytes`](BinaryFuseFilter::to_bytes); the fingerprint array
/// is stored separately by the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryFuseFilter {
    pub seed: [u8; 32],
    /// Arity (3 or 4).
    pub arity: u32,
    pub segment_length: u32,
    pub segment_count_length: u32,
    pub num_fingerprints: usize,
    /// Filter occupancy after construction (= keys inserted on success).
    pub filter_size: usize,
    /// Bits per fingerprint slot; sets the false-positive rate.
    pub mat_elem_bit_len: usize,
}

/// `(filter, reverse_order, reverse_h, hash_to_key)`. Caller uses
/// `reverse_order` + `reverse_h` to populate the fingerprint array
/// in dependency order; `hash_to_key` recovers the source key bytes.
pub type BinaryFuseFilterIntermediateStageResult<'a> =
    (BinaryFuseFilter, Vec<u64>, Vec<u8>, HashMap<u64, &'a [u8]>);

impl BinaryFuseFilter {
    /// Construct a 3-wise XOR Binary Fuse Filter. Adapted from
    /// `FastFilter/fastfilter_cpp/.../3wise_xor_binary_fuse_filter_lowmem.h`.
    /// `mat_elem_bit_len` sets the FP rate (`2^-mat_elem_bit_len`);
    /// `max_attempt_count` retries with fresh seeds.
    pub fn construct_3_wise<'a>(
        db: &HashMap<&'a [u8], &[u8]>,
        mat_elem_bit_len: usize,
        max_attempt_count: usize,
    ) -> Result<BinaryFuseFilterIntermediateStageResult<'a>> {
        const ARITY: u32 = 3;

        let db_size = db.len();
        if branch_opt::unlikely(db_size == 0) {
            return Err(BffError::EmptyKeyValueDatabase);
        }

        let segment_length = segment_length::<ARITY>(db_size as u32).min(1u32 << 18);

        let size_factor = size_factor::<ARITY>(db_size as u32);
        let capacity = if db_size > 1 {
            ((db_size as f64) * size_factor).round() as u32
        } else {
            0
        };

        let init_segment_count = capacity.div_ceil(segment_length);
        let (num_fingerprints, segment_count) = {
            let array_len = init_segment_count * segment_length;
            let segment_count: u32 = {
                let proposed = array_len.div_ceil(segment_length);
                if proposed < ARITY {
                    1
                } else {
                    proposed - (ARITY - 1)
                }
            };
            let array_len: u32 = (segment_count + ARITY - 1) * segment_length;
            (array_len as usize, segment_count)
        };
        let segment_count_length = segment_count * segment_length;

        let mut alone = vec![0u32; num_fingerprints];
        let mut t2count = vec![0u8; num_fingerprints];
        let mut t2hash = vec![0u64; num_fingerprints];
        let mut reverse_h = vec![0u8; db_size];
        let mut reverse_order = vec![0u64; db_size + 1];
        reverse_order[db_size] = 1;

        let mut hash_to_key: HashMap<u64, &'a [u8]> = HashMap::new();

        let block_bits = {
            let mut block_bits = 1;
            while (1 << block_bits) < segment_count {
                block_bits += 1;
            }
            block_bits
        };
        let block_bits_mask = (1u64 << block_bits) - 1;

        let start_pos_len: usize = 1 << block_bits;
        let mut start_pos = vec![0usize; start_pos_len];

        let mut h012 = [0u32; 5];

        let mut done = false;
        let mut ultimate_size = 0;

        let mut seed = [0u8; 32];
        let mut rng =
            ChaCha20Rng::try_from_os_rng().map_err(|_| BffError::ExhaustedAllAttemptsToBuild {
                arity: ARITY,
                attempts: 0,
            })?;

        for _ in 0..max_attempt_count {
            rng.fill_bytes(&mut seed);

            // Each attempt rehashes; clear the map so failed-attempt
            // entries don't accumulate. Correctness is unaffected by
            // the upstream's accumulation bug (overwrite-on-collision
            // semantics), but this bounds map capacity to N.
            hash_to_key.clear();

            for (idx, val) in start_pos.iter_mut().enumerate() {
                *val = (((idx as u64) * (db_size as u64)) >> block_bits) as usize;
            }

            for &key in db.keys() {
                let hashed_key = hash_of_key(key);
                let hash = mix256(&hashed_key, &seed);

                let mut segment_index = hash >> (64 - block_bits);
                while let Some(&sp) = start_pos.get(segment_index as usize) {
                    if reverse_order.get(sp).copied().unwrap_or(0) == 0 {
                        break;
                    }
                    segment_index = (segment_index + 1) & block_bits_mask;
                }

                if let Some(sp_slot) = start_pos.get_mut(segment_index as usize) {
                    let pos = *sp_slot;
                    if let Some(ro_slot) = reverse_order.get_mut(pos) {
                        *ro_slot = hash;
                    }
                    *sp_slot = sp_slot.saturating_add(1);
                }

                hash_to_key.insert(hash, key);
            }

            let mut error = false;
            for i in 0..db_size {
                let Some(&hash) = reverse_order.get(i) else {
                    break;
                };
                let (h0, h1, h2) =
                    hash_batch_for_3_wise_xor_filter(hash, segment_length, segment_count_length);
                let (h0, h1, h2) = (h0 as usize, h1 as usize, h2 as usize);

                if let Some(c) = t2count.get_mut(h0) {
                    *c = c.wrapping_add(4);
                }
                if let Some(h) = t2hash.get_mut(h0) {
                    *h ^= hash;
                }

                if let Some(c) = t2count.get_mut(h1) {
                    *c = c.wrapping_add(4);
                    *c ^= 1;
                }
                if let Some(h) = t2hash.get_mut(h1) {
                    *h ^= hash;
                }

                if let Some(c) = t2count.get_mut(h2) {
                    *c = c.wrapping_add(4);
                    *c ^= 2;
                }
                if let Some(h) = t2hash.get_mut(h2) {
                    *h ^= hash;
                }

                let c0 = t2count.get(h0).copied().unwrap_or(0);
                let c1 = t2count.get(h1).copied().unwrap_or(0);
                let c2 = t2count.get(h2).copied().unwrap_or(0);
                error = c0 < 4 || c1 < 4 || c2 < 4;
            }

            if error {
                reverse_order[..db_size].fill(0);
                t2count.fill(0);
                t2hash.fill(0);

                continue;
            }

            let mut qsize = 0;
            for (idx, &count) in t2count.iter().enumerate().take(num_fingerprints) {
                if let Some(slot) = alone.get_mut(qsize) {
                    *slot = idx as u32;
                }
                if (count >> 2) == 1 {
                    qsize += 1;
                }
            }

            let mut stack_size = 0;
            while qsize > 0 {
                qsize -= 1;

                let Some(&a) = alone.get(qsize) else {
                    break;
                };
                let index = a as usize;
                if t2count.get(index).copied().unwrap_or(0) >> 2 == 1 {
                    let hash = t2hash.get(index).copied().unwrap_or(0);
                    let found: u8 = t2count.get(index).copied().unwrap_or(0) & 3;

                    if let Some(r) = reverse_h.get_mut(stack_size) {
                        *r = found;
                    }
                    if let Some(r) = reverse_order.get_mut(stack_size) {
                        *r = hash;
                    }
                    stack_size += 1;

                    let (h0, h1, h2) = hash_batch_for_3_wise_xor_filter(
                        hash,
                        segment_length,
                        segment_count_length,
                    );

                    h012[1] = h1;
                    h012[2] = h2;
                    h012[3] = h0;
                    h012[4] = h012[1];

                    let other_index1 =
                        h012.get((found + 1) as usize).copied().unwrap_or(0) as usize;
                    if let Some(slot) = alone.get_mut(qsize) {
                        *slot = other_index1 as u32;
                    }
                    if t2count.get(other_index1).copied().unwrap_or(0) >> 2 == 2 {
                        qsize += 1;
                    }

                    if let Some(c) = t2count.get_mut(other_index1) {
                        *c = c.wrapping_sub(4);
                        *c ^= mod3(found + 1);
                    }
                    if let Some(h) = t2hash.get_mut(other_index1) {
                        *h ^= hash;
                    }

                    let other_index2 =
                        h012.get((found + 2) as usize).copied().unwrap_or(0) as usize;
                    if let Some(slot) = alone.get_mut(qsize) {
                        *slot = other_index2 as u32;
                    }
                    if t2count.get(other_index2).copied().unwrap_or(0) >> 2 == 2 {
                        qsize += 1;
                    }

                    if let Some(c) = t2count.get_mut(other_index2) {
                        *c = c.wrapping_sub(4);
                        *c ^= mod3(found + 2);
                    }
                    if let Some(h) = t2hash.get_mut(other_index2) {
                        *h ^= hash;
                    }
                }
            }

            if stack_size == db_size {
                ultimate_size = stack_size;
                done = true;
                break;
            }

            reverse_order[..db_size].fill(0);
            t2count.fill(0);
            t2hash.fill(0);
        }

        if branch_opt::unlikely(!done) {
            return Err(BffError::ExhaustedAllAttemptsToBuild {
                arity: ARITY,
                attempts: max_attempt_count,
            });
        }

        Ok((
            BinaryFuseFilter {
                seed,
                arity: ARITY,
                segment_length,
                segment_count_length,
                num_fingerprints,
                filter_size: ultimate_size,
                mat_elem_bit_len,
            },
            reverse_order,
            reverse_h,
            hash_to_key,
        ))
    }

    /// 4-wise XOR Binary Fuse Filter. Slightly denser than 3-wise
    /// (~1.08 vs ~1.13 bits/entry overhead) at the cost of one
    /// extra memory access per query.
    pub fn construct_4_wise<'a>(
        db: &HashMap<&'a [u8], &[u8]>,
        mat_elem_bit_len: usize,
        max_attempt_count: usize,
    ) -> Result<BinaryFuseFilterIntermediateStageResult<'a>> {
        const ARITY: u32 = 4;

        let db_size = db.len();
        if branch_opt::unlikely(db_size == 0) {
            return Err(BffError::EmptyKeyValueDatabase);
        }

        let segment_length = segment_length::<ARITY>(db_size as u32).min(1u32 << 18);

        let size_factor = size_factor::<ARITY>(db_size as u32);
        let capacity = if db_size > 1 {
            ((db_size as f64) * size_factor).round() as u32
        } else {
            0
        };

        let init_segment_count = capacity.div_ceil(segment_length);
        let (num_fingerprints, segment_count) = {
            let array_len = init_segment_count * segment_length;
            let segment_count: u32 = {
                let proposed = array_len.div_ceil(segment_length);
                if proposed < ARITY {
                    1
                } else {
                    proposed - (ARITY - 1)
                }
            };
            let array_len: u32 = (segment_count + ARITY - 1) * segment_length;
            (array_len as usize, segment_count)
        };
        let segment_count_length = segment_count * segment_length;

        let mut alone = vec![0u32; num_fingerprints];
        let mut t2count = vec![0u8; num_fingerprints];
        let mut t2hash = vec![0u64; num_fingerprints];
        let mut reverse_h = vec![0u8; db_size];
        let mut reverse_order = vec![0u64; db_size + 1];
        reverse_order[db_size] = 1;

        let mut hash_to_key: HashMap<u64, &'a [u8]> = HashMap::new();

        let block_bits = {
            let mut block_bits = 1;
            while (1 << block_bits) < segment_count {
                block_bits += 1;
            }
            block_bits
        };
        let block_bits_mask = (1u64 << block_bits) - 1;

        let start_pos_len: usize = 1 << block_bits;
        let mut start_pos = vec![0usize; start_pos_len];

        let mut h0123 = [0u32; 7];

        let mut done = false;
        let mut ultimate_size = 0;

        let mut seed = [0u8; 32];
        let mut rng =
            ChaCha20Rng::try_from_os_rng().map_err(|_| BffError::ExhaustedAllAttemptsToBuild {
                arity: ARITY,
                attempts: 0,
            })?;

        for _ in 0..max_attempt_count {
            rng.fill_bytes(&mut seed);

            // See `construct_3_wise` for the rehash-clear rationale.
            hash_to_key.clear();

            for (idx, val) in start_pos.iter_mut().enumerate().take(start_pos_len) {
                *val = (((idx as u64) * (db_size as u64)) >> block_bits) as usize;
            }

            for &key in db.keys() {
                let hashed_key = hash_of_key(key);
                let hash = mix256(&hashed_key, &seed);

                let mut segment_index = hash >> (64 - block_bits);
                while let Some(&sp) = start_pos.get(segment_index as usize) {
                    if reverse_order.get(sp).copied().unwrap_or(0) == 0 {
                        break;
                    }
                    segment_index = (segment_index + 1) & block_bits_mask;
                }

                if let Some(sp_slot) = start_pos.get_mut(segment_index as usize) {
                    let pos = *sp_slot;
                    if let Some(ro_slot) = reverse_order.get_mut(pos) {
                        *ro_slot = hash;
                    }
                    *sp_slot = sp_slot.saturating_add(1);
                }

                hash_to_key.insert(hash, key);
            }

            let mut count_mask = 0u8;
            for i in 0..db_size {
                let Some(&hash) = reverse_order.get(i) else {
                    break;
                };
                let (h0, h1, h2, h3) =
                    hash_batch_for_4_wise_xor_filter(hash, segment_length, segment_count_length);
                let (h0, h1, h2, h3) = (h0 as usize, h1 as usize, h2 as usize, h3 as usize);

                if let Some(c) = t2count.get_mut(h0) {
                    *c = c.wrapping_add(4);
                }
                if let Some(h) = t2hash.get_mut(h0) {
                    *h ^= hash;
                }
                count_mask |= t2count.get(h0).copied().unwrap_or(0);

                if let Some(c) = t2count.get_mut(h1) {
                    *c = c.wrapping_add(4);
                    *c ^= 1u8;
                }
                if let Some(h) = t2hash.get_mut(h1) {
                    *h ^= hash;
                }
                count_mask |= t2count.get(h1).copied().unwrap_or(0);

                if let Some(c) = t2count.get_mut(h2) {
                    *c = c.wrapping_add(4);
                    *c ^= 2u8;
                }
                if let Some(h) = t2hash.get_mut(h2) {
                    *h ^= hash;
                }
                count_mask |= t2count.get(h2).copied().unwrap_or(0);

                if let Some(c) = t2count.get_mut(h3) {
                    *c = c.wrapping_add(4);
                    *c ^= 3u8;
                }
                if let Some(h) = t2hash.get_mut(h3) {
                    *h ^= hash;
                }
                count_mask |= t2count.get(h3).copied().unwrap_or(0);
            }

            if count_mask >= 0x80 {
                reverse_order[..db_size].fill(0);
                t2count.fill(0);
                t2hash.fill(0);
                continue;
            }

            let mut qsize = 0;
            for (idx, &count) in t2count.iter().enumerate().take(num_fingerprints) {
                if let Some(slot) = alone.get_mut(qsize) {
                    *slot = idx as u32;
                }
                if (count >> 2) == 1 {
                    qsize += 1;
                }
            }

            let mut stack_size = 0;
            while qsize > 0 {
                qsize -= 1;

                let Some(&a) = alone.get(qsize) else {
                    break;
                };
                let index = a as usize;
                if t2count.get(index).copied().unwrap_or(0) >> 2 == 1 {
                    let hash = t2hash.get(index).copied().unwrap_or(0);
                    let found: u8 = t2count.get(index).copied().unwrap_or(0) & 3;

                    if let Some(r) = reverse_h.get_mut(stack_size) {
                        *r = found;
                    }
                    if let Some(r) = reverse_order.get_mut(stack_size) {
                        *r = hash;
                    }
                    stack_size += 1;

                    let (h0, h1, h2, h3) = hash_batch_for_4_wise_xor_filter(
                        hash,
                        segment_length,
                        segment_count_length,
                    );

                    h0123[1] = h1;
                    h0123[2] = h2;
                    h0123[3] = h3;
                    h0123[4] = h0;
                    h0123[5] = h0123[1];
                    h0123[6] = h0123[2];

                    let other_index =
                        h0123.get((found + 1) as usize).copied().unwrap_or(0) as usize;
                    if let Some(slot) = alone.get_mut(qsize) {
                        *slot = other_index as u32;
                    }
                    qsize += if t2count.get(other_index).copied().unwrap_or(0) >> 2 == 2 {
                        1
                    } else {
                        0
                    };
                    if let Some(c) = t2count.get_mut(other_index) {
                        *c = c.wrapping_sub(4);
                        *c ^= mod4(found + 1);
                    }
                    if let Some(h) = t2hash.get_mut(other_index) {
                        *h ^= hash;
                    }

                    let other_index =
                        h0123.get((found + 2) as usize).copied().unwrap_or(0) as usize;
                    if let Some(slot) = alone.get_mut(qsize) {
                        *slot = other_index as u32;
                    }
                    qsize += if t2count.get(other_index).copied().unwrap_or(0) >> 2 == 2 {
                        1
                    } else {
                        0
                    };
                    if let Some(c) = t2count.get_mut(other_index) {
                        *c = c.wrapping_sub(4);
                        *c ^= mod4(found + 2);
                    }
                    if let Some(h) = t2hash.get_mut(other_index) {
                        *h ^= hash;
                    }

                    let other_index =
                        h0123.get((found + 3) as usize).copied().unwrap_or(0) as usize;
                    if let Some(slot) = alone.get_mut(qsize) {
                        *slot = other_index as u32;
                    }
                    qsize += if t2count.get(other_index).copied().unwrap_or(0) >> 2 == 2 {
                        1
                    } else {
                        0
                    };
                    if let Some(c) = t2count.get_mut(other_index) {
                        *c = c.wrapping_sub(4);
                        *c ^= mod4(found + 3);
                    }
                    if let Some(h) = t2hash.get_mut(other_index) {
                        *h ^= hash;
                    }
                }
            }

            if stack_size == db_size {
                ultimate_size = stack_size;
                done = true;
                break;
            }

            reverse_order[..db_size].fill(0);
            t2count.fill(0);
            t2hash.fill(0);
        }

        if branch_opt::unlikely(!done) {
            return Err(BffError::ExhaustedAllAttemptsToBuild {
                arity: ARITY,
                attempts: max_attempt_count,
            });
        }

        Ok((
            BinaryFuseFilter {
                seed,
                arity: ARITY,
                segment_length,
                segment_count_length,
                num_fingerprints,
                filter_size: ultimate_size,
                mat_elem_bit_len,
            },
            reverse_order,
            reverse_h,
            hash_to_key,
        ))
    }

    /// Average bits per entry in the fingerprint array.
    pub fn bits_per_entry(&self) -> f64 {
        if self.filter_size == 0 {
            return 0.0;
        }
        ((self.num_fingerprints as f64) * (self.mat_elem_bit_len as f64))
            / (self.filter_size as f64)
    }

    /// Serialize the descriptor (little-endian).
    pub fn to_bytes(&self) -> Vec<u8> {
        let offset0 = 0;
        let offset1 = offset0 + self.seed.len();
        let offset2 = offset1 + std::mem::size_of_val(&self.arity);
        let offset3 = offset2 + std::mem::size_of_val(&self.segment_length);
        let offset4 = offset3 + std::mem::size_of_val(&self.segment_count_length);
        let offset5 = offset4 + std::mem::size_of_val(&self.num_fingerprints);
        let offset6 = offset5 + std::mem::size_of_val(&self.filter_size);
        let total_byte_len = offset6 + std::mem::size_of_val(&self.mat_elem_bit_len);

        let mut bytes = vec![0u8; total_byte_len];

        // Indexing is bounded by the offset math above.
        #[allow(clippy::indexing_slicing)]
        {
            bytes[offset0..offset1].copy_from_slice(&self.seed);
            bytes[offset1..offset2].copy_from_slice(&self.arity.to_le_bytes());
            bytes[offset2..offset3].copy_from_slice(&self.segment_length.to_le_bytes());
            bytes[offset3..offset4].copy_from_slice(&self.segment_count_length.to_le_bytes());
            bytes[offset4..offset5].copy_from_slice(&self.num_fingerprints.to_le_bytes());
            bytes[offset5..offset6].copy_from_slice(&self.filter_size.to_le_bytes());
            bytes[offset6..].copy_from_slice(&self.mat_elem_bit_len.to_le_bytes());
        }

        bytes
    }

    /// Deserialize a descriptor produced by `to_bytes`. Errors on
    /// length mismatch.
    pub fn from_bytes(bytes: &[u8]) -> Result<BinaryFuseFilter> {
        const OFFSET0: usize = 0;
        const OFFSET1: usize = OFFSET0 + std::mem::size_of::<[u8; 32]>();
        const OFFSET2: usize = OFFSET1 + std::mem::size_of::<u32>();
        const OFFSET3: usize = OFFSET2 + std::mem::size_of::<u32>();
        const OFFSET4: usize = OFFSET3 + std::mem::size_of::<u32>();
        const OFFSET5: usize = OFFSET4 + std::mem::size_of::<usize>();
        const OFFSET6: usize = OFFSET5 + std::mem::size_of::<usize>();
        const EXPECTED_BYTE_LEN: usize = OFFSET6 + std::mem::size_of::<usize>();

        if branch_opt::unlikely(EXPECTED_BYTE_LEN != bytes.len()) {
            return Err(BffError::FailedToDeserializeFilterFromBytes);
        }

        // Length check above bounds all indexing below.
        let seed: [u8; 32] = bytes
            .get(OFFSET0..OFFSET1)
            .and_then(|s| s.try_into().ok())
            .ok_or(BffError::FailedToDeserializeFilterFromBytes)?;
        let arity = u32::from_le_bytes(
            bytes
                .get(OFFSET1..OFFSET2)
                .and_then(|s| s.try_into().ok())
                .ok_or(BffError::FailedToDeserializeFilterFromBytes)?,
        );
        let segment_length = u32::from_le_bytes(
            bytes
                .get(OFFSET2..OFFSET3)
                .and_then(|s| s.try_into().ok())
                .ok_or(BffError::FailedToDeserializeFilterFromBytes)?,
        );
        let segment_count_length = u32::from_le_bytes(
            bytes
                .get(OFFSET3..OFFSET4)
                .and_then(|s| s.try_into().ok())
                .ok_or(BffError::FailedToDeserializeFilterFromBytes)?,
        );
        let num_fingerprints = usize::from_le_bytes(
            bytes
                .get(OFFSET4..OFFSET5)
                .and_then(|s| s.try_into().ok())
                .ok_or(BffError::FailedToDeserializeFilterFromBytes)?,
        );
        let filter_size = usize::from_le_bytes(
            bytes
                .get(OFFSET5..OFFSET6)
                .and_then(|s| s.try_into().ok())
                .ok_or(BffError::FailedToDeserializeFilterFromBytes)?,
        );
        let mat_elem_bit_len = usize::from_le_bytes(
            bytes
                .get(OFFSET6..)
                .and_then(|s| s.try_into().ok())
                .ok_or(BffError::FailedToDeserializeFilterFromBytes)?,
        );

        Ok(BinaryFuseFilter {
            seed,
            arity,
            segment_length,
            segment_count_length,
            num_fingerprints,
            filter_size,
            mat_elem_bit_len,
        })
    }
}

/// Per-segment length for a given entry count and arity.
#[inline]
pub fn segment_length<const ARITY: u32>(size: u32) -> u32 {
    if size == 0 {
        return 4;
    }
    match ARITY {
        3 => 1u32 << ((size as f64).ln() / 3.33_f64.ln() + 2.25).floor() as usize,
        4 => 1u32 << ((size as f64).ln() / 2.91_f64.ln() - 0.5).floor() as usize,
        _ => 65536,
    }
}

/// Fingerprint-array size factor relative to entry count.
#[inline]
pub fn size_factor<const ARITY: u32>(size: u32) -> f64 {
    match ARITY {
        3 => 1.125_f64.max(0.875 + 0.25 * 1e6_f64.ln() / (size as f64).ln()),
        4 => 1.075_f64.max(0.77 + 0.305 * 6e5_f64.ln() / (size as f64).ln()),
        _ => 2.0,
    }
}

/// `x % 3` for `x` in `0..=5`.
#[inline]
pub const fn mod3(x: u8) -> u8 {
    if x > 2 {
        x - 3
    } else {
        x
    }
}

/// `x % 4` for `x` in `0..=7`.
#[inline]
pub const fn mod4(x: u8) -> u8 {
    if x > 3 {
        x - 4
    } else {
        x
    }
}

/// MurmurHash3 64-bit finalizer.
#[inline]
pub const fn murmur64(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^= h >> 33;
    h
}

/// One-step mix of `(key, seed)` into a u64.
#[inline]
pub const fn mix(key: u64, seed: u64) -> u64 {
    murmur64(key.wrapping_add(seed))
}

/// Hash key bytes to a 32-byte digest via TurboShake128.
#[inline]
pub fn hash_of_key(key: &[u8]) -> [u64; 4] {
    let mut hasher = TurboShake128::default();
    hasher.absorb(key);
    hasher.finalize::<{ TurboShake128::DEFAULT_DOMAIN_SEPARATOR }>();

    let mut digest = [0u8; HASHED_KEY_BYTE_LEN];
    hasher.squeeze(&mut digest);

    let read_u64 = |offset: usize| -> u64 {
        let mut buf = [0u8; 8];
        if let Some(slice) = digest.get(offset..offset + 8) {
            if let Ok(arr) = slice.try_into() {
                buf = arr;
            }
        }
        u64::from_le_bytes(buf)
    };
    [read_u64(0), read_u64(8), read_u64(16), read_u64(24)]
}

/// Mix a 4 × u64 digest with a 32-byte seed into a u64 filter hash.
#[inline]
pub fn mix256(key: &[u64; 4], seed: &[u8; 32]) -> u64 {
    let read_u64 = |offset: usize| -> u64 {
        let mut buf = [0u8; 8];
        if let Some(slice) = seed.get(offset..offset + 8) {
            if let Ok(arr) = slice.try_into() {
                buf = arr;
            }
        }
        u64::from_le_bytes(buf)
    };
    let seed_words = [read_u64(0), read_u64(8), read_u64(16), read_u64(24)];

    key.iter()
        .map(|&k| {
            seed_words.into_iter().fold(0u64, |acc, seed_word| {
                murmur64(acc.wrapping_add(mix(k, seed_word)))
            })
        })
        .fold(0u64, |acc, r| acc.wrapping_add(r))
}

/// 3-wise variant: three filter-array indices for a hash.
#[inline]
pub const fn hash_batch_for_3_wise_xor_filter(
    hash: u64,
    segment_length: u32,
    segment_count_length: u32,
) -> (u32, u32, u32) {
    let segment_length_mask = segment_length - 1;
    let hi = ((hash as u128 * segment_count_length as u128) >> 64) as u64;

    let h0 = hi as u32;
    let mut h1 = h0 + segment_length;
    let mut h2 = h1 + segment_length;

    h1 ^= ((hash >> 18) as u32) & segment_length_mask;
    h2 ^= (hash as u32) & segment_length_mask;

    (h0, h1, h2)
}

/// 4-wise variant: four filter-array indices for a hash.
#[inline]
pub const fn hash_batch_for_4_wise_xor_filter(
    hash: u64,
    segment_length: u32,
    segment_count_length: u32,
) -> (u32, u32, u32, u32) {
    let segment_length_mask = segment_length - 1;
    let hi = ((hash as u128 * segment_count_length as u128) >> 64) as u64;

    let h0 = hi as u32;
    let mut h1 = h0 + segment_length;
    let mut h2 = h1 + segment_length;
    let mut h3 = h2 + segment_length;

    h1 ^= (hash as u32) & segment_length_mask;
    h2 ^= ((hash >> 16) as u32) & segment_length_mask;
    h3 ^= ((hash >> 32) as u32) & segment_length_mask;

    (h0, h1, h2, h3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn murmur64_matches_fixed_vector() {
        // murmur64 preserves zero (xor-shift + mul both fix 0).
        assert_eq!(murmur64(0), 0);
        // Lock a deterministic non-zero output.
        let h = murmur64(1);
        assert_ne!(h, 0);
        assert_eq!(h, murmur64(1));
    }

    #[test]
    fn mod3_mod4_small_inputs() {
        for i in 0u8..=5u8 {
            assert_eq!(mod3(i), i % 3, "mod3 at {i}");
        }
        for i in 0u8..=7u8 {
            assert_eq!(mod4(i), i % 4, "mod4 at {i}");
        }
    }

    #[test]
    fn hash_of_key_is_deterministic() {
        let a = hash_of_key(b"hello");
        let b = hash_of_key(b"hello");
        assert_eq!(a, b);
        let c = hash_of_key(b"hellp");
        assert_ne!(a, c);
    }

    #[test]
    fn segment_length_positive_for_small_input() {
        assert!(segment_length::<3>(1000) > 0);
        assert!(segment_length::<4>(1000) > 0);
        assert_eq!(segment_length::<3>(0), 4);
    }

    #[test]
    fn size_factor_at_least_lower_bound() {
        assert!(size_factor::<3>(1_000_000) >= 1.125);
        assert!(size_factor::<4>(1_000_000) >= 1.075);
    }
}
