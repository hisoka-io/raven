//! Pack and unpack `u32` limbs at arbitrary widths ≤ 32 bits.
//!
//! PIR schemes emit vectors of `u32` limbs carrying only `bits_per_limb`
//! payload bits; shipping 32 bits per limb wastes bandwidth.
//!
//! Packed byte length is `ceil(xs.len() * width / 8)`; byte order is
//! host-independent.

use core::convert::TryFrom;

/// Maximum width (in bits) accepted by [`pack_u32s`] and [`unpack_u32s`].
pub const MAX_BITS_PER_LIMB: u8 = 32;

/// Pack a slice of `u32` values, each carrying `bits_per_limb` payload bits,
/// into a byte buffer.
///
/// Any bits above `bits_per_limb` in each input limb are ignored (masked).
/// The output length is exactly `ceil(values.len() * bits_per_limb / 8)`.
///
/// # Errors
///
/// Returns `Err(BitpackError::WidthOutOfRange)` if `bits_per_limb` is `0` or
/// greater than [`MAX_BITS_PER_LIMB`].
pub fn pack_u32s(values: &[u32], bits_per_limb: u8) -> Result<Vec<u8>, BitpackError> {
    if bits_per_limb == 0 || bits_per_limb > MAX_BITS_PER_LIMB {
        return Err(BitpackError::WidthOutOfRange { bits_per_limb });
    }
    let bits_per_limb_usize = usize::from(bits_per_limb);
    let total_bits = values.len().saturating_mul(bits_per_limb_usize);
    let total_bytes = total_bits.div_ceil(8);
    let mut out = vec![0u8; total_bytes];

    let mut bit_cursor: usize = 0;
    for &v in values {
        let masked = if bits_per_limb == MAX_BITS_PER_LIMB {
            v
        } else {
            v & ((1u32 << bits_per_limb) - 1)
        };
        for bit_idx in 0..bits_per_limb_usize {
            let bit = (masked >> bit_idx) & 1;
            if bit != 0 {
                let dst_bit = bit_cursor + bit_idx;
                let byte = dst_bit / 8;
                let offset = dst_bit % 8;
                // byte < out.len() by construction: out is sized to cover total_bits.
                #[allow(clippy::expect_used)]
                let slot = out.get_mut(byte).expect("cursor within bounds");
                *slot |= 1u8 << offset;
            }
        }
        bit_cursor += bits_per_limb_usize;
    }
    Ok(out)
}

/// Unpack a byte buffer produced by [`pack_u32s`] into a vector of `u32`s.
///
/// `count` is the number of limbs expected; the caller must have recorded
/// this out-of-band at pack time.
///
/// # Errors
///
/// - `BitpackError::WidthOutOfRange`. `bits_per_limb` is `0` or > 32.
/// - `BitpackError::TruncatedInput`. `bytes` is shorter than the packed
///   representation of `count` limbs at `bits_per_limb` bits each.
pub fn unpack_u32s(
    bytes: &[u8],
    count: usize,
    bits_per_limb: u8,
) -> Result<Vec<u32>, BitpackError> {
    if bits_per_limb == 0 || bits_per_limb > MAX_BITS_PER_LIMB {
        return Err(BitpackError::WidthOutOfRange { bits_per_limb });
    }
    let bits_per_limb_usize = usize::from(bits_per_limb);
    let total_bits = count.saturating_mul(bits_per_limb_usize);
    let required_bytes = total_bits.div_ceil(8);
    if bytes.len() < required_bytes {
        return Err(BitpackError::TruncatedInput {
            got: bytes.len(),
            needed: required_bytes,
        });
    }

    let mut out = Vec::with_capacity(count);
    let mut bit_cursor: usize = 0;
    for _ in 0..count {
        let mut v: u32 = 0;
        for bit_idx in 0..bits_per_limb_usize {
            let src_bit = bit_cursor + bit_idx;
            let byte = src_bit / 8;
            let offset = src_bit % 8;
            // byte < bytes.len(): we rejected shorter inputs above.
            #[allow(clippy::expect_used)]
            let src_byte = *bytes.get(byte).expect("cursor within bounds");
            let bit = u32::from((src_byte >> offset) & 1);
            v |= bit << bit_idx;
        }
        out.push(v);
        bit_cursor += bits_per_limb_usize;
    }
    Ok(out)
}

/// Errors surfaced by [`pack_u32s`] and [`unpack_u32s`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitpackError {
    /// `bits_per_limb` was `0` or greater than [`MAX_BITS_PER_LIMB`].
    WidthOutOfRange {
        /// The invalid width supplied.
        bits_per_limb: u8,
    },
    /// The input byte slice was shorter than the packed representation.
    TruncatedInput {
        /// Bytes supplied.
        got: usize,
        /// Bytes required for the stated `count` and `bits_per_limb`.
        needed: usize,
    },
}

impl core::fmt::Display for BitpackError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WidthOutOfRange { bits_per_limb } => write!(
                f,
                "bit width {bits_per_limb} out of range (must be 1..={MAX_BITS_PER_LIMB})"
            ),
            Self::TruncatedInput { got, needed } => write!(
                f,
                "bitpack input truncated: got {got} bytes, needed {needed}"
            ),
        }
    }
}

impl std::error::Error for BitpackError {}

impl TryFrom<BitpackError> for (usize, usize) {
    type Error = BitpackError;
    fn try_from(value: BitpackError) -> Result<Self, Self::Error> {
        if let BitpackError::TruncatedInput { got, needed } = value {
            Ok((got, needed))
        } else {
            Err(value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn roundtrip_width_14_small_vector() {
        let values: Vec<u32> = vec![0, 1, 2, 4, 8, 16, 31, 100, 255, 16383];
        let packed = pack_u32s(&values, 14).expect("pack");
        let unpacked = unpack_u32s(&packed, values.len(), 14).expect("unpack");
        assert_eq!(values, unpacked);
    }

    #[test]
    fn roundtrip_width_32_preserves_full_limb() {
        let values: Vec<u32> = vec![0, u32::MAX, 0x1234_5678, 0xDEAD_BEEF];
        let packed = pack_u32s(&values, 32).expect("pack");
        assert_eq!(packed.len(), values.len() * 4);
        let unpacked = unpack_u32s(&packed, values.len(), 32).expect("unpack");
        assert_eq!(values, unpacked);
    }

    #[test]
    fn high_bits_beyond_width_are_masked_on_pack() {
        // 3-bit packing: only low 3 bits survive.
        let packed = pack_u32s(&[0xFFFF_FFFFu32], 3).expect("pack");
        let unpacked = unpack_u32s(&packed, 1, 3).expect("unpack");
        assert_eq!(unpacked, vec![0b111]);
    }

    #[test]
    fn width_zero_is_rejected() {
        assert!(matches!(
            pack_u32s(&[0], 0),
            Err(BitpackError::WidthOutOfRange { bits_per_limb: 0 })
        ));
        assert!(matches!(
            unpack_u32s(&[0u8; 1], 1, 0),
            Err(BitpackError::WidthOutOfRange { bits_per_limb: 0 })
        ));
    }

    #[test]
    fn width_above_max_is_rejected() {
        assert!(matches!(
            pack_u32s(&[0], 33),
            Err(BitpackError::WidthOutOfRange { bits_per_limb: 33 })
        ));
    }

    #[test]
    fn truncated_input_is_rejected() {
        // Packing 10 limbs at 14 bits = 140 bits = 18 bytes.
        let values: Vec<u32> = vec![1; 10];
        let packed = pack_u32s(&values, 14).expect("pack");
        assert_eq!(packed.len(), 18);

        // Drop last byte, attempt to unpack.
        let truncated = &packed[..packed.len() - 1];
        let err = unpack_u32s(truncated, 10, 14).expect_err("should refuse short input");
        let (got, needed) = <(usize, usize)>::try_from(err).expect("truncation variant");
        assert_eq!(needed, 18);
        assert_eq!(got, 17);
    }

    #[test]
    fn packed_byte_length_matches_ceil_formula() {
        let cases: [(usize, usize); 4] = [(10, 14), (1000, 11), (1, 1), (64, 32)];
        for (count, width) in cases {
            let values: Vec<u32> = (0..count).map(|i| u32::try_from(i).unwrap()).collect();
            let width_u8 = u8::try_from(width).expect("width in u8 range");
            let packed = pack_u32s(&values, width_u8).expect("pack");
            let expected = count.saturating_mul(width).div_ceil(8);
            assert_eq!(packed.len(), expected, "count={count} width={width}");
        }
    }

    proptest! {
        #[test]
        fn prop_roundtrip(
            width in 1u8..=32u8,
            len in 0usize..128,
            base in any::<u32>(),
        ) {
            // Derive values from a base so proptest shrinking stays small.
            let values: Vec<u32> = (0..len).map(|i| base.wrapping_add(u32::try_from(i).unwrap())).collect();
            let packed = pack_u32s(&values, width).expect("pack");
            let unpacked = unpack_u32s(&packed, len, width).expect("unpack");
            // Masked comparison: pack drops bits above the width.
            let mask = if width == 32 { u32::MAX } else { (1u32 << width) - 1 };
            let masked: Vec<u32> = values.iter().map(|v| v & mask).collect();
            prop_assert_eq!(unpacked, masked);
        }
    }
}
