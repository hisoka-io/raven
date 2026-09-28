//! Hex text of fixed-width byte strings: list keys, commitments, roots and signatures.

/// The `N` bytes `text` spells: exactly `2 * N` hex digits of either case, optionally after `0x`.
/// `None` for any other length or any other character.
///
/// ```
/// use raven_railgun_core::hex::decode_hex;
/// assert_eq!(decode_hex::<2>("0xA0ff"), Some([0xa0, 0xff]));
/// assert_eq!(decode_hex::<2>("+a0f"), None);
/// ```
#[must_use]
pub fn decode_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let digits = text.strip_prefix("0x").unwrap_or(text).as_bytes();
    if digits.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (byte, &[hi, lo]) in out.iter_mut().zip(digits.as_chunks::<2>().0) {
        *byte = (nibble(hi)? << 4) | nibble(lo)?;
    }
    Some(out)
}

const fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::decode_hex;
    use std::fmt::Write as _;

    #[test]
    fn every_byte_value_decodes_in_place_from_either_case_with_or_without_the_prefix() {
        let bytes: [u8; 32] = std::array::from_fn(|at| u8::try_from(at * 8 + 3).unwrap_or(0));
        let lower = bytes.iter().fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        });
        for text in [
            lower.clone(),
            lower.to_uppercase(),
            format!("0x{lower}"),
            format!("0x{}", lower.to_uppercase()),
        ] {
            assert_eq!(decode_hex::<32>(&text), Some(bytes), "{text}");
        }
        for value in 0..=255u8 {
            assert_eq!(decode_hex::<1>(&format!("{value:02x}")), Some([value]));
        }
    }

    #[test]
    fn a_wrong_length_or_a_non_hex_character_is_refused() {
        let short = "ab".repeat(31);
        for text in [
            String::new(),
            "0x".to_owned(),
            short.clone(),
            format!("{short}abab"),
            format!("0X{short}ab"),
            format!("0x0x{short}"),
            format!("+a{short}"),
            format!("ag{short}"),
            format!(" a{short}"),
            format!("\u{e9}{short}"),
        ] {
            assert_eq!(decode_hex::<32>(&text), None, "{text:?}");
        }
    }
}
