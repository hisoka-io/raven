//! Closed forms for the byte counts this bench publishes.
//!
//! The bench gate pins these numbers, and a pin nobody can re-derive is a copy. Each form
//! below predicts a serialized length from the shape alone, so a run whose measurement
//! disagrees with its own shape is refused at the producer instead of quietly shrinking the
//! baseline. The response form is carried independently at
//! `adapters/railgun/cli/tests/production_cell.rs` and the query form at
//! `crates/client/tests/query_generation_budget.rs`; all three agree at `d = 2048`.

/// Bit width the tight coefficient packer uses for `modulus`.
#[must_use]
pub const fn coefficient_bits(modulus: u64) -> usize {
    (u64::BITS - modulus.saturating_sub(1).leading_zeros()) as usize
}

/// Bincode bytes around a packed `ServerResponse`'s two coefficient payloads: the variant
/// tag; `a`'s coefficient length, one-modulus vector, q, dim, CRT inverse and NTT flag; the
/// `b` prefix length; the retained count; the empty column vector; and `Some(packing_mode)`.
pub const RESPONSE_ENVELOPE_BYTES: usize = 4 + (8 + 16 + 8 + 8 + 8 + 1) + 8 + 4 + 8 + 5;

/// The 32-byte PRG seed a seeded query ships in place of its `a` polynomial.
pub const QUERY_SEED_BYTES: usize = 32;

/// Everything a seeded query carries besides its coefficients, its seed and its per-limb
/// moduli: the `b` polynomial's own header (41), the row length prefix and tail (8 + 24),
/// the shard id (4), the vector length prefix (4), the packing mode (1) and the session
/// handle (9).
pub const QUERY_ENVELOPE_BYTES: usize = 41 + 8 + 24 + 4 + 4 + 1 + 9;

/// `p = 65_537` carries two record bytes per retained coefficient.
#[must_use]
pub const fn retained_coefficients(record_bytes: usize) -> usize {
    record_bytes.div_ceil(2)
}

/// Serialized length of a two-packing response: full `a`, then `b`'s retained prefix, both
/// packed at the ciphertext modulus's width.
#[must_use]
pub const fn response_bytes(modulus: u64, ring_dim: usize, record_bytes: usize) -> usize {
    let coefficients = ring_dim + retained_coefficients(record_bytes);
    RESPONSE_ENVELOPE_BYTES + (coefficients * coefficient_bits(modulus)).div_ceil(8)
}

/// Serialized length of one seeded, session-handled query. Independent of the entry count
/// and the record width: it is one `b` polynomial at `ring_dim` per CRT limb.
#[must_use]
pub const fn query_bytes(modulus: u64, ring_dim: usize, crt_limbs: usize) -> usize {
    (coefficient_bits(modulus) * ring_dim * crt_limbs).div_ceil(8)
        + 8 * crt_limbs
        + QUERY_SEED_BYTES
        + QUERY_ENVELOPE_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `q = 2^60 - 2^14 + 1`, the modulus every shipped preset uses.
    const DEFAULT_Q: u64 = 1_152_921_504_606_830_593;

    /// The served rung, `2^36 - 2^20 + 1`.
    const SERVED_Q: u64 = 68_718_428_161;

    #[test]
    fn coefficient_bits_reads_the_two_shipped_moduli() {
        assert_eq!(coefficient_bits(DEFAULT_Q), 60);
        assert_eq!(coefficient_bits(SERVED_Q), 36);
    }

    /// Measured through this producer at 2^10 and 2^16, all three record widths.
    #[test]
    fn the_response_form_reproduces_every_unswitched_size_on_disk() {
        assert_eq!(response_bytes(DEFAULT_Q, 2048, 32), 15_558);
        assert_eq!(response_bytes(DEFAULT_Q, 2048, 256), 16_398);
        assert_eq!(response_bytes(DEFAULT_Q, 2048, 512), 17_358);
    }

    /// The same three widths at the served rung, pinned independently by
    /// `adapters/railgun/engine/tests/wire_response_is_mod_switched.rs`.
    #[test]
    fn the_response_form_reproduces_every_served_size_the_adapter_pins() {
        assert_eq!(response_bytes(SERVED_Q, 2048, 32), 9_366);
        assert_eq!(response_bytes(SERVED_Q, 2048, 256), 9_870);
        assert_eq!(response_bytes(SERVED_Q, 2048, 512), 10_446);
    }

    /// The same number decomposed the way the card states it: ring term, seed, envelope.
    #[test]
    fn the_query_form_reproduces_the_production_upload() {
        assert_eq!(query_bytes(DEFAULT_Q, 2048, 1), 15_491);
        assert_eq!(query_bytes(DEFAULT_Q, 2048, 1), 2048 * 60 / 8 + 32 + 99);
    }

    /// A record width that moves the retained prefix must move the response by exactly the
    /// modelled amount, or the form is fitted to one point rather than derived.
    #[test]
    fn widening_the_record_moves_the_response_by_the_retained_prefix_alone() {
        let narrow = response_bytes(SERVED_Q, 2048, 32);
        let wide = response_bytes(SERVED_Q, 2048, 512);
        assert_eq!(wide - narrow, (256 - 16) * 36 / 8);
    }

    /// And the ring term is the only free coefficient in the query.
    #[test]
    fn doubling_the_ring_moves_the_query_by_the_ring_term_alone() {
        let narrow = query_bytes(DEFAULT_Q, 1024, 1);
        let wide = query_bytes(DEFAULT_Q, 2048, 1);
        assert_eq!(wide - narrow, 1024 * 60 / 8);
    }
}
