//! Flat complete-binary-tree row arithmetic shared by clients and encoders.

/// Map a node at `level` and its level-local `offset` into level-major flat storage.
pub fn flat_index(depth: u32, level: u32, offset: u32) -> u32 {
    let total = 1u32 << (depth + 1);
    let level_offset = total - (1u32 << (depth + 1 - level));
    level_offset + offset
}

/// Recover `(level, offset)` from a level-major flat node index.
pub fn level_and_offset(depth: u32, flat: u32) -> (u32, u32) {
    let total = 1u32 << (depth + 1);
    let mut cursor = 0u32;
    for level in 0..=depth {
        let span = total >> (level + 1);
        if flat < cursor.saturating_add(span.max(1)) {
            return (level, flat - cursor);
        }
        cursor = cursor.saturating_add(span.max(1));
    }
    (depth, 0)
}

#[cfg(test)]
mod tests {
    use super::{flat_index, level_and_offset};

    const DEPTH: u32 = 16;

    #[test]
    fn flat_index_and_inverse_agree_over_the_full_node_domain() {
        for level in 0..=DEPTH {
            let offsets_at_level = 1 << (DEPTH - level);
            for offset in 0..offsets_at_level {
                let flat = flat_index(DEPTH, level, offset);
                assert_eq!(level_and_offset(DEPTH, flat), (level, offset));
            }
        }
    }
}
