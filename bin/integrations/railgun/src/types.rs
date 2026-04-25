use std::fmt;

use bytes::Bytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommitmentRecord {
    pub(crate) leaf_index: u32,
    pub(crate) hash: [u8; 32],
}

impl CommitmentRecord {
    pub(crate) fn key(&self) -> u64 {
        u64::from(self.leaf_index)
    }

    pub(crate) fn to_bytes(&self) -> Bytes {
        Bytes::copy_from_slice(&self.hash)
    }

    #[allow(dead_code)]
    pub(crate) fn try_hash_from_bytes(buf: &[u8]) -> Option<[u8; 32]> {
        <[u8; 32]>::try_from(buf).ok()
    }
}

impl fmt::Display for CommitmentRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "leaf={} hash=0x{}",
            self.leaf_index,
            hex_lower(&self.hash)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScanCursor {
    /// Highest leaf index already processed; `None` before any leaves processed.
    pub(crate) last_processed_leaf: Option<u32>,
}

impl ScanCursor {
    pub(crate) fn empty() -> Self {
        Self {
            last_processed_leaf: None,
        }
    }

    pub(crate) fn next_leaf(self) -> u32 {
        self.last_processed_leaf.map_or(0, |n| n.saturating_add(1))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TreeStatus {
    pub(crate) tree_number: u32,
    pub(crate) size: u32,
}

impl TreeStatus {
    pub(crate) const TREE_CAPACITY: u32 = 1 << 16;
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(nib(b >> 4));
        s.push(nib(b & 0x0f));
    }
    s
}

fn nib(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + (n - 10)) as char,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_roundtrips_through_bytes() {
        let rec = CommitmentRecord {
            leaf_index: 42,
            hash: [7u8; 32],
        };
        let buf = rec.to_bytes();
        assert_eq!(buf.len(), 32);
        let back = CommitmentRecord::try_hash_from_bytes(&buf).expect("decode");
        assert_eq!(back, rec.hash);
    }

    #[test]
    fn key_is_leaf_index() {
        let rec = CommitmentRecord {
            leaf_index: 12345,
            hash: [0u8; 32],
        };
        assert_eq!(rec.key(), 12345u64);
    }

    #[test]
    fn try_hash_from_bytes_rejects_wrong_length() {
        assert!(CommitmentRecord::try_hash_from_bytes(&[0u8; 31]).is_none());
        assert!(CommitmentRecord::try_hash_from_bytes(&[0u8; 33]).is_none());
    }
}
