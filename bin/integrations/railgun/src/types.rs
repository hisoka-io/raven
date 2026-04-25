use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommitmentKind {
    Shield,
    Transact,
    LegacyGenerated,
    LegacyEncrypted,
}

impl CommitmentKind {
    pub(crate) fn from_subgraph_str(s: &str) -> Option<Self> {
        match s {
            "ShieldCommitment" => Some(Self::Shield),
            "TransactCommitment" => Some(Self::Transact),
            "LegacyGeneratedCommitment" => Some(Self::LegacyGenerated),
            "LegacyEncryptedCommitment" => Some(Self::LegacyEncrypted),
            _ => None,
        }
    }
}

impl fmt::Display for CommitmentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Shield => "Shield",
            Self::Transact => "Transact",
            Self::LegacyGenerated => "LegacyGenerated",
            Self::LegacyEncrypted => "LegacyEncrypted",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommitmentRecord {
    pub(crate) leaf_index: u32,
    pub(crate) kind: CommitmentKind,
    pub(crate) hash: [u8; 32],
    pub(crate) block_number: u64,
    pub(crate) tx_hash: [u8; 32],
}

impl CommitmentRecord {
    /// PIR / `StorageBackend` key. Tree is implicit (single active tree),
    /// so the leaf index alone uniquely identifies a commitment.
    #[allow(dead_code)]
    pub(crate) fn pir_key(&self) -> u64 {
        u64::from(self.leaf_index)
    }
}

impl fmt::Display for CommitmentRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{kind} leaf={leaf} hash=0x{hash} block={block} tx=0x{tx}",
            kind = self.kind,
            leaf = self.leaf_index,
            hash = hex_lower(&self.hash),
            block = self.block_number,
            tx = hex_lower(&self.tx_hash),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScanCursor {
    /// Highest leaf index already printed; `None` before any leaves processed.
    pub(crate) last_processed_leaf: Option<u32>,
}

impl ScanCursor {
    pub(crate) fn empty() -> Self {
        Self { last_processed_leaf: None }
    }

    pub(crate) fn next_leaf(self) -> u32 {
        self.last_processed_leaf.map_or(0, |n| n.saturating_add(1))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TreeStatus {
    pub(crate) tree_number: u32,
    pub(crate) size: u32,
    pub(crate) last_block: u64,
}

impl TreeStatus {
    pub(crate) const TREE_CAPACITY: u32 = 1 << 16;
}

fn hex_lower(bytes: &[u8]) -> String {
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
