//! The Howl node's wire.
//!
//! Every answer starts with the same [`Header`]: the wire version, the parameter set the
//! private reads run under, the route, and the tree state the answer was read from - the leaf
//! count, the chain block it reflects and the pool's root at that count. Everything in one
//! answer is read from that one state, so the rows of a feed segment, a block's leaves and
//! the upper nodes in it agree with each other and with the root.
//!
//! A request body starts with a [`RequestPrefix`]: the wire version and the parameter set the
//! caller built its keys and queries under. A node refuses a body made for another one.
//!
//! All integers are big-endian. Variable runs carry their length or are fixed by a count
//! given before them, so every body decodes without a schema.

#![deny(missing_docs)]

pub mod tree;

/// Version of this wire. Any change to a layout below is a new version.
pub const WIRE_VERSION: u16 = 1;

/// Parameter set of the private reads: ring dimension 2,048, one 60-bit modulus, plaintext
/// modulus 65,537, 256-byte cells, responses switched to the 36-bit modulus.
pub const PARAM_SET_D2048_CELL256: u16 = 1;

/// Bytes of one discovery cell.
pub const CELL_BYTES: usize = 256;

/// Rows of the discovery table one private query selects among.
pub const ROWS_PER_SHARD: u64 = 2_048;

/// Bytes per row of the public tag-prefix feed.
pub const PREFIX_BYTES: usize = 6;

/// Bytes of a tree leaf or node.
pub const NODE_BYTES: usize = 32;

/// Bytes of [`Header`] on the wire.
pub const HEADER_BYTES: usize = 56;

/// Bytes of [`RequestPrefix`] on the wire.
pub const REQUEST_PREFIX_BYTES: usize = 4;

/// Batch sizes a private read accepts. A wallet pads its positions up to the next one.
pub const LADDER: [usize; 5] = [1, 2, 4, 8, 16];

/// The largest batch: more positions are split over several batches.
pub const LADDER_CAP: usize = 16;

/// Upper nodes one answer carries at most.
pub const MAX_UPPER_NODES: u64 = 65_536;

/// The ladder step a batch of `real` positions is padded to, `None` above [`LADDER_CAP`] or
/// for an empty batch.
///
/// # Examples
/// ```
/// assert_eq!(howl_wire::padded_len(3), Some(4));
/// assert_eq!(howl_wire::padded_len(17), None);
/// ```
#[must_use]
pub fn padded_len(real: usize) -> Option<usize> {
    LADDER
        .iter()
        .copied()
        .find(|step| *step >= real && real > 0)
}

/// Why bytes did not decode.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum WireError {
    /// Fewer bytes than the layout needs.
    #[error("{what}: {got} bytes, {need} needed")]
    Short {
        /// What was being read.
        what: &'static str,
        /// Bytes available.
        got: usize,
        /// Bytes needed.
        need: usize,
    },
    /// Bytes after the end of the layout.
    #[error("{what}: {extra} bytes past the end")]
    Trailing {
        /// What was being read.
        what: &'static str,
        /// Surplus bytes.
        extra: usize,
    },
    /// Another wire version.
    #[error("wire version {got}, this build speaks {WIRE_VERSION}")]
    Version {
        /// Version found.
        got: u16,
    },
    /// A route id this build does not know.
    #[error("unknown route {0}")]
    Kind(u8),
    /// A field whose value the layout forbids.
    #[error("{0}")]
    Invalid(&'static str),
}

/// Which route an answer comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// The node's parameters and public key material.
    Params = 1,
    /// A segment of the tag-prefix feed.
    Prefixes = 2,
    /// One block of tree leaves.
    Block = 3,
    /// Level-10 nodes of full blocks.
    Upper = 4,
    /// Feed delta, upper delta and the newest block, together.
    Sync = 5,
    /// A registered session.
    Session = 6,
    /// Private reads of discovery cells.
    Notes = 7,
    /// A refusal that names the state it was refused against.
    Stale = 8,
}

impl TryFrom<u8> for Kind {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, WireError> {
        Ok(match value {
            1 => Self::Params,
            2 => Self::Prefixes,
            3 => Self::Block,
            4 => Self::Upper,
            5 => Self::Sync,
            6 => Self::Session,
            7 => Self::Notes,
            8 => Self::Stale,
            other => return Err(WireError::Kind(other)),
        })
    }
}

/// The first [`HEADER_BYTES`] of every answer.
///
/// Layout: `version u16 | param_set u16 | kind u8 | 3 zero bytes | leaf_count u64 |
/// block u64 | root [32]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Parameter set of the node's private reads.
    pub param_set: u16,
    /// The route.
    pub kind: Kind,
    /// Leaves in the tree every read of this answer reflects.
    pub leaf_count: u64,
    /// The chain block that tree is the state after. Zero before any block is read.
    pub block: u64,
    /// The pool's root at `leaf_count`, zero for an empty tree.
    pub root: [u8; 32],
}

impl Header {
    /// The header's bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_BYTES] {
        let mut out = [0u8; HEADER_BYTES];
        let mut w = Writer(Vec::with_capacity(HEADER_BYTES));
        w.u16(WIRE_VERSION);
        w.u16(self.param_set);
        w.bytes(&[self.kind as u8, 0, 0, 0]);
        w.u64(self.leaf_count);
        w.u64(self.block);
        w.bytes(&self.root);
        out.copy_from_slice(&w.0);
        out
    }

    /// Read a header and return it with the bytes after it.
    ///
    /// # Errors
    /// [`WireError`] for a short buffer, another version, an unknown route or non-zero
    /// reserved bytes.
    pub fn decode(bytes: &[u8]) -> Result<(Self, &[u8]), WireError> {
        let mut r = Reader::new("header", bytes);
        let version = r.u16()?;
        if version != WIRE_VERSION {
            return Err(WireError::Version { got: version });
        }
        let param_set = r.u16()?;
        let kind = Kind::try_from(r.u8()?)?;
        if r.take(3)? != [0, 0, 0] {
            return Err(WireError::Invalid("reserved header bytes are not zero"));
        }
        let header = Self {
            param_set,
            kind,
            leaf_count: r.u64()?,
            block: r.u64()?,
            root: r.array()?,
        };
        Ok((header, r.rest()))
    }
}

/// The first [`REQUEST_PREFIX_BYTES`] of every request body: `version u16 | param_set u16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestPrefix {
    /// Parameter set the request was built under.
    pub param_set: u16,
}

impl RequestPrefix {
    /// The prefix's bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; REQUEST_PREFIX_BYTES] {
        let v = WIRE_VERSION.to_be_bytes();
        let p = self.param_set.to_be_bytes();
        [v[0], v[1], p[0], p[1]]
    }

    /// Read a prefix and return it with the payload after it.
    ///
    /// # Errors
    /// [`WireError::Short`] or [`WireError::Version`].
    pub fn decode(bytes: &[u8]) -> Result<(Self, &[u8]), WireError> {
        let mut r = Reader::new("request prefix", bytes);
        let version = r.u16()?;
        if version != WIRE_VERSION {
            return Err(WireError::Version { got: version });
        }
        let param_set = r.u16()?;
        Ok((Self { param_set }, r.rest()))
    }
}

/// Rows `[base, next)` of the tag-prefix feed: `base u64 | next u64 | rows`.
///
/// The feed holds [`Header::leaf_count`] rows; `next == leaf_count` marks the newest segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixSegment {
    /// Position of the first row.
    pub base: u64,
    /// Position after the last row: the next read's `since`.
    pub next: u64,
    /// `(next - base) * 6` bytes.
    pub rows: Vec<u8>,
}

impl PrefixSegment {
    fn write(&self, w: &mut Writer) {
        w.u64(self.base);
        w.u64(self.next);
        w.bytes(&self.rows);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let base = r.u64()?;
        let next = r.u64()?;
        let count = next
            .checked_sub(base)
            .ok_or(WireError::Invalid("segment ends before it starts"))?;
        let rows = r.take(width(count, PREFIX_BYTES)?)?.to_vec();
        Ok(Self { base, next, rows })
    }
}

/// Leaves of one block: `block_index u32 | count u32 | leaves`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafBlock {
    /// Index of the block; it starts at leaf `block_index * 1024`.
    pub block_index: u32,
    /// `count * 32` bytes: the leaves present at the answer's leaf count.
    pub leaves: Vec<u8>,
}

impl LeafBlock {
    fn write(&self, w: &mut Writer) {
        w.u32(self.block_index);
        w.u32(u32::try_from(self.leaves.len() / NODE_BYTES).unwrap_or(u32::MAX));
        w.bytes(&self.leaves);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let block_index = r.u32()?;
        let count = r.u32()?;
        if u64::from(count) > tree::BLOCK_LEAVES {
            return Err(WireError::Invalid("a block holds at most 1,024 leaves"));
        }
        let leaves = r.take(width(u64::from(count), NODE_BYTES)?)?.to_vec();
        Ok(Self {
            block_index,
            leaves,
        })
    }

    /// The leaves as nodes.
    #[must_use]
    pub fn nodes(&self) -> Vec<tree::Node> {
        nodes(&self.leaves)
    }
}

/// Level-10 nodes of full blocks `[base, next)`: `base u64 | next u64 | nodes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpperNodes {
    /// First block.
    pub base: u64,
    /// Block after the last one carried.
    pub next: u64,
    /// `(next - base) * 32` bytes.
    pub nodes: Vec<u8>,
}

impl UpperNodes {
    fn write(&self, w: &mut Writer) {
        w.u64(self.base);
        w.u64(self.next);
        w.bytes(&self.nodes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let base = r.u64()?;
        let next = r.u64()?;
        let count = next
            .checked_sub(base)
            .ok_or(WireError::Invalid("upper run ends before it starts"))?;
        let nodes = r.take(width(count, NODE_BYTES)?)?.to_vec();
        Ok(Self { base, next, nodes })
    }

    /// The nodes.
    #[must_use]
    pub fn list(&self) -> Vec<tree::Node> {
        nodes(&self.nodes)
    }
}

/// What the node serves with: `entry_bytes u32 | rows_per_shard u32 | ladder_cap u16 |
/// session_ttl_secs u32 | crs_len u32 | crs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Params {
    /// Bytes per discovery cell.
    pub entry_bytes: u32,
    /// Rows per shard of the discovery table.
    pub rows_per_shard: u32,
    /// The largest batch a private read takes.
    pub ladder_cap: u16,
    /// Seconds a session stays registered after its last use.
    pub session_ttl_secs: u32,
    /// The public key material clients build keys and queries under, in its versioned form.
    pub crs: Vec<u8>,
}

/// A registered session: `handle u64 | ttl_secs u32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    /// Handle to send with each batch.
    pub handle: u64,
    /// Seconds the handle stays valid after its last use.
    pub ttl_secs: u32,
}

/// One answer per query of a batch, in request order: `count u16 | (len u32 | bytes)*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notes {
    /// Encoded responses.
    pub responses: Vec<Vec<u8>>,
}

/// The body of an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// [`Kind::Params`].
    Params(Params),
    /// [`Kind::Prefixes`].
    Prefixes(PrefixSegment),
    /// [`Kind::Block`].
    Block(LeafBlock),
    /// [`Kind::Upper`].
    Upper(UpperNodes),
    /// [`Kind::Sync`]: the feed from a cursor, the upper nodes from a cursor and the block
    /// holding the newest leaf, all at the header's leaf count.
    Sync {
        /// Feed rows from the wallet's cursor.
        prefixes: PrefixSegment,
        /// Upper nodes from the wallet's cursor.
        upper: UpperNodes,
        /// The block holding leaf `leaf_count - 1`, empty for an empty tree. Its leaves start
        /// at the request's `held` when that falls inside the block, else at its first leaf.
        newest: LeafBlock,
    },
    /// [`Kind::Session`].
    Session(Session),
    /// [`Kind::Notes`].
    Notes(Notes),
    /// [`Kind::Stale`]: the request named something past the node's state, which the
    /// header states.
    Stale,
}

impl Body {
    /// The route this body answers.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        match self {
            Self::Params(_) => Kind::Params,
            Self::Prefixes(_) => Kind::Prefixes,
            Self::Block(_) => Kind::Block,
            Self::Upper(_) => Kind::Upper,
            Self::Sync { .. } => Kind::Sync,
            Self::Session(_) => Kind::Session,
            Self::Notes(_) => Kind::Notes,
            Self::Stale => Kind::Stale,
        }
    }
}

/// A full answer: header and body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// Parameter set of the node.
    pub param_set: u16,
    /// Leaf count of the state read.
    pub leaf_count: u64,
    /// Block of the state read.
    pub block: u64,
    /// Root of the state read.
    pub root: [u8; 32],
    /// The body.
    pub body: Body,
}

impl Answer {
    /// The answer's header.
    #[must_use]
    pub const fn header(&self) -> Header {
        Header {
            param_set: self.param_set,
            kind: self.body.kind(),
            leaf_count: self.leaf_count,
            block: self.block,
            root: self.root,
        }
    }

    /// The answer's bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer(self.header().encode().to_vec());
        match &self.body {
            Body::Params(p) => {
                w.u32(p.entry_bytes);
                w.u32(p.rows_per_shard);
                w.u16(p.ladder_cap);
                w.u32(p.session_ttl_secs);
                w.u32(u32::try_from(p.crs.len()).unwrap_or(u32::MAX));
                w.bytes(&p.crs);
            }
            Body::Prefixes(s) => s.write(&mut w),
            Body::Block(b) => b.write(&mut w),
            Body::Upper(u) => u.write(&mut w),
            Body::Sync {
                prefixes,
                upper,
                newest,
            } => {
                prefixes.write(&mut w);
                upper.write(&mut w);
                newest.write(&mut w);
            }
            Body::Session(s) => {
                w.u64(s.handle);
                w.u32(s.ttl_secs);
            }
            Body::Notes(n) => {
                w.u16(u16::try_from(n.responses.len()).unwrap_or(u16::MAX));
                for response in &n.responses {
                    w.u32(u32::try_from(response.len()).unwrap_or(u32::MAX));
                    w.bytes(response);
                }
            }
            Body::Stale => {}
        }
        w.0
    }

    /// Read an answer.
    ///
    /// # Errors
    /// [`WireError`] for any malformed or surplus byte.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let (header, rest) = Header::decode(bytes)?;
        let mut r = Reader::new("answer body", rest);
        let body = match header.kind {
            Kind::Params => {
                let entry_bytes = r.u32()?;
                let rows_per_shard = r.u32()?;
                let ladder_cap = r.u16()?;
                let session_ttl_secs = r.u32()?;
                let len = r.u32()?;
                let crs = r.take(usize::try_from(len).unwrap_or(usize::MAX))?.to_vec();
                Body::Params(Params {
                    entry_bytes,
                    rows_per_shard,
                    ladder_cap,
                    session_ttl_secs,
                    crs,
                })
            }
            Kind::Prefixes => Body::Prefixes(PrefixSegment::read(&mut r)?),
            Kind::Block => Body::Block(LeafBlock::read(&mut r)?),
            Kind::Upper => Body::Upper(UpperNodes::read(&mut r)?),
            Kind::Sync => Body::Sync {
                prefixes: PrefixSegment::read(&mut r)?,
                upper: UpperNodes::read(&mut r)?,
                newest: LeafBlock::read(&mut r)?,
            },
            Kind::Session => Body::Session(Session {
                handle: r.u64()?,
                ttl_secs: r.u32()?,
            }),
            Kind::Notes => {
                let count = r.u16()?;
                let mut responses = Vec::with_capacity(usize::from(count).min(LADDER_CAP));
                for _ in 0..count {
                    let len = r.u32()?;
                    responses.push(r.take(usize::try_from(len).unwrap_or(usize::MAX))?.to_vec());
                }
                Body::Notes(Notes { responses })
            }
            Kind::Stale => Body::Stale,
        };
        r.end()?;
        Ok(Self {
            param_set: header.param_set,
            leaf_count: header.leaf_count,
            block: header.block,
            root: header.root,
            body,
        })
    }
}

fn width(count: u64, each: usize) -> Result<usize, WireError> {
    usize::try_from(count)
        .ok()
        .and_then(|count| count.checked_mul(each))
        .ok_or(WireError::Invalid(
            "a run longer than this platform addresses",
        ))
}

fn nodes(bytes: &[u8]) -> Vec<tree::Node> {
    bytes.as_chunks::<NODE_BYTES>().0.to_vec()
}

struct Writer(Vec<u8>);

impl Writer {
    fn bytes(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
    fn u16(&mut self, v: u16) {
        self.bytes(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.bytes(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.bytes(&v.to_be_bytes());
    }
}

struct Reader<'a> {
    what: &'static str,
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(what: &'static str, bytes: &'a [u8]) -> Self {
        Self { what, bytes }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.bytes.len() < n {
            return Err(WireError::Short {
                what: self.what,
                got: self.bytes.len(),
                need: n,
            });
        }
        let (head, tail) = self.bytes.split_at(n);
        self.bytes = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(u8::from_be_bytes(self.array()?))
    }
    fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    const fn rest(self) -> &'a [u8] {
        self.bytes
    }

    fn end(self) -> Result<(), WireError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(WireError::Trailing {
                what: self.what,
                extra: self.bytes.len(),
            })
        }
    }
}
