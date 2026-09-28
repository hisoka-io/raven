//! A capture folder: `events.bin` rows, the `noncanonical.jsonl` overrides, and the manifest's
//! chain block.

use std::collections::BTreeMap;
use std::path::Path;

use crate::{ReplayError, Result};
use raven_railgun_core::hex::decode_hex;

/// `events.bin` magic.
pub const EVENTS_BIN_MAGIC: [u8; 8] = *b"RVNPPOI1";
/// `events.bin` format version this crate reads and writes.
pub const EVENTS_BIN_VERSION: u32 = 1;
/// Header size in bytes.
pub const EVENTS_BIN_HEADER_BYTES: usize = 64;
/// Row size in bytes: index, type, commitment, root, signature.
pub const EVENTS_BIN_ROW_BYTES: usize = 133;
const ROW_BYTES_FIELD: u32 = 133;

/// A list event's type, coded in `events.bin` in upstream's `POIEventType` order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventType {
    /// Code 0.
    Shield,
    /// Code 1.
    Transact,
    /// Code 2.
    Unshield,
    /// Code 3.
    LegacyTransact,
}

impl EventType {
    /// In code order, which is also the key order of upstream's `poiEventLengths`.
    pub const ALL: [Self; 4] = [
        Self::Shield,
        Self::Transact,
        Self::Unshield,
        Self::LegacyTransact,
    ];

    /// The `events.bin` code.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::Shield => 0,
            Self::Transact => 1,
            Self::Unshield => 2,
            Self::LegacyTransact => 3,
        }
    }

    /// The type named by an `events.bin` code.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.code() == code)
    }

    /// The string upstream serves in `signedPOIEvent.type`.
    #[must_use]
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::Shield => "Shield",
            Self::Transact => "Transact",
            Self::Unshield => "Unshield",
            Self::LegacyTransact => "LegacyTransact",
        }
    }
}

/// One list event, its hashes as the big-endian bytes of the wire hex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRow {
    /// Global list index.
    pub index: u32,
    /// Event type.
    pub event_type: EventType,
    /// `blindedCommitment`.
    pub blinded_commitment: [u8; 32],
    /// `validatedMerkleroot`: the root of the event's tree right after its insert.
    pub validated_merkleroot: [u8; 32],
    /// The list provider's ed25519 signature.
    pub signature: [u8; 64],
}

/// The exact strings upstream served for a row whose canonical rebuild differs from them.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct WireOverride {
    /// `blindedCommitment` as served.
    #[serde(rename = "blindedCommitment")]
    pub blinded_commitment: String,
    /// `signature` as served.
    pub signature: String,
    /// `type` as served.
    #[serde(rename = "type")]
    pub event_type: String,
    /// `validatedMerkleroot` as served.
    #[serde(rename = "validatedMerkleroot")]
    pub validated_merkleroot: String,
}

/// The chain a capture was taken on, as named in its manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainScope {
    /// Upstream `chainType`.
    pub chain_type: u32,
    /// Upstream `chainID`.
    pub chain_id: u32,
    /// Upstream network name, the key under `forNetwork` in node status.
    pub network: String,
    /// Upstream `txidVersion`.
    pub txid_version: String,
}

/// A whole list, index 0 onward, with the rows whose wire strings are not canonical.
#[derive(Clone, Debug)]
pub struct Capture {
    list_key: [u8; 32],
    rows: Vec<EventRow>,
    overrides: BTreeMap<u32, WireOverride>,
}

impl Capture {
    /// # Errors
    ///
    /// [`ReplayError::EventsBin`] if row `i` does not carry index `i`, and
    /// [`ReplayError::Noncanonical`] if an override names a row that does not exist or decodes
    /// to bytes other than that row's.
    pub fn new(
        list_key: [u8; 32],
        rows: Vec<EventRow>,
        overrides: BTreeMap<u32, WireOverride>,
    ) -> Result<Self> {
        if let Some((position, row)) = rows
            .iter()
            .enumerate()
            .find(|(position, row)| usize::try_from(row.index).ok() != Some(*position))
        {
            return Err(ReplayError::EventsBin(format!(
                "row {position} carries index {}; a replay serves a contiguous list from 0",
                row.index
            )));
        }
        for (index, wire) in &overrides {
            let row = usize::try_from(*index)
                .ok()
                .and_then(|i| rows.get(i))
                .ok_or_else(|| {
                    ReplayError::Noncanonical(format!(
                        "override for index {index}, but the list has {} rows",
                        rows.len()
                    ))
                })?;
            check_override(row, wire)?;
        }
        Ok(Self {
            list_key,
            rows,
            overrides,
        })
    }

    /// Reads `events.bin`, `noncanonical.jsonl` when present, and the manifest's chain block,
    /// and refuses a folder whose manifest disagrees with its `events.bin`.
    ///
    /// # Errors
    ///
    /// [`ReplayError::Io`] on a read failure, otherwise the error of the file that is wrong.
    pub fn load_dir(dir: &Path) -> Result<(Self, ChainScope)> {
        let (list_key, rows) = read_events_bin(&read(&dir.join("events.bin"))?)?;
        let noncanonical = dir.join("noncanonical.jsonl");
        let overrides = if noncanonical.exists() {
            let text = String::from_utf8(read(&noncanonical)?).map_err(|e| {
                ReplayError::Noncanonical(format!("{}: not UTF-8: {e}", noncanonical.display()))
            })?;
            parse_noncanonical_jsonl(&text)?
        } else {
            BTreeMap::new()
        };
        let manifest = read(&dir.join("manifest.json"))?;
        let scope = check_manifest(&manifest, &list_key, rows.len())?;
        Ok((Self::new(list_key, rows, overrides)?, scope))
    }

    /// The list key, which is also the list provider's ed25519 public key.
    #[must_use]
    pub fn list_key(&self) -> &[u8; 32] {
        &self.list_key
    }

    /// Every row, index order.
    #[must_use]
    pub fn rows(&self) -> &[EventRow] {
        &self.rows
    }

    pub(crate) fn wire_override(&self, index: u32) -> Option<&WireOverride> {
        self.overrides.get(&index)
    }

    pub(crate) fn overrides(&self) -> impl Iterator<Item = (&u32, &WireOverride)> {
        self.overrides.iter()
    }

    /// The `validatedMerkleroot` string upstream serves for row `index`.
    pub(crate) fn root_wire(&self, row: &EventRow) -> String {
        self.wire_override(row.index).map_or_else(
            || hex(&row.validated_merkleroot),
            |w| w.validated_merkleroot.clone(),
        )
    }
}

fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|source| ReplayError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn check_override(row: &EventRow, wire: &WireOverride) -> Result<()> {
    let refuse = |field: &str| {
        Err(ReplayError::Noncanonical(format!(
            "override for index {}: {field} does not decode to the events.bin row's bytes",
            row.index
        )))
    };
    if decode_hex::<32>(&wire.blinded_commitment) != Some(row.blinded_commitment) {
        return refuse("blindedCommitment");
    }
    if decode_hex::<32>(&wire.validated_merkleroot) != Some(row.validated_merkleroot) {
        return refuse("validatedMerkleroot");
    }
    if decode_hex::<64>(&wire.signature) != Some(row.signature) {
        return refuse("signature");
    }
    if wire.event_type != row.event_type.wire_name() {
        return refuse("type");
    }
    Ok(())
}

fn check_manifest(bytes: &[u8], list_key: &[u8; 32], rows: usize) -> Result<ChainScope> {
    let manifest: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| ReplayError::Manifest(format!("manifest.json is not JSON: {e}")))?;
    let field = |path: &[&str]| {
        path.iter()
            .try_fold(&manifest, |v, key| v.get(key))
            .ok_or_else(|| {
                ReplayError::Manifest(format!("manifest.json has no {}", path.join(".")))
            })
    };
    let text = |path: &[&str]| -> Result<String> {
        match field(path)? {
            serde_json::Value::String(s) => Ok(s.clone()),
            serde_json::Value::Number(n) => Ok(n.to_string()),
            other => Err(ReplayError::Manifest(format!(
                "manifest.json {} is {other}, not a string",
                path.join(".")
            ))),
        }
    };
    let number = |path: &[&str]| -> Result<u64> {
        let raw = text(path)?;
        raw.parse().map_err(|_| {
            ReplayError::Manifest(format!(
                "manifest.json {} is {raw}, not an integer",
                path.join(".")
            ))
        })
    };
    let manifest_key = text(&["list_key"])?;
    if manifest_key != hex(list_key) {
        return Err(ReplayError::Manifest(format!(
            "manifest.json list_key {manifest_key} is not events.bin's {}",
            hex(list_key)
        )));
    }
    let n = number(&["n"])?;
    if u64::try_from(rows).ok() != Some(n) {
        return Err(ReplayError::Manifest(format!(
            "manifest.json n is {n}, events.bin holds {rows} rows"
        )));
    }
    let small = |path: &[&str]| -> Result<u32> {
        let v = number(path)?;
        u32::try_from(v).map_err(|_| {
            ReplayError::Manifest(format!("manifest.json {} is {v}, past u32", path.join(".")))
        })
    };
    Ok(ChainScope {
        chain_type: small(&["chain", "chainType"])?,
        chain_id: small(&["chain", "chainID"])?,
        network: text(&["chain", "network"])?,
        txid_version: text(&["chain", "txidVersion"])?,
    })
}

/// Decodes an `events.bin` image into its list key and rows.
///
/// # Errors
///
/// [`ReplayError::EventsBin`] naming the header field or row that is wrong.
pub fn read_events_bin(bytes: &[u8]) -> Result<([u8; 32], Vec<EventRow>)> {
    let bad = |reason: String| ReplayError::EventsBin(reason);
    let header = bytes.get(..EVENTS_BIN_HEADER_BYTES).ok_or_else(|| {
        bad(format!(
            "{} bytes is shorter than the {EVENTS_BIN_HEADER_BYTES}-byte header",
            bytes.len()
        ))
    })?;
    let mut fields = Reader(header);
    let magic: [u8; 8] = fields.take()?;
    if magic != EVENTS_BIN_MAGIC {
        return Err(bad(format!("magic {magic:?} is not RVNPPOI1")));
    }
    let version = u32::from_le_bytes(fields.take()?);
    if version != EVENTS_BIN_VERSION {
        return Err(bad(format!(
            "version {version}, this reader knows {EVENTS_BIN_VERSION}"
        )));
    }
    let row_size = u32::from_le_bytes(fields.take()?);
    if row_size != ROW_BYTES_FIELD {
        return Err(bad(format!(
            "row size {row_size}, expected {EVENTS_BIN_ROW_BYTES}"
        )));
    }
    let count = u64::from_le_bytes(fields.take()?);
    let first_index = u64::from_le_bytes(fields.take()?);
    if first_index != 0 {
        return Err(bad(format!(
            "first_index {first_index}; a replay serves the list from index 0"
        )));
    }
    let list_key: [u8; 32] = fields.take()?;
    let body = bytes.get(EVENTS_BIN_HEADER_BYTES..).unwrap_or_default();
    let expected = usize::try_from(count)
        .ok()
        .and_then(|c| c.checked_mul(EVENTS_BIN_ROW_BYTES))
        .ok_or_else(|| bad(format!("count {count} overflows the address space")))?;
    if body.len() != expected {
        return Err(bad(format!(
            "header says {count} rows ({expected} bytes), file holds {} bytes of rows",
            body.len()
        )));
    }
    let rows = body
        .as_chunks::<EVENTS_BIN_ROW_BYTES>()
        .0
        .iter()
        .map(|chunk| {
            let mut row = Reader(chunk);
            let index = u32::from_le_bytes(row.take()?);
            let [code] = row.take::<1>()?;
            let event_type = EventType::from_code(code)
                .ok_or_else(|| bad(format!("row {index} has unknown type code {code}")))?;
            Ok(EventRow {
                index,
                event_type,
                blinded_commitment: row.take()?,
                validated_merkleroot: row.take()?,
                signature: row.take()?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((list_key, rows))
}

/// Encodes rows as an `events.bin` image, the inverse of [`read_events_bin`].
#[must_use]
pub fn write_events_bin(list_key: &[u8; 32], rows: &[EventRow]) -> Vec<u8> {
    let mut out = Vec::with_capacity(EVENTS_BIN_HEADER_BYTES + rows.len() * EVENTS_BIN_ROW_BYTES);
    out.extend_from_slice(&EVENTS_BIN_MAGIC);
    out.extend_from_slice(&EVENTS_BIN_VERSION.to_le_bytes());
    out.extend_from_slice(&ROW_BYTES_FIELD.to_le_bytes());
    out.extend_from_slice(&u64::try_from(rows.len()).unwrap_or(u64::MAX).to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(list_key);
    for row in rows {
        out.extend_from_slice(&row.index.to_le_bytes());
        out.push(row.event_type.code());
        out.extend_from_slice(&row.blinded_commitment);
        out.extend_from_slice(&row.validated_merkleroot);
        out.extend_from_slice(&row.signature);
    }
    out
}

/// Parses `noncanonical.jsonl`: one upstream row per line, its wire strings plus `index`.
///
/// # Errors
///
/// [`ReplayError::Noncanonical`] naming the line that does not parse or repeats an index.
pub fn parse_noncanonical_jsonl(text: &str) -> Result<BTreeMap<u32, WireOverride>> {
    #[derive(serde::Deserialize)]
    struct Line {
        index: u32,
        #[serde(flatten)]
        wire: WireOverride,
    }
    let mut out = BTreeMap::new();
    for (number, line) in text
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
    {
        let parsed: Line = serde_json::from_str(line).map_err(|e| {
            ReplayError::Noncanonical(format!("noncanonical.jsonl line {}: {e}", number + 1))
        })?;
        if out.insert(parsed.index, parsed.wire).is_some() {
            return Err(ReplayError::Noncanonical(format!(
                "noncanonical.jsonl line {} repeats index {}",
                number + 1,
                parsed.index
            )));
        }
    }
    Ok(out)
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let (head, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or_else(|| ReplayError::EventsBin(format!("truncated field of {N} bytes")))?;
        self.0 = rest;
        Ok(*head)
    }
}

/// Lowercase hex, no prefix.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(index: u32) -> EventRow {
        let fill = u8::try_from(index % 200).expect("small");
        EventRow {
            index,
            event_type: EventType::ALL[usize::try_from(index % 4).expect("small")],
            blinded_commitment: [fill; 32],
            validated_merkleroot: [fill.wrapping_add(1); 32],
            signature: [fill.wrapping_add(2); 64],
        }
    }

    #[test]
    fn events_bin_round_trips_with_the_documented_layout() {
        let key = [0xab; 32];
        let rows: Vec<EventRow> = (0..5).map(row).collect();
        let image = write_events_bin(&key, &rows);
        assert_eq!(image.len(), 64 + 5 * 133);
        assert_eq!(&image[..8], b"RVNPPOI1");
        assert_eq!(image[16..24], 5u64.to_le_bytes());
        assert_eq!(image[32..64], key);
        assert_eq!(image[64 + 133 + 4], 1, "row 1 is Transact, code 1");
        assert_eq!(read_events_bin(&image).expect("read"), (key, rows));
    }

    #[test]
    fn events_bin_refuses_a_damaged_image() {
        let image = write_events_bin(&[1; 32], &[row(0), row(1)]);
        let mut magic = image.clone();
        magic[0] = b'X';
        let mut short = image.clone();
        short.pop();
        let mut first_index = image.clone();
        first_index[24] = 3;
        let mut type_code = image.clone();
        type_code[64 + 4] = 9;
        for (damaged, needle) in [
            (magic, "magic"),
            (short, "bytes of rows"),
            (first_index, "first_index 3"),
            (type_code, "type code 9"),
        ] {
            let error = read_events_bin(&damaged).expect_err(needle).to_string();
            assert!(error.contains(needle), "{error}");
        }
        let error = Capture::new([1; 32], vec![row(0), row(2)], BTreeMap::new())
            .expect_err("gap")
            .to_string();
        assert!(error.contains("row 1 carries index 2"), "{error}");
    }

    #[test]
    fn an_override_must_decode_to_its_rows_bytes() {
        let rows: Vec<EventRow> = (0..3).map(row).collect();
        let bare = |r: &EventRow| WireOverride {
            blinded_commitment: hex(&r.blinded_commitment),
            signature: hex(&r.signature),
            event_type: r.event_type.wire_name().to_owned(),
            validated_merkleroot: hex(&r.validated_merkleroot),
        };
        let mut good = BTreeMap::new();
        good.insert(2, bare(&rows[2]));
        Capture::new([0; 32], rows.clone(), good)
            .expect("an unprefixed commitment is the same bytes");

        let mut wrong = BTreeMap::new();
        wrong.insert(1, bare(&rows[2]));
        let error = Capture::new([0; 32], rows.clone(), wrong)
            .expect_err("wrong")
            .to_string();
        assert!(error.contains("index 1: blindedCommitment"), "{error}");

        let mut beyond = BTreeMap::new();
        beyond.insert(3, bare(&rows[2]));
        assert!(Capture::new([0; 32], rows.clone(), beyond).is_err());

        let mut signed_digit = BTreeMap::new();
        let mut plus = bare(&rows[2]);
        plus.blinded_commitment = format!("+{}", &plus.blinded_commitment[1..]);
        signed_digit.insert(2, plus);
        let error = Capture::new([0; 32], rows, signed_digit)
            .expect_err("a signed digit pair is not hex")
            .to_string();
        assert!(error.contains("index 2: blindedCommitment"), "{error}");
    }

    #[test]
    fn noncanonical_lines_parse_by_index_and_refuse_a_repeat() {
        let line = r#"{"blindedCommitment":"01","index":7,"signature":"02","type":"Unshield","validatedMerkleroot":"03"}"#;
        let parsed = parse_noncanonical_jsonl(&format!("{line}\n")).expect("parse");
        assert_eq!(
            parsed.get(&7).map(|w| w.blinded_commitment.as_str()),
            Some("01")
        );
        assert!(parse_noncanonical_jsonl(&format!("{line}\n{line}\n")).is_err());
    }
}
