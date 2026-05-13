//! Versioned bincode wire format helpers.

/// Bincode allocation cap per deserialize call; matches the HTTP body cap.
/// Prevents a crafted length prefix triggering `Vec::with_capacity(2^48)`.
pub(crate) const BINCODE_DESERIALIZE_LIMIT: u64 = 8 * 1024 * 1024;

pub(crate) fn bincode_deserialize_capped<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> bincode::Result<T> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_limit(BINCODE_DESERIALIZE_LIMIT)
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .deserialize(bytes)
}

/// Wire-protocol schema version; u16 BE prefix on every bincode body.
/// A major bump means a structural break requiring all clients to upgrade.
pub const WIRE_SCHEMA_VERSION: u16 = 1;

/// Length of the [`WIRE_SCHEMA_VERSION`] prefix in bytes.
pub const WIRE_SCHEMA_PREFIX_LEN: usize = 2;

/// Surfaced on 400 BadVersion responses so the client can diagnose mismatch.
pub const X_RAVEN_SCHEMA_VERSION: &str = "X-Raven-Schema-Version";

pub(crate) const X_RAVEN_SCHEMA_VERSION_HEADER: &str = "x-raven-schema-version";

/// Decode a versioned wire body, returning `Err` on short body or version mismatch.
pub fn read_versioned<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, VersionedDecodeError> {
    if bytes.len() < WIRE_SCHEMA_PREFIX_LEN {
        return Err(VersionedDecodeError::Short {
            got: bytes.len(),
            need: WIRE_SCHEMA_PREFIX_LEN,
        });
    }
    let version_bytes = bytes
        .get(..WIRE_SCHEMA_PREFIX_LEN)
        .ok_or(VersionedDecodeError::Short {
            got: bytes.len(),
            need: WIRE_SCHEMA_PREFIX_LEN,
        })?;
    let mut buf = [0u8; WIRE_SCHEMA_PREFIX_LEN];
    buf.copy_from_slice(version_bytes);
    let version = u16::from_be_bytes(buf);
    if version != WIRE_SCHEMA_VERSION {
        return Err(VersionedDecodeError::BadVersion {
            expected: WIRE_SCHEMA_VERSION,
            got: version,
        });
    }
    let payload = bytes
        .get(WIRE_SCHEMA_PREFIX_LEN..)
        .ok_or(VersionedDecodeError::Short {
            got: bytes.len(),
            need: WIRE_SCHEMA_PREFIX_LEN,
        })?;
    bincode_deserialize_capped(payload).map_err(|e| VersionedDecodeError::Bincode(e.to_string()))
}

/// Serialize a value with the versioned wire prefix.
pub fn write_versioned<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, bincode::Error> {
    let mut out = Vec::with_capacity(WIRE_SCHEMA_PREFIX_LEN + 64);
    out.extend_from_slice(&WIRE_SCHEMA_VERSION.to_be_bytes());
    let body = bincode::serialize(value)?;
    out.extend_from_slice(&body);
    Ok(out)
}

/// Serialize a batch into the cross-language wire format the SDK decoder expects.
///
/// ```text
/// [u16 BE schema version]
/// [u64 LE element count]
/// for each element:
///   [u64 LE element length]
///   [bincode(element) bytes]
/// ```
///
/// Per-element length-prefixing is required because `S::Response` is variable-length;
/// a flat `bincode::serialize(&Vec<T>)` emits no per-element delimiters.
/// SDK decoder: `sdk/typescript-railgun/src/raven-poi-node-interface.ts:909-946`.
///
/// # Errors
/// Returns `bincode::Error` if any element fails to serialize.
pub fn write_batch_response_versioned<T: serde::Serialize>(
    items: &[T],
) -> Result<Vec<u8>, bincode::Error> {
    let mut out = Vec::with_capacity(WIRE_SCHEMA_PREFIX_LEN + 8 + items.len() * 64);
    out.extend_from_slice(&WIRE_SCHEMA_VERSION.to_be_bytes());
    let count = u64::try_from(items.len()).map_err(|_| bincode::ErrorKind::SizeLimit)?;
    out.extend_from_slice(&count.to_le_bytes());
    for item in items {
        let body = bincode::serialize(item)?;
        let elem_len = u64::try_from(body.len()).map_err(|_| bincode::ErrorKind::SizeLimit)?;
        out.extend_from_slice(&elem_len.to_le_bytes());
        out.extend_from_slice(&body);
    }
    Ok(out)
}

/// Decode a batch-response body emitted by [`write_batch_response_versioned`].
///
/// # Errors
/// Returns [`VersionedDecodeError`] on schema mismatch, short body, or bincode failure.
pub fn read_batch_response_versioned<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<Vec<T>, VersionedDecodeError> {
    let header_end = WIRE_SCHEMA_PREFIX_LEN + 8;
    if bytes.len() < header_end {
        return Err(VersionedDecodeError::Short {
            got: bytes.len(),
            need: header_end,
        });
    }
    let prefix = bytes
        .get(..WIRE_SCHEMA_PREFIX_LEN)
        .ok_or(VersionedDecodeError::Short {
            got: bytes.len(),
            need: WIRE_SCHEMA_PREFIX_LEN,
        })?;
    let mut buf = [0u8; WIRE_SCHEMA_PREFIX_LEN];
    buf.copy_from_slice(prefix);
    let version = u16::from_be_bytes(buf);
    if version != WIRE_SCHEMA_VERSION {
        return Err(VersionedDecodeError::BadVersion {
            expected: WIRE_SCHEMA_VERSION,
            got: version,
        });
    }
    let count_slice =
        bytes
            .get(WIRE_SCHEMA_PREFIX_LEN..header_end)
            .ok_or(VersionedDecodeError::Short {
                got: bytes.len(),
                need: header_end,
            })?;
    let mut count_buf = [0u8; 8];
    count_buf.copy_from_slice(count_slice);
    let count_u64 = u64::from_le_bytes(count_buf);
    let count = usize::try_from(count_u64).map_err(|_| {
        VersionedDecodeError::Bincode(format!("batch count exceeds usize: {count_u64}"))
    })?;
    // Cap up-front allocation so a crafted count can't trigger Vec::with_capacity(2^48).
    let cap = count.min(usize::try_from(BINCODE_DESERIALIZE_LIMIT).unwrap_or(usize::MAX) / 16);
    let mut out: Vec<T> = Vec::with_capacity(cap);
    let mut offset = header_end;
    for idx in 0..count {
        let elem_header_end = offset.checked_add(8).ok_or(VersionedDecodeError::Short {
            got: bytes.len(),
            need: usize::MAX,
        })?;
        let len_slice = bytes
            .get(offset..elem_header_end)
            .ok_or(VersionedDecodeError::Short {
                got: bytes.len(),
                need: elem_header_end,
            })?;
        let mut len_buf = [0u8; 8];
        len_buf.copy_from_slice(len_slice);
        let elem_len_u64 = u64::from_le_bytes(len_buf);
        let elem_len = usize::try_from(elem_len_u64).map_err(|_| {
            VersionedDecodeError::Bincode(format!(
                "element {idx} length exceeds usize: {elem_len_u64}"
            ))
        })?;
        offset = elem_header_end;
        let elem_end = offset
            .checked_add(elem_len)
            .ok_or(VersionedDecodeError::Short {
                got: bytes.len(),
                need: usize::MAX,
            })?;
        let elem_bytes = bytes
            .get(offset..elem_end)
            .ok_or(VersionedDecodeError::Short {
                got: bytes.len(),
                need: elem_end,
            })?;
        let elem: T = bincode_deserialize_capped(elem_bytes)
            .map_err(|e| VersionedDecodeError::Bincode(format!("element {idx}: {e}")))?;
        out.push(elem);
        offset = elem_end;
    }
    Ok(out)
}

/// Errors surfaced by [`read_versioned`].
#[derive(Debug, thiserror::Error)]
pub enum VersionedDecodeError {
    /// Body shorter than the version prefix.
    #[error("body too short: got {got} bytes, need >= {need}")]
    Short {
        /// Bytes received.
        got: usize,
        /// Bytes required.
        need: usize,
    },
    /// Leading u16 doesn't match [`WIRE_SCHEMA_VERSION`].
    #[error("schema version mismatch: server expects v{expected}, client sent v{got}")]
    BadVersion {
        /// Server's expected version.
        expected: u16,
        /// Client-supplied version.
        got: u16,
    },
    /// Bincode deserialize failed after version prefix was accepted.
    #[error("bincode decode: {0}")]
    Bincode(String),
}
