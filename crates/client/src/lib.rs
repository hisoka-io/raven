//! Wasm-compatible PIR client surface for Raven: query construction and response
//! extraction across the JS/Wasm boundary.
//!
//! This surface is InsPIRe-typed (`InspireParams`/`ShardConfig`). The packing
//! mode is whatever the session derived from the CRS and whatever the server
//! tagged the response with; this layer never overrides either. All complex Rust
//! types cross the JS boundary as bincode-encoded `Vec<u8>`. See
//! `tests/parity_native_vs_wasm.rs` for byte-equality tests against a native
//! Rust client.
//!
//! Production entry points draw the RLWE key, packing-key noise, query noise,
//! cover selection, and batch permutation from `OsRng`-seeded streams. No
//! `#[wasm_bindgen]` entry point accepts caller-supplied randomness. The
//! `#[doc(hidden)]` test seams [`build_seeded_query_rust_with_noise_seed`] and
//! [`build_padded_batch_rust_with_test_rng`] never cross the JS boundary.
//! `tests/client_entropy_kat.rs` covers the entropy-drawn query path.

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]
#![deny(missing_docs)]

use rand::rngs::OsRng;
use rand::RngCore;
use raven_inspire::inspiring::PackParams;
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, ShardConfig};
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::{
    extract_two_packing, ClientSession, ClientState, SeededClientQuery, ServerCrs, ServerResponse,
    SessionResidue,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Route Rust panics to structured JS exceptions instead of opaque WASM traps. Idempotent.
#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[derive(Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
struct WasmInstanceParamsBundle {
    inspire_params_bincode: Vec<u8>,
    shard_config_bincode: Vec<u8>,
    rlwe_secret_key_bincode: Vec<u8>,
}

impl std::fmt::Debug for WasmInstanceParamsBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmInstanceParamsBundle")
            .field("inspire_params_len", &self.inspire_params_bincode.len())
            .field("shard_config_len", &self.shard_config_bincode.len())
            .field("rlwe_secret_key_len", &self.rlwe_secret_key_bincode.len())
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
enum WasmClientError {
    #[error("bincode deserialize {what}: {detail}")]
    Decode { what: &'static str, detail: String },
    #[error("bincode serialize {what}: {detail}")]
    Encode { what: &'static str, detail: String },
    #[error("raven-inspire {op}: {detail}")]
    Inspire { op: &'static str, detail: String },
    #[error("OS entropy unavailable for {what}: {detail}")]
    Entropy { what: &'static str, detail: String },
}

const VERSIONED_BATCH_FRAME_BYTES: usize = 2 + 8;

/// Failure while sizing or constructing a padded client batch.
///
/// ```
/// use raven_client::{padded_batch_ladder, PaddedBatchError};
///
/// assert_eq!(padded_batch_ladder(100, 410)?, vec![1, 2, 4]);
/// assert!(matches!(
///     padded_batch_ladder(usize::MAX, usize::MAX),
///     Err(PaddedBatchError::ArithmeticOverflow { .. })
/// ));
/// # Ok::<(), PaddedBatchError>(())
/// ```
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum PaddedBatchError {
    /// No real query was supplied.
    #[error("padded batch requires at least one real query")]
    EmptyBatch,
    /// No serialized query measurement was supplied.
    #[error(
        "serialized query size is zero; measure a serialized query before generating the padded \
         batch ladder"
    )]
    ZeroQuerySize,
    /// Request-size arithmetic exceeded the platform `usize` domain.
    #[error("padded batch size overflow while computing {operation}")]
    ArithmeticOverflow {
        /// Arithmetic operation that overflowed.
        operation: &'static str,
    },
    /// The caller's cap cannot hold even one framed query.
    #[error(
        "padded batch body cap {body_cap_bytes} bytes is below the one-query minimum \
         {minimum_body_bytes} bytes"
    )]
    BodyCapTooSmall {
        /// Caller-supplied request-body cap.
        body_cap_bytes: usize,
        /// Versioned one-query request size.
        minimum_body_bytes: usize,
    },
    /// Real queries fit only at an off-ladder length.
    #[error(
        "cannot pad {real_count} real queries to a dyadic step under the body cap; \
         at most {max_slots} serialized queries fit"
    )]
    ImpossiblePadding {
        /// Number of caller queries.
        real_count: usize,
        /// Raw slot capacity under the cap.
        max_slots: usize,
    },
    /// A query failed before the batch could be assembled.
    #[error("padded batch query slot {slot} for target {target_idx} failed: {detail}")]
    Query {
        /// Caller or cover slot being built.
        slot: usize,
        /// Global database index queried by the slot.
        target_idx: u64,
        /// Typed upstream query failure rendered with its context.
        detail: String,
    },
    /// Query serialization changed size inside one batch.
    #[error(
        "padded batch query slot {slot} serialized to {actual} bytes; expected the measured \
         {expected} bytes"
    )]
    QuerySizeMismatch {
        /// Wire slot with the unexpected size.
        slot: usize,
        /// First query's serialized size.
        expected: usize,
        /// Current query's serialized size.
        actual: usize,
    },
    /// A bounded unbiased random draw did not converge.
    #[error(
        "padded batch random draw below {upper_bound} did not converge in {attempts} attempts"
    )]
    RandomDrawExhausted {
        /// Exclusive upper bound requested by the shuffle or cover draw.
        upper_bound: usize,
        /// Bounded rejection attempts consumed.
        attempts: usize,
    },
    /// Bincode could not serialize a batch component.
    #[error("padded batch could not serialize {what}: {detail}")]
    Encode {
        /// Component being serialized.
        what: &'static str,
        /// Bincode failure.
        detail: String,
    },
    /// OS entropy was unavailable for the production CSPRNG.
    #[error("padded batch OS entropy unavailable: {detail}")]
    Entropy {
        /// Platform entropy failure.
        detail: String,
    },
    /// Session, parameter, or shard geometry is inconsistent.
    #[error("padded batch configuration rejected: {detail}")]
    Configuration {
        /// Actionable validation failure.
        detail: String,
    },
}

/// Generate the dyadic batch ladder that fits a measured serialized query and body cap.
///
/// The cap includes the two-byte schema prefix and the bincode `Vec` length. No deployment-specific
/// ceiling is embedded in the client.
///
/// ```
/// use raven_client::padded_batch_ladder;
///
/// assert_eq!(padded_batch_ladder(100, 410)?, vec![1, 2, 4]);
/// assert_eq!(padded_batch_ladder(100, 409)?, vec![1, 2]);
/// # Ok::<(), raven_client::PaddedBatchError>(())
/// ```
///
/// # Errors
/// Returns [`PaddedBatchError::ZeroQuerySize`] without a real measurement,
/// [`PaddedBatchError::ArithmeticOverflow`] when the framed size cannot be represented, or
/// [`PaddedBatchError::BodyCapTooSmall`] when no query fits.
pub fn padded_batch_ladder(
    serialized_query_bytes: usize,
    body_cap_bytes: usize,
) -> Result<Vec<usize>, PaddedBatchError> {
    if serialized_query_bytes == 0 {
        return Err(PaddedBatchError::ZeroQuerySize);
    }
    let minimum_body_bytes = VERSIONED_BATCH_FRAME_BYTES
        .checked_add(serialized_query_bytes)
        .ok_or(PaddedBatchError::ArithmeticOverflow {
            operation: "one-query request bytes",
        })?;
    if body_cap_bytes < minimum_body_bytes {
        return Err(PaddedBatchError::BodyCapTooSmall {
            body_cap_bytes,
            minimum_body_bytes,
        });
    }

    let max_slots = (body_cap_bytes - VERSIONED_BATCH_FRAME_BYTES) / serialized_query_bytes;
    let mut ladder = Vec::new();
    let mut step = 1usize;
    while step <= max_slots {
        ladder.push(step);
        let Some(next) = step.checked_mul(2) else {
            break;
        };
        step = next;
    }
    Ok(ladder)
}

/// Gaussian sampler over a fresh 32-byte OS seed.
///
/// A failed draw surfaces as an error; falling back to a weaker source would
/// hand every client the same secret key.
fn os_seeded_sampler(sigma: f64, what: &'static str) -> Result<GaussianSampler, WasmClientError> {
    let mut seed = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut seed)
        .map_err(|e| WasmClientError::Entropy {
            what,
            detail: e.to_string(),
        })?;
    Ok(GaussianSampler::from_seed(sigma, seed))
}

impl From<WasmClientError> for JsValue {
    fn from(value: WasmClientError) -> Self {
        JsValue::from_str(&value.to_string())
    }
}

impl From<PaddedBatchError> for JsValue {
    fn from(value: PaddedBatchError) -> Self {
        JsValue::from_str(&value.to_string())
    }
}

/// Allocation cap for untrusted bincode crossing the JS->Wasm boundary (64 MiB).
///
/// Enforced as a slice-length pre-check, not `bincode::Options::with_limit`:
/// bincode 1.3.3's slice path (`src/internal.rs:114` `deserialize_seed`) overrides
/// any configured limit to `Infinite`, so `with_limit` is a no-op for
/// `bincode::deserialize(bytes)`. This is a trust-boundary ceiling, not a version
/// envelope: individual types can impose a smaller cap and their own layout marker.
pub const WASM_BINCODE_DESERIALIZE_LIMIT_BYTES: usize = 64 * 1024 * 1024;

/// Allocation cap for a self-authored session-residue blob from
/// [`serialize_client_session`] (32 MiB).
///
/// The residue (CRS + secret key + packing-key body, no automorph tables) is
/// ~1.25 MiB at d=2048 and ~2.5 MiB at d=4096; 32 MiB is ~10x the largest-ring
/// residue, so a malformed cached blob is rejected by the cheap length check
/// before a large contiguous allocation is attempted in a 32-bit wasm heap. This
/// smaller cap is valid only for the client's self-authored cache format.
pub const WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES: usize = 32 * 1024 * 1024;

/// Decode server-supplied [`InspireParams`] and enforce [`InspireParams::validate`].
///
/// Every field arrives over the wire under the server's control, and `sigma` in
/// particular drives secret-key and query-noise sampling, so nothing downstream may
/// consume these unvalidated.
fn decode_validated_params(
    bytes: &[u8],
    what: &'static str,
) -> Result<InspireParams, WasmClientError> {
    let params: InspireParams = decode(bytes, what)?;
    params
        .validate()
        .map_err(|detail| WasmClientError::Decode {
            what,
            detail: format!("server-supplied params rejected: {detail}"),
        })?;
    Ok(params)
}

/// Decode the bundle's `ShardConfig`, pin it to `params`, and return the server's
/// declared record width.
fn decode_validated_shard_config(
    shard_config_bincode: &[u8],
    params: &InspireParams,
) -> Result<ShardConfig, WasmClientError> {
    let shard_config: ShardConfig = decode(shard_config_bincode, "shard_config")?;
    shard_config
        .validate_for_params(params)
        .map_err(|detail| WasmClientError::Decode {
            what: "shard_config",
            detail: format!("shard geometry does not match the params ring: {detail}"),
        })?;
    Ok(shard_config)
}

// Adapter HTTP envelope version; parity-gated here to avoid a framework-to-transport dependency.
const SESSION_WIRE_SCHEMA_VERSION: u16 = 6;

fn decode<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    what: &'static str,
) -> Result<T, WasmClientError> {
    use bincode::Options;

    if bytes.len() > WASM_BINCODE_DESERIALIZE_LIMIT_BYTES {
        return Err(WasmClientError::Decode {
            what,
            detail: format!(
                "size limit reached: payload {} bytes exceeds cap {}",
                bytes.len(),
                WASM_BINCODE_DESERIALIZE_LIMIT_BYTES
            ),
        });
    }
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| WasmClientError::Decode {
            what,
            detail: e.to_string(),
        })
}

/// [`decode`] with the 32 MiB trusted cap. MUST NOT see HTTP-sourced bytes;
/// only self-written session blobs round-tripped through client storage.
fn decode_trusted<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    what: &'static str,
) -> Result<T, WasmClientError> {
    if bytes.len() > WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES {
        return Err(WasmClientError::Decode {
            what,
            detail: format!(
                "size limit reached: payload {} bytes exceeds cap {}",
                bytes.len(),
                WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES
            ),
        });
    }
    bincode::deserialize::<T>(bytes).map_err(|e| WasmClientError::Decode {
        what,
        detail: e.to_string(),
    })
}

fn encode<T: Serialize>(value: &T, what: &'static str) -> Result<Vec<u8>, WasmClientError> {
    bincode::serialize(value).map_err(|e| WasmClientError::Encode {
        what,
        detail: e.to_string(),
    })
}

/// Decode an HTTP-sourced CRS blob: enforce the general 64 MiB untrusted cap, then
/// let [`ServerCrs`] enforce its artifact-specific 16 MiB body cap and magic. The
/// nested limits serve different trust and type boundaries rather than competing
/// envelope conventions.
fn decode_versioned_crs(bytes: &[u8]) -> Result<ServerCrs, WasmClientError> {
    if bytes.len() > WASM_BINCODE_DESERIALIZE_LIMIT_BYTES {
        return Err(WasmClientError::Decode {
            what: "server_crs",
            detail: format!(
                "size limit reached: payload {} bytes exceeds cap {}",
                bytes.len(),
                WASM_BINCODE_DESERIALIZE_LIMIT_BYTES
            ),
        });
    }
    ServerCrs::from_versioned_bytes(bytes).map_err(|e| WasmClientError::Decode {
        what: "server_crs",
        detail: e.to_string(),
    })
}

/// The cached session must have been derived under the CRS the instance serves NOW.
///
/// Packing keys are a function of `w_seed`, and nothing downstream compares them: the server's only
/// geometry check looks at gamma and key length, which a stale key set satisfies exactly. So a
/// session reused across a CRS rotation produces a well-formed query, a successful respond and a
/// successful extract that returns bytes unrelated to the record. The seed is already on the wire -
/// the published CRS strips `galois_keys` but keeps `inspiring_w_seed` - so both values are in hand
/// here, which makes this the one place the comparison can happen.
fn ensure_session_matches_live_crs(
    session: &ClientSession,
    crs_bincode: &[u8],
) -> Result<(), String> {
    let live = ServerCrs::from_versioned_bytes(crs_bincode).map_err(|e| e.to_string())?;
    let held = session.crs();
    ensure_session_params_match(&held.params, &live.params)
        .map_err(|detail| format!("deserialize_client_session: live CRS {detail}"))?;
    if held.inspiring_w_seed != live.inspiring_w_seed {
        return Err(format!(
            "deserialize_client_session: this session was derived under CRS w_seed {} but the \
             instance now serves {}. Packing keys are a function of w_seed and nothing downstream \
             compares them, so reusing this session would return wrong bytes at HTTP 200. Discard \
             the cached session and re-run the handshake against the current CRS.",
            hex8(&held.inspiring_w_seed),
            hex8(&live.inspiring_w_seed)
        ));
    }
    if held.inspiring_num_columns != live.inspiring_num_columns {
        return Err(format!(
            "deserialize_client_session: this session was derived at {} packing columns but the \
             instance now serves {}. The record width changed, so extraction would reassemble the \
             wrong number of bytes. Discard the cached session and re-run the handshake.",
            held.inspiring_num_columns, live.inspiring_num_columns
        ));
    }
    Ok(())
}

fn ensure_session_params_match(
    held: &InspireParams,
    current: &InspireParams,
) -> Result<(), String> {
    if current.ring_dim != held.ring_dim
        || current.q != held.q
        || current.crt_moduli != held.crt_moduli
        || current.p != held.p
        || current.sigma.to_bits() != held.sigma.to_bits()
        || current.gadget_base != held.gadget_base
        || current.query_gadget_len != held.query_gadget_len
        || current.packing_gadget_len != held.packing_gadget_len
    {
        return Err(
            "ring_dim/q/p/sigma mismatch or CRT/gadget drift: session parameters drifted from the \
             live tuple; discard the cached session and rebuild it from one consistent params/CRS response"
                .to_owned(),
        );
    }
    Ok(())
}

/// First eight bytes, enough to name WHICH seed without printing key-adjacent material in full.
fn hex8(seed: &[u8; 32]) -> String {
    let mut out = String::with_capacity(16);
    for byte in seed.iter().take(8) {
        for nibble in [byte >> 4, byte & 0x0f] {
            out.push(char::from_digit(u32::from(nibble), 16).unwrap_or('?'));
        }
    }
    out
}

/// Opaque handle to an active [`ClientSession`]. Constructed via [`build_client_session`].
#[wasm_bindgen]
pub struct ClientSessionHandle {
    inner: ClientSession,
    params: InspireParams,
    shard_config: ShardConfig,
    registration_body: Vec<u8>,
}

impl std::fmt::Debug for ClientSessionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSessionHandle")
            .field("ring_dim", &self.params.ring_dim)
            .field("entry_size_bytes", &self.shard_config.entry_size_bytes)
            .field("has_handle", &self.inner.session_handle().is_some())
            .finish_non_exhaustive()
    }
}

/// Construct a [`ClientSessionHandle`] from a params bundle bincode blob
/// (produced by [`build_instance_params_blob`]) and the public CRS bincode.
/// Pays the one-time O(d^3) packing-key generation cost.
#[wasm_bindgen]
pub fn build_client_session(
    params_bundle_bincode: &[u8],
    crs_bincode: &[u8],
) -> Result<ClientSessionHandle, JsValue> {
    let bundle: WasmInstanceParamsBundle = decode(params_bundle_bincode, "params_bundle")?;
    let inspire_params = decode_validated_params(&bundle.inspire_params_bincode, "inspire_params")?;
    let secret_key: RlweSecretKey = decode(&bundle.rlwe_secret_key_bincode, "rlwe_secret_key")?;
    let crs = decode_versioned_crs(crs_bincode)?;
    // the packing keys ship to the server; a known error term solves for the secret key
    let mut sampler = os_seeded_sampler(inspire_params.sigma, "client_session_packing_keys")?;
    let session = ClientSession::new(crs, secret_key, &mut sampler).map_err(|e| {
        WasmClientError::Inspire {
            op: "ClientSession::new",
            detail: e.to_string(),
        }
    })?;
    let shard_config =
        decode_validated_shard_config(&bundle.shard_config_bincode, &inspire_params)?;
    let registration_body = session_registration_body(&session, &shard_config, &inspire_params)?;
    Ok(ClientSessionHandle {
        inner: session,
        params: inspire_params,
        shard_config,
        registration_body,
    })
}

/// Validate that `instance_params_bincode` matches the session's ring params.
/// Catches CRS/params drift at session-bind time rather than at first query.
#[wasm_bindgen]
pub fn register_client_session(
    session: &mut ClientSessionHandle,
    instance_params_bincode: &[u8],
) -> Result<(), JsValue> {
    let bundle: WasmInstanceParamsBundle = decode(instance_params_bincode, "params_bundle")?;
    let inspire_params = decode_validated_params(&bundle.inspire_params_bincode, "inspire_params")?;
    ensure_session_params_match(&session.inner.crs().params, &inspire_params)
        .map_err(|detail| JsValue::from_str(&format!("register_client_session: {detail}")))?;
    Ok(())
}

/// Serialize this session's client packing keys for `POST /v1/instance/:id/session`.
///
/// The body is `[u16 BE schema version][bincode ClientPackingKeys]`. It contains
/// key material and must be sent only to the instance that supplied this session's CRS.
#[wasm_bindgen]
pub fn client_packing_keys_versioned(session: &ClientSessionHandle) -> Result<Vec<u8>, JsValue> {
    Ok(session.registration_body.clone())
}

fn session_registration_body(
    session: &ClientSession,
    shard_config: &ShardConfig,
    params: &InspireParams,
) -> Result<Vec<u8>, WasmClientError> {
    let mut sampler = os_seeded_sampler(params.sigma, "session_registration_query")?;
    let (_, query) = session
        .query_seeded(0, shard_config, &mut sampler)
        .map_err(|e| WasmClientError::Inspire {
            op: "ClientSession::query_seeded for session registration",
            detail: e.to_string(),
        })?;
    let keys = query.inspiring_packing_keys.ok_or_else(|| WasmClientError::Inspire {
        op: "client_packing_keys_versioned",
        detail: "session has no inline packing keys; establish each remote session before installing its handle"
            .to_owned(),
    })?;
    let mut out = SESSION_WIRE_SCHEMA_VERSION.to_be_bytes().to_vec();
    out.extend_from_slice(&encode(&keys, "client_packing_keys")?);
    Ok(out)
}

/// Install the bare `u64` handle returned by the remote session endpoint.
///
/// Subsequent query bodies carry this handle and omit inline packing keys. The
/// server validates whether the opaque handle is current for that instance.
#[wasm_bindgen]
pub fn install_server_session_handle(
    session: &mut ClientSessionHandle,
    handle: u64,
) -> Result<(), JsValue> {
    session
        .inner
        .install_server_session_handle(raven_inspire::ServerSessionHandle(handle))
        .map_err(|e| WasmClientError::Inspire {
            op: "ClientSession::install_server_session_handle",
            detail: e.to_string(),
        })?;
    Ok(())
}

/// Output of [`build_seeded_query`].
#[derive(Serialize, Deserialize, Debug)]
pub struct WasmSeededQueryOutput {
    /// Per-query secret material needed to decrypt the response.
    /// Must NOT be sent to the server.
    pub client_state_bincode: Vec<u8>,
    /// Encrypted PIR query payload. POST to the server's query endpoint.
    pub query_bytes: Vec<u8>,
}

/// Bincode result of [`build_padded_batch`] for browser callers.
///
/// Only `query_batch_bytes` is sent to the server. Pair each response at
/// `response_slots[i]` with local-only `client_states_bincode[i]` to restore caller order.
#[derive(Serialize, Deserialize)]
pub struct WasmPaddedBatchOutput {
    /// Secret extraction states in the caller's original target order.
    pub client_states_bincode: Vec<Vec<u8>>,
    /// Versioned bincode `Vec<SeededClientQuery>` ready for the batch endpoint.
    pub query_batch_bytes: Vec<u8>,
    /// Wire response slot for each caller query, in caller order.
    pub response_slots: Vec<u32>,
}

impl std::fmt::Debug for WasmPaddedBatchOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmPaddedBatchOutput")
            .field("client_states", &self.client_states_bincode.len())
            .field("query_batch_bytes", &self.query_batch_bytes.len())
            .field("response_slots", &self.response_slots)
            .finish()
    }
}

/// Native padded-query batch with caller-order extraction metadata.
///
/// `queries` are shuffled into wire order. For caller query `i`, decrypt response
/// `response_slots[i]` with `client_states[i]`; cover responses are consumed but ignored.
pub struct PaddedBatch {
    /// Secret extraction states in the caller's original target order.
    pub client_states: Vec<ClientState>,
    /// Real and cover queries in shuffled wire order.
    pub queries: Vec<SeededClientQuery>,
    /// Wire response slot for each caller query, in caller order.
    pub response_slots: Vec<usize>,
    /// Serialized size measured from the first generated query.
    pub serialized_query_bytes: usize,
    /// Exact versioned request-body size for `queries`.
    pub request_bytes: usize,
    wire_targets: Vec<u64>,
}

impl std::fmt::Debug for PaddedBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PaddedBatch")
            .field("client_states", &self.client_states.len())
            .field("queries", &self.queries.len())
            .field("response_slots", &self.response_slots)
            .field("serialized_query_bytes", &self.serialized_query_bytes)
            .field("request_bytes", &self.request_bytes)
            .finish_non_exhaustive()
    }
}

impl PaddedBatch {
    /// Test-only view of real and cover targets in wire order.
    #[doc(hidden)]
    #[must_use]
    pub fn wire_targets_for_test(&self) -> &[u64] {
        &self.wire_targets
    }
}

/// Build a seeded PIR query for `target_idx`, in whatever packing mode the
/// session derived from the CRS.
///
/// The caller re-supplies `shard_config` per query, so it is checked against the
/// session's ring: a drifted geometry would otherwise map `target_idx` to a
/// different shard and retrieve the wrong record with no error.
#[wasm_bindgen]
pub fn build_seeded_query(
    session: &ClientSessionHandle,
    shard_config_bincode: &[u8],
    target_idx: u64,
) -> Result<Vec<u8>, JsValue> {
    let shard_config: ShardConfig = decode(shard_config_bincode, "shard_config")?;
    shard_config
        .validate_for_params(&session.params)
        .map_err(|detail| WasmClientError::Decode {
            what: "shard_config",
            detail: format!("shard geometry does not match the session ring: {detail}"),
        })?;
    // reused query noise lets the server re-encrypt each candidate index and match bytes
    let mut sampler = os_seeded_sampler(session.params.sigma, "seeded_query_noise")?;
    let (client_state, query) = session
        .inner
        .query_seeded(target_idx, &shard_config, &mut sampler)
        .map_err(|e| WasmClientError::Inspire {
            op: "ClientSession::query_seeded",
            detail: e.to_string(),
        })?;
    let client_state_bincode = encode(&client_state, "client_state")?;
    let query_bytes = encode(&query, "seeded_client_query")?;
    let bundle = WasmSeededQueryOutput {
        client_state_bincode,
        query_bytes,
    };
    Ok(encode(&bundle, "wasm_seeded_query_output")?)
}

/// Replace only the clear shard selector in a serialized seeded query.
///
/// Fanout responders override this field per response slot. Retargeting it to an independently
/// sampled slot prevents the original target shard from remaining as a clear marker while the
/// encrypted local-index query, packing mode, keys, and session handle remain unchanged.
///
/// # Errors
/// Returns a JS error when `query_bytes` is not exactly one valid bincode [`SeededClientQuery`].
#[wasm_bindgen]
pub fn retarget_seeded_query_shard(
    query_bytes: &[u8],
    nominal_shard_id: u32,
) -> Result<Vec<u8>, JsValue> {
    let mut query: SeededClientQuery = decode(query_bytes, "fanout_seeded_client_query")?;
    query.shard_id = nominal_shard_id;
    Ok(encode(&query, "fanout_seeded_client_query")?)
}

/// Build a shuffled, CSPRNG-padded batch for a browser client.
///
/// `global_indices_bincode` is a bincode `Vec<u64>`. The returned
/// [`WasmPaddedBatchOutput`] keeps extraction state local and carries a versioned request body
/// whose exact size is at most `body_cap_bytes`.
///
/// # Errors
/// Returns a JS error for malformed inputs, empty batches, arithmetic overflow, a cap that admits
/// no dyadic padded length, unavailable OS entropy, or query construction failure.
#[wasm_bindgen]
pub fn build_padded_batch(
    session: &ClientSessionHandle,
    shard_config_bincode: &[u8],
    global_indices_bincode: &[u8],
    body_cap_bytes: u32,
) -> Result<Vec<u8>, JsValue> {
    let shard_config = decode_validated_shard_config(shard_config_bincode, &session.params)?;
    let global_indices: Vec<u64> = decode(global_indices_bincode, "padded_batch_global_indices")?;
    let body_cap_bytes =
        usize::try_from(body_cap_bytes).map_err(|_| PaddedBatchError::ArithmeticOverflow {
            operation: "browser body cap",
        })?;
    let batch = build_padded_batch_rust(
        &session.inner,
        &session.params,
        &shard_config,
        &global_indices,
        body_cap_bytes,
    )?;
    let client_states_bincode = batch
        .client_states
        .iter()
        .map(|state| encode(state, "padded_batch_client_state"))
        .collect::<Result<Vec<_>, _>>()?;
    let response_slots = batch
        .response_slots
        .iter()
        .map(|slot| {
            u32::try_from(*slot).map_err(|_| PaddedBatchError::ArithmeticOverflow {
                operation: "browser response slot",
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut query_batch_bytes = SESSION_WIRE_SCHEMA_VERSION.to_be_bytes().to_vec();
    query_batch_bytes.extend_from_slice(&encode(&batch.queries, "padded_batch_queries")?);
    if query_batch_bytes.len() != batch.request_bytes {
        return Err(WasmClientError::Encode {
            what: "padded_batch_queries",
            detail: format!(
                "encoded request is {} bytes but measured sizing produced {} bytes",
                query_batch_bytes.len(),
                batch.request_bytes
            ),
        }
        .into());
    }
    let output = WasmPaddedBatchOutput {
        client_states_bincode,
        query_batch_bytes,
        response_slots,
    };
    Ok(encode(&output, "wasm_padded_batch_output")?)
}

/// Decode a server response to plaintext row bytes, dispatching on the server's
/// declared packing mode.
///
/// `client_state_bincode` is the [`build_seeded_query`] output. Its
/// `rlwe_secret_key` is `#[serde(skip)]`, so it arrives default-built (empty
/// `moduli`) and must be rehydrated from `session` before extraction; otherwise
/// `Poly::mul_ntt` panics with `Moduli must match`.
#[wasm_bindgen]
pub fn extract_response(
    session: &ClientSessionHandle,
    crs_bincode: &[u8],
    client_state_bincode: &[u8],
    response_bytes: &[u8],
    entry_size: u32,
) -> Result<Vec<u8>, JsValue> {
    let crs = decode_versioned_crs(crs_bincode)?;
    let mut client_state: ClientState = decode(client_state_bincode, "client_state")?;
    // rehydrate serde-skipped key; extraction reads only rlwe_secret_key
    client_state.rlwe_secret_key = session.inner.rlwe_secret_key().clone();
    let response: ServerResponse = decode(response_bytes, "server_response")?;
    let entry_size = entry_size_against_session(entry_size as usize, session)?;
    let plaintext =
        extract_two_packing(&crs, &client_state, &response, entry_size).map_err(|e| {
            WasmClientError::Inspire {
                op: "extract_two_packing",
                detail: e.to_string(),
            }
        })?;
    Ok(plaintext)
}

/// Reject an `entry_size` the session's ring cannot have encoded.
///
/// The caller supplies this across the JS boundary while the session holds the
/// authoritative ring, so an off-law width would otherwise decode a well-formed
/// record of the wrong length and return it as success.
fn checked_entry_size(entry_size: usize, ring_dim: usize) -> Result<usize, WasmClientError> {
    if entry_size == 0
        || !PackParams::is_legal_width(ring_dim, raven_inspire::num_columns(entry_size))
    {
        return Err(WasmClientError::Decode {
            what: "entry_size",
            detail: format!(
                "entry_size {entry_size} is not a legal cell width at ring_dim {ring_dim}: \
                 ceil(entry_size/2) must be a non-zero power of two no larger than {}",
                ring_dim / 2
            ),
        });
    }
    Ok(entry_size)
}

/// Pin a caller-supplied width to the server's declared one.
///
/// The width law alone admits a *smaller* legal width, which decodes a prefix of
/// the record and returns it as success, so the declared size is the authority.
fn pin_entry_size(
    entry_size: usize,
    ring_dim: usize,
    declared: usize,
) -> Result<usize, WasmClientError> {
    let entry_size = checked_entry_size(entry_size, ring_dim)?;
    if entry_size != declared {
        return Err(WasmClientError::Decode {
            what: "entry_size",
            detail: format!(
                "entry_size {entry_size} disagrees with the server-declared record size \
                 {declared}; extraction would return a truncated or over-read record"
            ),
        });
    }
    Ok(entry_size)
}

fn entry_size_against_session(
    entry_size: usize,
    session: &ClientSessionHandle,
) -> Result<usize, WasmClientError> {
    pin_entry_size(
        entry_size,
        session.params.ring_dim,
        session.shard_config.entry_size_bytes,
    )
}

#[cfg(test)]
mod entry_size_tests {
    use super::pin_entry_size;

    const RING_DIM: usize = 2048;
    const DECLARED: usize = 512;

    #[test]
    fn the_declared_width_is_accepted() {
        assert_eq!(
            pin_entry_size(DECLARED, RING_DIM, DECLARED).expect("declared width"),
            DECLARED
        );
    }

    /// The case the cell-width law alone cannot catch: 256 is a legal width, so
    /// only the declared size refuses it.
    #[test]
    fn a_deflated_but_legal_width_is_refused() {
        let err = pin_entry_size(256, RING_DIM, DECLARED)
            .expect_err("a legal-but-wrong width must be refused");
        assert!(
            err.to_string().contains("server-declared record size"),
            "got: {err}"
        );
    }

    #[test]
    fn an_inflated_width_and_zero_are_refused() {
        pin_entry_size(1024, RING_DIM, DECLARED).expect_err("inflated width");
        pin_entry_size(0, RING_DIM, DECLARED).expect_err("zero width");
        pin_entry_size(328, RING_DIM, DECLARED).expect_err("off-law width");
    }

    #[test]
    fn an_odd_width_rounds_up_before_legality_is_checked() {
        pin_entry_size(5, RING_DIM, 5).expect_err("five bytes induce three columns");
    }
}

/// Serialize a [`ClientSessionHandle`] to a persistable warm-cache blob.
///
/// Encodes the session residue (~1.25 MiB) - not the >160 MiB automorph tables,
/// which a rehydrated session never needs - so a warm-cache load skips the
/// one-time O(d^3) packing-key generation [`build_client_session`] pays.
///
/// # Security
///
/// The blob holds the client RLWE secret key. Persisting it is opt-in and places
/// a secret at rest: a stolen blob plus observed traffic deanonymizes this
/// client's query indices (not funds). Storage is not encrypted at rest; persist
/// only with the user's informed consent.
#[wasm_bindgen]
pub fn serialize_client_session(session: &ClientSessionHandle) -> Result<Vec<u8>, JsValue> {
    Ok(encode(
        &session.inner.to_residue(),
        "client_session_residue",
    )?)
}

/// Reconstitute a [`ClientSessionHandle`] from a [`serialize_client_session`] blob.
///
/// Decodes the session residue under [`WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES`]
/// and rehydrates without rebuilding the automorph tables. The residue's CRS is
/// checked against both the current parameters and current CRS so a rotation
/// surfaces as a typed error, not a silently wrong query.
#[wasm_bindgen]
pub fn deserialize_client_session(
    params_bundle_bincode: &[u8],
    crs_bincode: &[u8],
    session_bincode: &[u8],
) -> Result<ClientSessionHandle, JsValue> {
    let bundle: WasmInstanceParamsBundle = decode(params_bundle_bincode, "params_bundle")?;
    let inspire_params = decode_validated_params(&bundle.inspire_params_bincode, "inspire_params")?;
    ServerCrs::check_magic(crs_bincode).map_err(|e| WasmClientError::Decode {
        what: "server_crs",
        detail: e.to_string(),
    })?;
    let residue: SessionResidue = decode_trusted(session_bincode, "client_session")?;
    let inner = ClientSession::from_residue(residue).map_err(|e| WasmClientError::Inspire {
        op: "ClientSession::from_residue",
        detail: e.to_string(),
    })?;
    ensure_session_params_match(&inner.crs().params, &inspire_params).map_err(|detail| {
        WasmClientError::Decode {
            what: "client_session",
            detail,
        }
    })?;
    ensure_session_matches_live_crs(&inner, crs_bincode).map_err(|detail| {
        WasmClientError::Decode {
            what: "client_session",
            detail,
        }
    })?;
    let shard_config =
        decode_validated_shard_config(&bundle.shard_config_bincode, &inspire_params)?;
    let registration_body = session_registration_body(&inner, &shard_config, &inspire_params)?;
    Ok(ClientSessionHandle {
        inner,
        params: inspire_params,
        shard_config,
        registration_body,
    })
}

/// Generate a fresh RLWE secret key and return the params-bundle bincode blob
/// the SDK passes to [`build_client_session`].
#[wasm_bindgen]
pub fn build_instance_params_blob(
    inspire_params_bincode: &[u8],
    shard_config_bincode: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let inspire_params = decode_validated_params(inspire_params_bincode, "inspire_params")?;
    let shard_config: ShardConfig = decode(shard_config_bincode, "shard_config")?;
    shard_config
        .validate_for_params(&inspire_params)
        .map_err(|detail| WasmClientError::Decode {
            what: "shard_config",
            detail: format!("shard geometry does not match the params ring: {detail}"),
        })?;
    // the key is derived entirely from this sampler: one seed here is one key for every client
    let mut sampler = os_seeded_sampler(inspire_params.sigma, "rlwe_secret_key")?;
    let secret_key = RlweSecretKey::generate(&inspire_params, &mut sampler);
    let secret_key_bincode = encode(&secret_key, "rlwe_secret_key")?;
    let bundle = WasmInstanceParamsBundle {
        inspire_params_bincode: inspire_params_bincode.to_vec(),
        shard_config_bincode: shard_config_bincode.to_vec(),
        rlwe_secret_key_bincode: secret_key_bincode,
    };
    Ok(encode(&bundle, "wasm_instance_params_bundle")?)
}

/// Test-only mirror of the crate-private [`decode`]; surfaces its error as `String`.
#[doc(hidden)]
pub fn decode_capped_for_test<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    what: &'static str,
) -> Result<T, String> {
    decode::<T>(bytes, what).map_err(|e| e.to_string())
}

/// Test-only mirror of the crate-private [`decode_trusted`]; surfaces its error as `String`.
#[doc(hidden)]
pub fn decode_trusted_for_test<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    what: &'static str,
) -> Result<T, String> {
    decode_trusted::<T>(bytes, what).map_err(|e| e.to_string())
}

/// Pure-Rust mirror of [`serialize_client_session`].
#[doc(hidden)]
pub fn serialize_client_session_rust(session: &ClientSession) -> Result<Vec<u8>, String> {
    bincode::serialize(&session.to_residue()).map_err(|e| e.to_string())
}

/// Pure-Rust mirror of [`deserialize_client_session`].
#[doc(hidden)]
pub fn deserialize_client_session_rust(
    params_bundle_bincode: &[u8],
    crs_bincode: &[u8],
    session_bincode: &[u8],
) -> Result<(ClientSession, InspireParams), String> {
    // same validation order as the wasm entry point: bundle, params, CRS magic,
    // then the trusted cap + residue decode
    let bundle: WasmInstanceParamsBundle =
        bincode::deserialize(params_bundle_bincode).map_err(|e| e.to_string())?;
    let inspire_params: InspireParams =
        bincode::deserialize(&bundle.inspire_params_bincode).map_err(|e| e.to_string())?;
    ServerCrs::check_magic(crs_bincode).map_err(|e| e.to_string())?;
    if session_bincode.len() > WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES {
        return Err(format!(
            "size limit reached: payload {} bytes exceeds cap {}",
            session_bincode.len(),
            WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES
        ));
    }
    let residue: SessionResidue =
        bincode::deserialize(session_bincode).map_err(|e| e.to_string())?;
    let inner = ClientSession::from_residue(residue).map_err(|e| e.to_string())?;
    ensure_session_params_match(&inner.crs().params, &inspire_params)?;
    ensure_session_matches_live_crs(&inner, crs_bincode)?;
    Ok((inner, inspire_params))
}

/// Rust-native mirror of [`build_seeded_query`]. Draws query noise from OS entropy,
/// so the mirror is never weaker than the wasm path it stands in for.
pub fn build_seeded_query_rust(
    session: &ClientSession,
    params: &InspireParams,
    shard_config: &ShardConfig,
    target_idx: u64,
) -> Result<(ClientState, SeededClientQuery), String> {
    let mut sampler =
        os_seeded_sampler(params.sigma, "seeded_query_noise").map_err(|e| e.to_string())?;
    seeded_query_with_sampler(session, shard_config, target_idx, &mut sampler)
}

/// [`build_seeded_query_rust`] with the Gaussian noise seed pinned by the caller.
///
/// Test seam only: two calls under one seed emit byte-identical noise, which is what
/// makes a native-vs-wasm byte comparison possible at all. Callers on a real query
/// path MUST NOT pin a seed - a reused seed hands the server the query index.
#[doc(hidden)]
pub fn build_seeded_query_rust_with_noise_seed(
    session: &ClientSession,
    params: &InspireParams,
    shard_config: &ShardConfig,
    target_idx: u64,
    noise_seed: [u8; 32],
) -> Result<(ClientState, SeededClientQuery), String> {
    let mut sampler = GaussianSampler::from_seed(params.sigma, noise_seed);
    seeded_query_with_sampler(session, shard_config, target_idx, &mut sampler)
}

fn seeded_query_with_sampler(
    session: &ClientSession,
    shard_config: &ShardConfig,
    target_idx: u64,
    sampler: &mut GaussianSampler,
) -> Result<(ClientState, SeededClientQuery), String> {
    let (state, query) = session
        .query_seeded(target_idx, shard_config, sampler)
        .map_err(|e| e.to_string())?;
    Ok((state, query))
}

struct BatchSlot {
    target_idx: u64,
    query: SeededClientQuery,
    real: Option<(usize, ClientState)>,
}

const RANDOM_DRAW_ATTEMPTS: usize = 64;

fn uniform_below(rng: &mut impl RngCore, upper_bound: usize) -> Result<usize, PaddedBatchError> {
    let bound = u64::try_from(upper_bound).map_err(|_| PaddedBatchError::ArithmeticOverflow {
        operation: "random draw upper bound",
    })?;
    if bound == 0 {
        return Err(PaddedBatchError::RandomDrawExhausted {
            upper_bound,
            attempts: 0,
        });
    }
    let limit = u64::MAX - (u64::MAX % bound);
    for _ in 0..RANDOM_DRAW_ATTEMPTS {
        let draw = rng.next_u64();
        if draw < limit {
            return usize::try_from(draw % bound).map_err(|_| {
                PaddedBatchError::ArithmeticOverflow {
                    operation: "random draw index",
                }
            });
        }
    }
    Err(PaddedBatchError::RandomDrawExhausted {
        upper_bound,
        attempts: RANDOM_DRAW_ATTEMPTS,
    })
}

fn build_batch_slot(
    session: &ClientSession,
    shard_config: &ShardConfig,
    target_idx: u64,
    slot: usize,
    sampler: &mut GaussianSampler,
) -> Result<(ClientState, SeededClientQuery, usize), PaddedBatchError> {
    let (state, query) = seeded_query_with_sampler(session, shard_config, target_idx, sampler)
        .map_err(|detail| PaddedBatchError::Query {
            slot,
            target_idx,
            detail,
        })?;
    let serialized_query_bytes = bincode::serialize(&query)
        .map_err(|error| PaddedBatchError::Encode {
            what: "seeded_client_query",
            detail: error.to_string(),
        })?
        .len();
    Ok((state, query, serialized_query_bytes))
}

struct CheckedBatchQueryBuilder<'a> {
    session: &'a ClientSession,
    shard_config: &'a ShardConfig,
    sampler: &'a mut GaussianSampler,
    serialized_query_bytes: usize,
}

impl CheckedBatchQueryBuilder<'_> {
    fn build(
        &mut self,
        target_idx: u64,
        slot: usize,
    ) -> Result<(ClientState, SeededClientQuery), PaddedBatchError> {
        let (state, query, actual) = build_batch_slot(
            self.session,
            self.shard_config,
            target_idx,
            slot,
            self.sampler,
        )?;
        if actual != self.serialized_query_bytes {
            return Err(PaddedBatchError::QuerySizeMismatch {
                slot,
                expected: self.serialized_query_bytes,
                actual,
            });
        }
        Ok((state, query))
    }
}

fn build_remaining_batch_slots(
    mut slots: Vec<BatchSlot>,
    builder: &mut CheckedBatchQueryBuilder<'_>,
    global_indices: &[u64],
    cover_targets: &[u64],
) -> Result<Vec<BatchSlot>, PaddedBatchError> {
    for (caller_index, target_idx) in global_indices.iter().copied().enumerate().skip(1) {
        let (state, query) = builder.build(target_idx, caller_index)?;
        slots.push(BatchSlot {
            target_idx,
            query,
            real: Some((caller_index, state)),
        });
    }
    for target_idx in cover_targets.iter().copied() {
        let slot = slots.len();
        let (_state, query) = builder.build(target_idx, slot)?;
        slots.push(BatchSlot {
            target_idx,
            query,
            real: None,
        });
    }
    Ok(slots)
}

fn draw_distinct_cover_targets(
    shard_config: &ShardConfig,
    global_indices: &[u64],
    cover_count: usize,
    layout_rng: &mut impl RngCore,
) -> Result<Vec<u64>, PaddedBatchError> {
    let mut occupied_shards = Vec::with_capacity(global_indices.len() + cover_count);
    for (caller_slot, target_idx) in global_indices.iter().copied().enumerate() {
        if target_idx >= shard_config.total_entries {
            return Err(PaddedBatchError::Configuration {
                detail: format!(
                    "real target {target_idx} at caller slot {caller_slot} is outside total_entries {}",
                    shard_config.total_entries
                ),
            });
        }
        let (shard_id, _) = shard_config
            .try_index_to_shard(target_idx)
            .map_err(|detail| PaddedBatchError::Configuration {
                detail: format!("real target {target_idx} has invalid shard geometry: {detail}"),
            })?;
        let shard_id =
            usize::try_from(shard_id).map_err(|_| PaddedBatchError::ArithmeticOverflow {
                operation: "real shard id",
            })?;
        if let Err(insert_at) = occupied_shards.binary_search(&shard_id) {
            occupied_shards.insert(insert_at, shard_id);
        }
    }

    let num_shards = usize::try_from(shard_config.num_shards()).map_err(|_| {
        PaddedBatchError::ArithmeticOverflow {
            operation: "validated shard count",
        }
    })?;
    let available_covers = num_shards.checked_sub(occupied_shards.len()).ok_or_else(|| {
        PaddedBatchError::Configuration {
            detail: format!(
                "validated geometry has {num_shards} shards but real targets occupy {} distinct shards",
                occupied_shards.len()
            ),
        }
    })?;
    if cover_count > available_covers {
        return Err(PaddedBatchError::Configuration {
            detail: format!(
                "padded batch requires {cover_count} distinct cover shards outside {} real shards, but validated geometry has only {available_covers} available",
                occupied_shards.len()
            ),
        });
    }

    let mut cover_targets = Vec::with_capacity(cover_count);
    for _ in 0..cover_count {
        let rank = uniform_below(layout_rng, num_shards - occupied_shards.len())?;
        let mut shard_id = rank;
        for occupied in occupied_shards.iter().copied() {
            if occupied > shard_id {
                break;
            }
            shard_id = shard_id
                .checked_add(1)
                .ok_or(PaddedBatchError::ArithmeticOverflow {
                    operation: "cover shard rank",
                })?;
        }
        let Err(insert_at) = occupied_shards.binary_search(&shard_id) else {
            return Err(PaddedBatchError::Configuration {
                detail: format!("cover shard selection repeated occupied shard {shard_id}"),
            });
        };
        occupied_shards.insert(insert_at, shard_id);
        let shard_id =
            u32::try_from(shard_id).map_err(|_| PaddedBatchError::ArithmeticOverflow {
                operation: "cover shard id",
            })?;
        cover_targets.push(shard_config.shard_to_index(shard_id, 0));
    }
    Ok(cover_targets)
}

fn finish_padded_batch(
    slots: Vec<BatchSlot>,
    real_count: usize,
    serialized_query_bytes: usize,
    request_bytes: usize,
) -> Result<PaddedBatch, PaddedBatchError> {
    let padded_len = slots.len();
    let mut caller_states: Vec<Option<ClientState>> = (0..real_count).map(|_| None).collect();
    let mut response_slots = vec![0usize; real_count];
    let mut queries = Vec::with_capacity(padded_len);
    let mut wire_targets = Vec::with_capacity(padded_len);
    for (wire_slot, slot) in slots.into_iter().enumerate() {
        if let Some((caller_index, state)) = slot.real {
            let state_cell =
                caller_states
                    .get_mut(caller_index)
                    .ok_or(PaddedBatchError::ImpossiblePadding {
                        real_count,
                        max_slots: padded_len,
                    })?;
            *state_cell = Some(state);
            let response_slot = response_slots.get_mut(caller_index).ok_or(
                PaddedBatchError::ImpossiblePadding {
                    real_count,
                    max_slots: padded_len,
                },
            )?;
            *response_slot = wire_slot;
        }
        wire_targets.push(slot.target_idx);
        queries.push(slot.query);
    }
    let client_states = caller_states
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(PaddedBatchError::ImpossiblePadding {
            real_count,
            max_slots: padded_len,
        })?;

    Ok(PaddedBatch {
        client_states,
        queries,
        response_slots,
        serialized_query_bytes,
        request_bytes,
        wire_targets,
    })
}

fn build_padded_batch_with_randomness(
    session: &ClientSession,
    shard_config: &ShardConfig,
    global_indices: &[u64],
    body_cap_bytes: usize,
    layout_rng: &mut impl RngCore,
    query_sampler: &mut GaussianSampler,
) -> Result<PaddedBatch, PaddedBatchError> {
    let Some(&first_target) = global_indices.first() else {
        return Err(PaddedBatchError::EmptyBatch);
    };
    let (first_state, first_query, serialized_query_bytes) =
        build_batch_slot(session, shard_config, first_target, 0, query_sampler)?;
    let ladder = padded_batch_ladder(serialized_query_bytes, body_cap_bytes)?;
    let max_slots = (body_cap_bytes - VERSIONED_BATCH_FRAME_BYTES) / serialized_query_bytes;
    let padded_len = ladder
        .iter()
        .copied()
        .find(|step| *step >= global_indices.len())
        .ok_or(PaddedBatchError::ImpossiblePadding {
            real_count: global_indices.len(),
            max_slots,
        })?;

    let request_bytes = padded_len
        .checked_mul(serialized_query_bytes)
        .and_then(|query_bytes| VERSIONED_BATCH_FRAME_BYTES.checked_add(query_bytes))
        .ok_or(PaddedBatchError::ArithmeticOverflow {
            operation: "padded request bytes",
        })?;
    if request_bytes > body_cap_bytes {
        return Err(PaddedBatchError::ImpossiblePadding {
            real_count: global_indices.len(),
            max_slots,
        });
    }
    let cover_count = padded_len - global_indices.len();
    let cover_targets =
        draw_distinct_cover_targets(shard_config, global_indices, cover_count, layout_rng)?;

    let slots = vec![BatchSlot {
        target_idx: first_target,
        query: first_query,
        real: Some((0, first_state)),
    }];
    let mut builder = CheckedBatchQueryBuilder {
        session,
        shard_config,
        sampler: query_sampler,
        serialized_query_bytes,
    };
    let mut slots =
        build_remaining_batch_slots(slots, &mut builder, global_indices, &cover_targets)?;

    for remaining in (2..=slots.len()).rev() {
        let swap_with = uniform_below(layout_rng, remaining)?;
        slots.swap(remaining - 1, swap_with);
    }
    finish_padded_batch(
        slots,
        global_indices.len(),
        serialized_query_bytes,
        request_bytes,
    )
}

/// Build a CSPRNG-padded batch for native Rust callers.
///
/// Real queries are returned in shuffled wire order. `response_slots` maps each caller-order
/// `client_states` entry back to its response. The dyadic ceiling is derived from the first query's
/// measured serialized size and `body_cap_bytes`.
///
/// ```
/// use raven_client::build_padded_batch_rust;
/// use raven_inspire::math::GaussianSampler;
/// use raven_inspire::params::{InspireParams, SecurityLevel};
/// use raven_inspire::{setup, ClientSession};
///
/// let params = InspireParams {
///     ring_dim: 256,
///     q: 1_152_921_504_606_830_593,
///     crt_moduli: vec![1_152_921_504_606_830_593],
///     p: 65_537,
///     sigma: 6.4,
///     gadget_base: 1 << 20,
///     query_gadget_len: 3,
///     packing_gadget_len: 3,
///     security_level: SecurityLevel::Bits128,
/// };
/// let database = vec![0u8; params.ring_dim * 32];
/// let mut setup_sampler = GaussianSampler::with_seed(params.sigma, 7);
/// let (crs, encoded, secret_key) =
///     setup(&params, &database, 32, &mut setup_sampler)?;
/// let mut session_sampler = GaussianSampler::with_seed(params.sigma, 9);
/// let session = ClientSession::new(crs, secret_key, &mut session_sampler)?;
/// let batch = build_padded_batch_rust(
///     &session,
///     &params,
///     &encoded.config,
///     &[3, 11],
///     1_000_000,
/// )?;
/// assert_eq!(batch.client_states.len(), 2);
/// assert_eq!(batch.queries.len(), 2);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
/// Returns [`PaddedBatchError`] when the input is empty, sizing overflows, the cap admits no legal
/// ladder step, the validated geometry cannot supply distinct cover shards, entropy is unavailable,
/// or InsPIRe cannot construct a query.
pub fn build_padded_batch_rust(
    session: &ClientSession,
    params: &InspireParams,
    shard_config: &ShardConfig,
    global_indices: &[u64],
    body_cap_bytes: usize,
) -> Result<PaddedBatch, PaddedBatchError> {
    validate_padded_batch_inputs(session, params, shard_config, global_indices)?;
    let mut layout_rng = raven_inspire::math::gaussian::os_seeded_chacha("padded_batch_layout")
        .map_err(|error| PaddedBatchError::Entropy {
            detail: error.to_string(),
        })?;
    let mut query_sampler =
        os_seeded_sampler(params.sigma, "padded_batch_query_noise").map_err(|error| {
            PaddedBatchError::Entropy {
                detail: error.to_string(),
            }
        })?;
    build_padded_batch_with_randomness(
        session,
        shard_config,
        global_indices,
        body_cap_bytes,
        &mut layout_rng,
        &mut query_sampler,
    )
}

/// Deterministic test seam for [`build_padded_batch_rust`].
///
/// This function is not a production entry point. Reusing either stream reveals query relations.
#[doc(hidden)]
pub fn build_padded_batch_rust_with_test_rng(
    session: &ClientSession,
    params: &InspireParams,
    shard_config: &ShardConfig,
    global_indices: &[u64],
    body_cap_bytes: usize,
    layout_rng: &mut impl RngCore,
    noise_seed: [u8; 32],
) -> Result<PaddedBatch, PaddedBatchError> {
    validate_padded_batch_inputs(session, params, shard_config, global_indices)?;
    let mut query_sampler = GaussianSampler::from_seed(params.sigma, noise_seed);
    build_padded_batch_with_randomness(
        session,
        shard_config,
        global_indices,
        body_cap_bytes,
        layout_rng,
        &mut query_sampler,
    )
}

fn validate_padded_batch_inputs(
    session: &ClientSession,
    params: &InspireParams,
    shard_config: &ShardConfig,
    global_indices: &[u64],
) -> Result<(), PaddedBatchError> {
    if global_indices.is_empty() {
        return Err(PaddedBatchError::EmptyBatch);
    }
    params
        .validate()
        .map_err(|detail| PaddedBatchError::Configuration {
            detail: detail.to_owned(),
        })?;
    ensure_session_params_match(&session.crs().params, params)
        .map_err(|detail| PaddedBatchError::Configuration { detail })?;
    shard_config
        .validate_for_params(params)
        .map_err(|detail| PaddedBatchError::Configuration {
            detail: detail.to_owned(),
        })?;
    Ok(())
}

/// Rust-native mirror of [`extract_response`].
pub fn extract_response_rust(
    crs: &ServerCrs,
    client_state: &ClientState,
    response: &ServerResponse,
    entry_size: usize,
) -> Result<Vec<u8>, String> {
    let entry_size = checked_entry_size(entry_size, crs.ring_dim()).map_err(|e| e.to_string())?;
    extract_two_packing(crs, client_state, response, entry_size).map_err(|e| e.to_string())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use proptest::{prop_assert, prop_assert_eq, proptest};

    struct ZeroRng;

    impl rand::RngCore for ZeroRng {
        fn next_u32(&mut self) -> u32 {
            0
        }

        fn next_u64(&mut self) -> u64 {
            0
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    proptest! {
        #[test]
        fn distinct_cover_draws_fill_the_real_shard_complement(
            real_count in 1usize..32,
            cover_count in 0usize..32,
            spare_shards in 0usize..32,
        ) {
            let num_shards = real_count + cover_count + spare_shards;
            let total_entries = u64::try_from(num_shards * 256).expect("bounded shard count");
            let shard_config = ShardConfig::for_ring_dim(256, 32, total_entries)
                .expect("valid generated geometry");
            let global_indices = (0..real_count)
                .map(|shard_id| u64::try_from(shard_id * 256 + shard_id).expect("bounded target"))
                .collect::<Vec<_>>();

            let cover_targets = draw_distinct_cover_targets(
                &shard_config,
                &global_indices,
                cover_count,
                &mut ZeroRng,
            ).expect("generated geometry has enough covers");
            let real_shards = global_indices.iter().map(|target_idx| {
                shard_config.try_index_to_shard(*target_idx).expect("valid target").0
            }).collect::<std::collections::BTreeSet<_>>();
            let cover_shards = cover_targets.iter().map(|target_idx| {
                shard_config.try_index_to_shard(*target_idx).expect("valid cover").0
            }).collect::<std::collections::BTreeSet<_>>();

            prop_assert_eq!(cover_targets.len(), cover_count);
            prop_assert_eq!(cover_shards.len(), cover_count);
            prop_assert!(cover_shards.is_disjoint(&real_shards));
            prop_assert!(cover_targets.iter().all(|target_idx| *target_idx < total_entries));
        }
    }
}
