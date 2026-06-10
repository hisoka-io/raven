//! Wasm-compatible PIR client surface for Raven: query construction and response
//! extraction across the JS/Wasm boundary.
//!
//! This surface is InsPIRe-typed (`InspireParams`/`ShardConfig`; forces
//! `PackingMode::Inspiring` to match the server's packing configuration). All
//! complex Rust types cross the JS boundary as bincode-encoded `Vec<u8>`. See
//! `tests/parity_native_vs_wasm.rs` for byte-equality tests against a native
//! Rust client.

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]
#![deny(missing_docs)]

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, ShardConfig};
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::{
    extract_inspiring, ClientSession, ClientState, PackingMode, SeededClientQuery, ServerCrs,
    ServerResponse, SessionResidue,
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
}

impl From<WasmClientError> for JsValue {
    fn from(value: WasmClientError) -> Self {
        JsValue::from_str(&value.to_string())
    }
}

/// Allocation cap for untrusted bincode crossing the JS->Wasm boundary (64 MiB).
///
/// Enforced as a slice-length pre-check, not `bincode::Options::with_limit`:
/// bincode 1.3.3's slice path (`src/internal.rs:114` `deserialize_seed`) overrides
/// any configured limit to `Infinite`, so `with_limit` is a no-op for
/// `bincode::deserialize(bytes)`.
pub const WASM_BINCODE_DESERIALIZE_LIMIT_BYTES: usize = 64 * 1024 * 1024;

/// Allocation cap for a self-authored session-residue blob from
/// [`serialize_client_session`] (32 MiB).
///
/// The residue (CRS + secret key + packing-key body, no automorph tables) is
/// ~1.25 MiB at d=2048 and ~2.5 MiB at d=4096; 32 MiB is ~10x the largest-ring
/// residue, so a malformed cached blob is rejected by the cheap length check
/// before a large contiguous allocation is attempted in a 32-bit wasm heap.
pub const WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES: usize = 32 * 1024 * 1024;

fn decode<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    what: &'static str,
) -> Result<T, WasmClientError> {
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
    bincode::deserialize::<T>(bytes).map_err(|e| WasmClientError::Decode {
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

/// Decode an HTTP-sourced CRS blob: enforce the untrusted cap, then validate the
/// [`ServerCrs::MAGIC`] version prefix so a layout mismatch is a typed error, not a
/// silent bincode mis-parse.
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

/// Opaque handle to an active [`ClientSession`]. Constructed via [`build_client_session`].
#[wasm_bindgen]
pub struct ClientSessionHandle {
    inner: ClientSession,
    params: InspireParams,
}

impl std::fmt::Debug for ClientSessionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSessionHandle")
            .field("ring_dim", &self.params.ring_dim)
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
    let inspire_params: InspireParams = decode(&bundle.inspire_params_bincode, "inspire_params")?;
    let secret_key: RlweSecretKey = decode(&bundle.rlwe_secret_key_bincode, "rlwe_secret_key")?;
    let crs = decode_versioned_crs(crs_bincode)?;
    let mut sampler = GaussianSampler::new(inspire_params.sigma);
    let session = ClientSession::new(crs, secret_key, &mut sampler).map_err(|e| {
        WasmClientError::Inspire {
            op: "ClientSession::new",
            detail: e.to_string(),
        }
    })?;
    Ok(ClientSessionHandle {
        inner: session,
        params: inspire_params,
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
    let inspire_params: InspireParams = decode(&bundle.inspire_params_bincode, "inspire_params")?;
    if inspire_params.ring_dim != session.params.ring_dim
        || inspire_params.q != session.params.q
        || inspire_params.p != session.params.p
    {
        return Err(JsValue::from_str(
            "register_client_session: instance params drift detected (ring_dim/q/p mismatch with session)",
        ));
    }
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

/// Build a seeded PIR query for `target_idx`. Forces `PackingMode::Inspiring`
/// to match the server's packing configuration.
#[wasm_bindgen]
pub fn build_seeded_query(
    session: &ClientSessionHandle,
    shard_config_bincode: &[u8],
    target_idx: u64,
) -> Result<Vec<u8>, JsValue> {
    let shard_config: ShardConfig = decode(shard_config_bincode, "shard_config")?;
    let mut sampler = GaussianSampler::new(session.params.sigma);
    let (client_state, mut query) = session
        .inner
        .query_seeded(target_idx, &shard_config, &mut sampler)
        .map_err(|e| WasmClientError::Inspire {
            op: "ClientSession::query_seeded",
            detail: e.to_string(),
        })?;
    query.packing_mode = PackingMode::Inspiring;
    let client_state_bincode = encode(&client_state, "client_state")?;
    let query_bytes = encode(&query, "seeded_client_query")?;
    let bundle = WasmSeededQueryOutput {
        client_state_bincode,
        query_bytes,
    };
    Ok(encode(&bundle, "wasm_seeded_query_output")?)
}

/// Decode a server response to plaintext row bytes via [`extract_inspiring`].
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
    // rehydrate serde-skipped key; extract_inspiring reads only rlwe_secret_key
    client_state.rlwe_secret_key = session.inner.rlwe_secret_key().clone();
    let response: ServerResponse = decode(response_bytes, "server_response")?;
    let plaintext = extract_inspiring(&crs, &client_state, &response, entry_size as usize)
        .map_err(|e| WasmClientError::Inspire {
            op: "extract_inspiring",
            detail: e.to_string(),
        })?;
    Ok(plaintext)
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
/// and rehydrates without rebuilding the automorph tables. `crs_bincode` is
/// validated only for its [`ServerCrs::MAGIC`] version prefix (cheap, no full
/// decode); the residue carries the authoritative CRS that serves queries. The
/// rehydrated CRS ring_dim is checked against the params bundle so a CRS rotation
/// surfaces as a typed error, not a silently wrong query.
#[wasm_bindgen]
pub fn deserialize_client_session(
    params_bundle_bincode: &[u8],
    crs_bincode: &[u8],
    session_bincode: &[u8],
) -> Result<ClientSessionHandle, JsValue> {
    let bundle: WasmInstanceParamsBundle = decode(params_bundle_bincode, "params_bundle")?;
    let inspire_params: InspireParams = decode(&bundle.inspire_params_bincode, "inspire_params")?;
    ServerCrs::check_magic(crs_bincode).map_err(|e| WasmClientError::Decode {
        what: "server_crs",
        detail: e.to_string(),
    })?;
    let residue: SessionResidue = decode_trusted(session_bincode, "client_session")?;
    let inner = ClientSession::from_residue(residue).map_err(|e| WasmClientError::Inspire {
        op: "ClientSession::from_residue",
        detail: e.to_string(),
    })?;
    // the residue CRS (not the bundle) drives all query crypto; ring_dim is the only
    // load-bearing match (q/p drift in the bundle is inert), and from_residue already
    // proved the residue's own crs/key ring_dim+modulus agree
    if inner.crs().ring_dim() != inspire_params.ring_dim {
        return Err(WasmClientError::Decode {
            what: "client_session",
            detail: format!(
                "deserialize_client_session: residue CRS ring_dim {} does not match params-bundle InspireParams ring_dim {}",
                inner.crs().ring_dim(),
                inspire_params.ring_dim
            ),
        }
        .into());
    }
    Ok(ClientSessionHandle {
        inner,
        params: inspire_params,
    })
}

/// Generate a fresh RLWE secret key and return the params-bundle bincode blob
/// the SDK passes to [`build_client_session`].
#[wasm_bindgen]
pub fn build_instance_params_blob(
    inspire_params_bincode: &[u8],
    shard_config_bincode: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let inspire_params: InspireParams = decode(inspire_params_bincode, "inspire_params")?;
    // decode-check catches caller params/shard drift at session bind
    let _shard_config: ShardConfig = decode(shard_config_bincode, "shard_config")?;
    let mut sampler = GaussianSampler::new(inspire_params.sigma);
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
    if inner.crs().ring_dim() != inspire_params.ring_dim {
        return Err(format!(
            "deserialize_client_session: residue CRS ring_dim {} does not match params-bundle InspireParams ring_dim {}",
            inner.crs().ring_dim(),
            inspire_params.ring_dim
        ));
    }
    Ok((inner, inspire_params))
}

/// Rust-native mirror of [`build_seeded_query`].
pub fn build_seeded_query_rust(
    session: &ClientSession,
    params: &InspireParams,
    shard_config: &ShardConfig,
    target_idx: u64,
) -> Result<(ClientState, SeededClientQuery), String> {
    let mut sampler = GaussianSampler::new(params.sigma);
    let (state, mut query) = session
        .query_seeded(target_idx, shard_config, &mut sampler)
        .map_err(|e| e.to_string())?;
    query.packing_mode = PackingMode::Inspiring;
    Ok((state, query))
}

/// Rust-native mirror of [`extract_response`].
pub fn extract_response_rust(
    crs: &ServerCrs,
    client_state: &ClientState,
    response: &ServerResponse,
    entry_size: usize,
) -> Result<Vec<u8>, String> {
    extract_inspiring(crs, client_state, response, entry_size).map_err(|e| e.to_string())
}
