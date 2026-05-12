//! Browser/Node WASM client surface for raven-inspire's PIR query/extract path.
//! All complex Rust types cross the JS boundary as bincode-encoded `Vec<u8>`.
//!
//! See `tests/parity_native_vs_wasm.rs` for byte-equality tests against a
//! native Rust client.

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, ShardConfig};

/// Install [`console_error_panic_hook`] so Rust panics surface as structured
/// JS exceptions instead of opaque `unreachable executed` traps. Call once at
/// module load; idempotent.
#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::{
    extract_inspiring, ClientSession, ClientState, PackingMode, SeededClientQuery, ServerCrs,
    ServerResponse,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// Private wire bundle passed to/from build_instance_params_blob and build_client_session.
#[derive(Serialize, Deserialize, Debug)]
#[allow(clippy::struct_field_names)]
struct WasmInstanceParamsBundle {
    inspire_params_bincode: Vec<u8>,
    shard_config_bincode: Vec<u8>,
    rlwe_secret_key_bincode: Vec<u8>,
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

/// Maximum legitimate WASM-side bincode payload (64 MiB). Defense-in-depth
/// against a malicious server response that crosses the JS->Wasm boundary
/// with an inflated length: rejecting before `bincode::deserialize` runs
/// caps the worst-case allocation and avoids any pathological-input
/// compute path inside the deserializer. The largest legitimate payload
/// is the production-cell `ServerCrs` at ~35 MB (d=2048, p=65537,
/// total_entries=131_072 for the per-node commit-tree shape); the params
/// bundle, `SeededClientQuery`, and `ServerResponse` all fit comfortably.
///
/// Pre-check (rather than `bincode::DefaultOptions::with_limit`) because
/// bincode 1.x's slice-deserialize entry point overrides any configured
/// limit to `Infinite` (ref bincode-1.3.3 src/internal.rs:114
/// `deserialize_seed`); the configured `with_limit` is a no-op for
/// `bincode::deserialize(bytes)` and only takes effect on
/// `deserialize_from(reader)`. The slice-length pre-check is the
/// reliable enforcement mechanism on this boundary.
pub const WASM_BINCODE_DESERIALIZE_LIMIT_BYTES: usize = 64 * 1024 * 1024;

/// Trusted-source bincode deserialize ceiling for self-written
/// session blobs returned by [`serialize_client_session`].
///
/// At the locked production cell (d=2048) the bincoded `ClientSession`
/// is ~194 MB (CRS ~35 MB + precomputed packing keys ~150 MB + secrets).
/// Higher than the general [`WASM_BINCODE_DESERIALIZE_LIMIT_BYTES`] cap
/// because the blob originates from the WASM itself (via the symmetric
/// [`serialize_client_session`] write earlier in the wallet's session
/// lifetime); the threat model differs from HTTP-sourced bytes which
/// retain the 64 MiB cap.
pub const WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES: usize = 256 * 1024 * 1024;

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

/// Trusted-source variant of [`decode`] using the larger
/// [`WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES`] ceiling. Reserved for
/// self-written blobs the wallet round-trips through its own storage
/// (e.g. `serialize_client_session` -> IndexedDB ->
/// `deserialize_client_session`). MUST NOT be called from any path
/// that receives HTTP-sourced bytes; those keep the 64 MiB [`decode`]
/// defense.
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

/// Opaque handle to an active [`ClientSession`]. Constructed via [`build_client_session`].
#[wasm_bindgen]
pub struct ClientSessionHandle {
    inner: ClientSession,
    // Cached alongside the session because query_seeded needs a fresh sampler
    // each call but params are stable.
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
    let crs: ServerCrs = decode(crs_bincode, "server_crs")?;
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
    /// Encrypted PIR query payload. POST to `/v1/instance/:id/query`.
    pub query_bytes: Vec<u8>,
}

/// Build a seeded PIR query for `target_idx`. Forces `PackingMode::Inspiring`
/// to match the production server stack.
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

/// Decode a server response and return the plaintext row bytes via
/// [`extract_inspiring`].
///
/// All inputs except `session` are bincode blobs the SDK already holds:
/// - `session`: the [`ClientSessionHandle`] that emitted the matching query
/// - `crs_bincode`: from `InstanceParams::crs_bincode`
/// - `client_state_bincode`: from [`build_seeded_query`] output
/// - `response_bytes`: from the server's `POST /v1/instance/:id/query` reply
/// - `entry_size`: from `InstanceParams::entry_size`
///
/// `client_state_bincode` is the bincode emitted by [`build_seeded_query`].
/// Upstream [`raven_inspire::ClientState`] marks both `secret_key` (LWE)
/// and `rlwe_secret_key` (RLWE) with `#[serde(skip, default)]` so secret
/// material never crosses a serialization boundary by accident. The skip
/// means a bincode round-trip yields a `ClientState` whose secret keys
/// are `Default::default()` polynomials with empty `moduli` vectors;
/// passing that to `extract_inspiring` panics inside `Poly::mul_ntt`
/// (`Moduli must match`) because the ciphertext polynomial carries the
/// live single-modulus shape but the default-built secret-key polynomial
/// does not. Native parity tests do not surface this because they hold
/// the `ClientState` Rust value in process and never bincode round-trip
/// it; only the WASM boundary forces the trip. Fix: rehydrate the
/// stripped RLWE secret key from the in-WASM-memory session, which owns
/// the live key, before calling the extractor. The fix is lossless:
/// `(state.index, state.shard_id, state.local_index)` are the only
/// non-skip fields and they already round-trip cleanly.
#[wasm_bindgen]
pub fn extract_response(
    session: &ClientSessionHandle,
    crs_bincode: &[u8],
    client_state_bincode: &[u8],
    response_bytes: &[u8],
    entry_size: u32,
) -> Result<Vec<u8>, JsValue> {
    let crs: ServerCrs = decode(crs_bincode, "server_crs")?;
    let mut client_state: ClientState = decode(client_state_bincode, "client_state")?;
    // Rehydrate `#[serde(skip, default)]` `rlwe_secret_key` from the
    // in-memory session. Without this, the field is an empty default
    // `RlweSecretKey` (zero polynomial with empty `moduli` Vec) and
    // `extract_inspiring` panics in `Poly::mul_ntt` with `Moduli must
    // match`. The LWE `secret_key` field stays default;
    // `extract_inspiring` reads only `rlwe_secret_key`.
    client_state.rlwe_secret_key = session.inner.rlwe_secret_key().clone();
    let response: ServerResponse = decode(response_bytes, "server_response")?;
    let plaintext = extract_inspiring(&crs, &client_state, &response, entry_size as usize)
        .map_err(|e| WasmClientError::Inspire {
            op: "extract_inspiring",
            detail: e.to_string(),
        })?;
    Ok(plaintext)
}

/// Serialize a fully constructed [`ClientSessionHandle`] to a bincode
/// blob that can be persisted across browser tabs / page reloads /
/// process boundaries.
///
/// Pairs with [`deserialize_client_session`] to amortise the heavy
/// O(d^3) automorph-table + packing-key generation that
/// [`build_client_session`] runs (~12.6 s for the production-cell
/// d=2048 params). The SDK persists the blob to IndexedDB keyed by
/// `(instanceId, sha256(crsBincode))`; on subsequent loads it
/// reconstitutes the session via [`deserialize_client_session`] in
/// milliseconds rather than re-running the cold path.
///
/// At the locked upstream pin `119641b`, [`raven_inspire::ClientSession`]
/// does NOT derive `Serialize` / `Deserialize` / `Clone`. The SDK
/// surface is shipped now so the wallet's storage layer can encode
/// against a stable ABI, but every call surfaces a typed
/// [`WasmClientError::Encode`] until the upstream derives land
/// (tracked as the Phase 6 warm-cache deferral, option (a)). When
/// the derives ship, switch this body to
/// `Ok(encode(&session.inner, "client_session")?)` and the SDK warms
/// up transparently — no ABI change required.
#[wasm_bindgen]
pub fn serialize_client_session(session: &ClientSessionHandle) -> Result<Vec<u8>, JsValue> {
    // Suppress unused-binding lint without dropping the symbol from the ABI.
    let _ = session;
    Err(WasmClientError::Encode {
        what: "client_session",
        detail: "upstream raven_inspire::ClientSession at pin 119641b lacks \
             Clone+Serialize+Deserialize derives; warm-cache deferred per Phase 6 (a)"
            .to_string(),
    }
    .into())
}

/// Reconstitute a [`ClientSessionHandle`] from a previously serialized
/// session blob plus the same [`WasmInstanceParamsBundle`] + CRS bytes
/// [`build_client_session`] consumed.
///
/// Symmetric counterpart to [`serialize_client_session`]. Validates the
/// supplied `session_bincode` length against
/// [`WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES`] and the params-bundle's
/// `InspireParams::ring_dim` against the supplied `crs_bincode` so a
/// CRS-rotation mismatch surfaces as a typed error rather than as a
/// silently wrong query later.
///
/// At the locked upstream pin `119641b`,
/// [`raven_inspire::ClientSession`] does NOT derive `Deserialize`. As
/// with [`serialize_client_session`], the symbol is shipped now so the
/// SDK can encode against a stable ABI; calls surface a typed
/// [`WasmClientError::Decode`] until upstream lands the derives.
#[wasm_bindgen]
pub fn deserialize_client_session(
    params_bundle_bincode: &[u8],
    crs_bincode: &[u8],
    session_bincode: &[u8],
) -> Result<ClientSessionHandle, JsValue> {
    // Pre-validate inputs the way the working serde pair will once
    // upstream derives land, so wallet integration code sees the same
    // typed-error surface across the two regimes.
    let bundle: WasmInstanceParamsBundle = decode(params_bundle_bincode, "params_bundle")?;
    let inspire_params: InspireParams = decode(&bundle.inspire_params_bincode, "inspire_params")?;
    let crs: ServerCrs = decode(crs_bincode, "server_crs")?;
    if crs.ring_dim() != inspire_params.ring_dim {
        return Err(WasmClientError::Decode {
            what: "client_session",
            detail: format!(
                "deserialize_client_session: CRS ring_dim {} does not match params-bundle InspireParams ring_dim {}",
                crs.ring_dim(),
                inspire_params.ring_dim
            ),
        }
        .into());
    }
    if session_bincode.len() > WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES {
        return Err(WasmClientError::Decode {
            what: "client_session",
            detail: format!(
                "size limit reached: payload {} bytes exceeds cap {}",
                session_bincode.len(),
                WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES
            ),
        }
        .into());
    }
    Err(WasmClientError::Decode {
        what: "client_session",
        detail: "upstream raven_inspire::ClientSession at pin 119641b lacks \
             Clone+Serialize+Deserialize derives; warm-cache deferred per Phase 6 (a)"
            .to_string(),
    }
    .into())
}

/// Generate a fresh RLWE secret key and return the [`WasmInstanceParamsBundle`]
/// bincode blob the SDK passes to [`build_client_session`].
#[wasm_bindgen]
pub fn build_instance_params_blob(
    inspire_params_bincode: &[u8],
    shard_config_bincode: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let inspire_params: InspireParams = decode(inspire_params_bincode, "inspire_params")?;
    // Validate shard_config decodes cleanly (catches operator/wallet mismatch at boot).
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

// Tree depth matches `engine/src/models/merkletree-types.ts:7` and
// `raven-railgun-engine::imt::TREE_DEPTH`. Pinned here so this crate
// stays a pure leaf in the WASM dependency graph.
const PATH_INDEX_TREE_DEPTH: u32 = 16;
const PATH_INDEX_LEAVES_PER_TREE: u32 = 1u32 << PATH_INDEX_TREE_DEPTH;
const PATH_INDICES_LEN: usize = PATH_INDEX_TREE_DEPTH as usize;

/// Flat-global-index for `(level, idx_at_level)` in a depth-D binary tree.
///
/// Level 0 (leaves) occupies `[0, 2^D)`; level 1 follows in `[2^D, 2^D + 2^(D-1))`,
/// …, root at `2^(D+1) - 2`. Mirrors `PerNodeEncoder::flat_index` in
/// `raven-railgun-engine`.
fn flat_index_for(level: u32, idx_at_level: u32) -> u32 {
    let depth = PATH_INDEX_TREE_DEPTH;
    let total = 1u32 << (depth + 1);
    let level_offset = total - (1u32 << (depth + 1 - level));
    level_offset + idx_at_level
}

/// 16 flat-global row indices for the Merkle auth path of `leaf_idx` in a
/// commit tree (`PerNodeEncoder` layout). The wallet issues one PIR query per
/// index and reconstructs the path locally.
#[wasm_bindgen]
pub fn path_indices_for_leaf(tree_number: u32, leaf_idx: u32) -> Result<Vec<u32>, JsValue> {
    let _ = tree_number;
    if leaf_idx >= PATH_INDEX_LEAVES_PER_TREE {
        return Err(JsValue::from_str(&format!(
            "path_indices_for_leaf: leaf_idx {leaf_idx} >= 2^TREE_DEPTH ({PATH_INDEX_LEAVES_PER_TREE})"
        )));
    }
    let mut out = Vec::with_capacity(PATH_INDICES_LEN);
    let mut idx = leaf_idx;
    for level in 0..PATH_INDEX_TREE_DEPTH {
        let sibling_idx = idx ^ 1;
        out.push(flat_index_for(level, sibling_idx));
        idx >>= 1;
    }
    Ok(out)
}

/// 16 flat-global row indices for the Merkle auth path of per-list PPOI leaf
/// `idx` (`PerListNodeEncoder` layout). Mirror of [`path_indices_for_leaf`]
/// keyed on `list_key` rather than `tree_number`.
#[wasm_bindgen]
pub fn path_indices_for_per_list_leaf(list_key: &[u8], idx: u32) -> Result<Vec<u32>, JsValue> {
    if list_key.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "path_indices_for_per_list_leaf: list_key length {} must be 32",
            list_key.len()
        )));
    }
    if idx >= PATH_INDEX_LEAVES_PER_TREE {
        return Err(JsValue::from_str(&format!(
            "path_indices_for_per_list_leaf: idx {idx} >= 2^TREE_DEPTH ({PATH_INDEX_LEAVES_PER_TREE})"
        )));
    }
    let mut out = Vec::with_capacity(PATH_INDICES_LEN);
    let mut walk = idx;
    for level in 0..PATH_INDEX_TREE_DEPTH {
        let sibling_idx = walk ^ 1;
        out.push(flat_index_for(level, sibling_idx));
        walk >>= 1;
    }
    Ok(out)
}

/// Capped bincode-deserialize entry point for integration tests.
///
/// Mirrors the cap the wasm-bindgen surface enforces via `decode<T>`
/// without exposing the helper itself (which is intentionally
/// crate-private so callers route through the typed surface). Returns
/// the same `String` shape as the wasm boundary's
/// `WasmClientError::Decode { detail }` so a failing-cap test can
/// assert on the surfaced detail.
#[doc(hidden)]
pub fn decode_capped_for_test<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    what: &'static str,
) -> Result<T, String> {
    decode::<T>(bytes, what).map_err(|e| e.to_string())
}

/// Trusted-cap mirror of [`decode_capped_for_test`].
///
/// Routes through the same [`decode_trusted`] helper the
/// [`deserialize_client_session`] wasm-bindgen surface uses (or would
/// use, once upstream lands the `ClientSession` serde derives) for
/// self-written session blobs, so tests can exercise the larger
/// [`WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES`] ceiling without leaking
/// the crate-private helper.
#[doc(hidden)]
pub fn decode_trusted_for_test<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    what: &'static str,
) -> Result<T, String> {
    decode_trusted::<T>(bytes, what).map_err(|e| e.to_string())
}

/// Pure-Rust mirror of [`serialize_client_session`].
///
/// At the locked upstream pin `119641b`, [`ClientSession`] does NOT
/// derive `Serialize` / `Clone`. Returns the same typed error the
/// wasm-bindgen surface surfaces so unit tests can lock the Phase 6
/// (a) deferral shape; when upstream lands the derives this body
/// switches to `bincode::serialize(session).map_err(|e| e.to_string())`
/// and the test asserts the working path instead.
#[doc(hidden)]
pub fn serialize_client_session_rust(session: &ClientSession) -> Result<Vec<u8>, String> {
    let _ = session;
    Err(
        "upstream raven_inspire::ClientSession at pin 119641b lacks \
         Clone+Serialize+Deserialize derives; warm-cache deferred per Phase 6 (a)"
            .to_string(),
    )
}

/// Pure-Rust mirror of [`deserialize_client_session`].
///
/// Pre-validates `session_bincode.len()` against the trusted cap and
/// `crs.ring_dim()` against the params bundle so the "size limit
/// reached" and ring-dim drift paths are testable, then surfaces the
/// same typed `Err` the wasm-bindgen surface surfaces at pin
/// `119641b`.
#[doc(hidden)]
pub fn deserialize_client_session_rust(
    params_bundle_bincode: &[u8],
    crs_bincode: &[u8],
    session_bincode: &[u8],
) -> Result<(ClientSession, InspireParams), String> {
    if session_bincode.len() > WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES {
        return Err(format!(
            "size limit reached: payload {} bytes exceeds cap {}",
            session_bincode.len(),
            WASM_DESERIALIZE_TRUSTED_LIMIT_BYTES
        ));
    }
    let bundle: WasmInstanceParamsBundle =
        bincode::deserialize(params_bundle_bincode).map_err(|e| e.to_string())?;
    let inspire_params: InspireParams =
        bincode::deserialize(&bundle.inspire_params_bincode).map_err(|e| e.to_string())?;
    let crs: ServerCrs = bincode::deserialize(crs_bincode).map_err(|e| e.to_string())?;
    if crs.ring_dim() != inspire_params.ring_dim {
        return Err(format!(
            "deserialize_client_session: CRS ring_dim {} does not match params-bundle InspireParams ring_dim {}",
            crs.ring_dim(),
            inspire_params.ring_dim
        ));
    }
    Err(
        "upstream raven_inspire::ClientSession at pin 119641b lacks \
         Clone+Serialize+Deserialize derives; warm-cache deferred per Phase 6 (a)"
            .to_string(),
    )
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

/// Rust-native mirror of [`path_indices_for_leaf`].
pub fn path_indices_for_leaf_rust(tree_number: u32, leaf_idx: u32) -> Result<Vec<u32>, String> {
    let _ = tree_number;
    if leaf_idx >= PATH_INDEX_LEAVES_PER_TREE {
        return Err(format!(
            "path_indices_for_leaf: leaf_idx {leaf_idx} >= 2^TREE_DEPTH ({PATH_INDEX_LEAVES_PER_TREE})"
        ));
    }
    let mut out = Vec::with_capacity(PATH_INDICES_LEN);
    let mut idx = leaf_idx;
    for level in 0..PATH_INDEX_TREE_DEPTH {
        let sibling_idx = idx ^ 1;
        out.push(flat_index_for(level, sibling_idx));
        idx >>= 1;
    }
    Ok(out)
}

/// Rust-native mirror of [`path_indices_for_per_list_leaf`].
pub fn path_indices_for_per_list_leaf_rust(list_key: &[u8], idx: u32) -> Result<Vec<u32>, String> {
    if list_key.len() != 32 {
        return Err(format!(
            "path_indices_for_per_list_leaf: list_key length {} must be 32",
            list_key.len()
        ));
    }
    if idx >= PATH_INDEX_LEAVES_PER_TREE {
        return Err(format!(
            "path_indices_for_per_list_leaf: idx {idx} >= 2^TREE_DEPTH ({PATH_INDEX_LEAVES_PER_TREE})"
        ));
    }
    let mut out = Vec::with_capacity(PATH_INDICES_LEN);
    let mut walk = idx;
    for level in 0..PATH_INDEX_TREE_DEPTH {
        let sibling_idx = walk ^ 1;
        out.push(flat_index_for(level, sibling_idx));
        walk >>= 1;
    }
    Ok(out)
}

#[cfg(test)]
mod path_indices_tests {
    use super::*;

    #[test]
    fn path_indices_for_leaf_zero_matches_per_node_encoder_layout() {
        // For leaf 0 the sibling at level 0 is leaf 1 -> flat_index(0, 1) = 1.
        // Sibling at level 1 is the right child of the level-1 root segment
        // -> flat_index(1, 1) = 2^16 + 1 = 65537.
        let out = path_indices_for_leaf_rust(0, 0).expect("leaf 0 ok");
        assert_eq!(out[0], 1);
        assert_eq!(out[1], 65537);
    }

    #[test]
    fn path_indices_for_per_list_returns_same_layout_as_per_node_encoder() {
        // Per-list and commit-tree paths share the per-node flat layout;
        // for the same leaf index the index sequences must be byte-identical.
        let key = [7u8; 32];
        let a = path_indices_for_leaf_rust(0, 1234).expect("leaf 1234 ok");
        let b = path_indices_for_per_list_leaf_rust(&key, 1234).expect("per-list 1234 ok");
        assert_eq!(a, b);
    }

    #[test]
    fn flat_index_root_is_total_minus_two() {
        let depth = PATH_INDEX_TREE_DEPTH;
        let total = 1u32 << (depth + 1);
        let root = flat_index_for(depth, 0);
        assert_eq!(root, total - 2);
    }
}
