/**
 * Client-side PIR helper for the Raven Railgun POI SDK.
 *
 * Wraps the `raven-inspire-client-wasm` Wasm artifact that ships the
 * raven-inspire client API (build_seeded_query / extract_response).
 * The wallet builds encrypted PIR queries entirely in-process and
 * POSTs only the encrypted blob to the adapter server. Plaintext
 * blinded commitments and leaf indices never cross the wire.
 *
 * Two consumers:
 * - `RavenPOINodeInterface` constructed with `useClientPir: true`
 *   uses this module to build queries.
 * - The privacy-invariant test harness uses the exported types to
 *   capture wire requests and assert no BC bytes appear in any
 *   request body.
 */

import type { POIStatus } from "./raven-poi-node-interface";
import { RavenError } from "./errors";
import { idbGet, idbPut, sha256Hex } from "./session-cache";

/**
 * Subset of the `raven-inspire-client-wasm` surface this SDK needs.
 *
 * The wasm-pack output is loaded lazily; this interface is the
 * structural contract the SDK consumes regardless of how the wasm
 * was loaded (bundler import vs Node CJS require vs direct
 * WebAssembly instantiation).
 */
export interface RavenInspireWasm {
  build_client_session(
    paramsBundleBincode: Uint8Array,
    crsBincode: Uint8Array,
  ): RavenInspireClientSession;
  build_seeded_query(
    session: RavenInspireClientSession,
    shardConfigBincode: Uint8Array,
    targetIdx: bigint,
  ): Uint8Array;
  extract_response(
    session: RavenInspireClientSession,
    crsBincode: Uint8Array,
    clientStateBincode: Uint8Array,
    responseBytes: Uint8Array,
    entrySize: number,
  ): Uint8Array;
  register_client_session?(
    session: RavenInspireClientSession,
    instanceParamsBincode: Uint8Array,
  ): void;
  /**
   * Install the WASM-side panic hook so Rust panics inside the
   * crate surface as structured `Error: panicked at '<msg>',
   * <file>:<line>` JS exceptions instead of opaque
   * `RuntimeError: unreachable executed` traps.
   *
   * Idempotent. Wallets SHOULD call this once at module load before
   * any other call. The convenience wrapper [`installPanicHook`]
   * forwards here and is a safe no-op when the wasm shim does not
   * expose the symbol.
   */
  init_panic_hook?(): void;
  build_instance_params_blob(
    inspireParamsBincode: Uint8Array,
    shardConfigBincode: Uint8Array,
  ): Uint8Array;
  /**
   * Serialize a fully constructed client session to a bincode blob
   * that can be cached across page reloads / process restarts.
   *
   * Optional: older WASM builds do not export this symbol; callers
   * MUST treat it as `undefined` and skip the warm-cache path.
   * Available since the `s036-client-session-serde` upstream pin.
   */
  serialize_client_session?(session: RavenInspireClientSession): Uint8Array;
  /**
   * Reconstitute a session from a previously cached bincode blob
   * plus the same params bundle / CRS the cold path consumed.
   *
   * Optional: older WASM builds do not export this symbol; callers
   * MUST treat it as `undefined` and fall through to
   * `build_client_session`. Available since the
   * `s036-client-session-serde` upstream pin.
   */
  deserialize_client_session?(
    paramsBundleBincode: Uint8Array,
    crsBincode: Uint8Array,
    sessionBincode: Uint8Array,
  ): RavenInspireClientSession;
  /**
   * Returns the 16 flat-global row indices needed for an auth-path
   * PIR query against `PerNodeEncoder` (commit-tree). Pure function;
   * deterministic. Throws on `leaf_idx >= 2^16`.
   */
  path_indices_for_leaf(treeNumber: number, leafIdx: number): Uint32Array;
  /**
   * Returns the 16 flat-global row indices needed for an auth-path
   * PIR query against `PerListNodeEncoder` (per-list PPOI tree).
   * Pure function; deterministic. Throws on
   * `list_key.length != 32` or `idx >= 2^16`.
   */
  path_indices_for_per_list_leaf(listKey: Uint8Array, idx: number): Uint32Array;
}

/**
 * Opaque handle owned by the wasm module. The SDK never inspects it.
 */
export interface RavenInspireClientSession {
  free(): void;
}

/**
 * Cached state for one (instance_id, list_key) tuple. Built once per
 * session boot via `loadClientPir`; reused across all
 * `getPOIsPerList` / `getPOIMerkleProofs` / `getMerkleProof` calls.
 */
export interface ClientPirContext {
  readonly wasm: RavenInspireWasm;
  readonly session: RavenInspireClientSession;
  readonly crsBincode: Uint8Array;
  readonly shardConfigBincode: Uint8Array;
  readonly entrySize: number;
}

/**
 * Pre-computed BC -> idx map for one PPOI list. The wallet fetches
 * this once at boot from the server's public publishing channel
 * (`GET /v1/poi/:list/bc-to-idx-map`). Lookup happens locally; the
 * idx is then handed to the wasm query builder.
 */
export type BcToIdxMap = Map<string, number>;

/**
 * Decoded shape of a single client-PIR query bundle. Mirrors the
 * Rust `WasmSeededQueryOutput` bincode struct.
 */
export interface ClientPirQueryBundle {
  /**
   * Local-only; held in memory while the HTTP request is in flight
   * and passed back to `extract_response` when the server replies.
   * Never sent to the server.
   */
  clientStateBincode: Uint8Array;
  /**
   * The encrypted PIR query blob. POSTed to `/v1/instance/:id/query`.
   */
  queryBytes: Uint8Array;
}

/**
 * Decode the bincode payload returned by `build_seeded_query`.
 *
 * The wasm module emits a single `Uint8Array` carrying the bincode
 * of `{ client_state_bincode: Vec<u8>, query_bytes: Vec<u8> }`. Both
 * inner Vec<u8>s are bincode-prefix-encoded.
 */
export function decodeClientPirQueryBundle(buf: Uint8Array): ClientPirQueryBundle {
  // bincode v1 default config: u64 LE length prefix for Vec<u8>.
  if (buf.length < 8) {
    throw RavenError.decodeError(`decodeClientPirQueryBundle: buffer too short (${buf.length})`);
  }
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const stateLen = readU64LE(view, 0);
  const stateStart = 8;
  const stateEnd = stateStart + stateLen;
  if (stateEnd + 8 > buf.length) {
    throw RavenError.decodeError(
      `decodeClientPirQueryBundle: truncated state payload (need ${stateEnd + 8}, have ${buf.length})`,
    );
  }
  const clientStateBincode = buf.subarray(stateStart, stateEnd);
  const queryLen = readU64LE(view, stateEnd);
  const queryStart = stateEnd + 8;
  const queryEnd = queryStart + queryLen;
  if (queryEnd > buf.length) {
    throw RavenError.decodeError(
      `decodeClientPirQueryBundle: truncated query payload (need ${queryEnd}, have ${buf.length})`,
    );
  }
  const queryBytes = buf.subarray(queryStart, queryEnd);
  return {
    clientStateBincode: cloneBytes(clientStateBincode),
    queryBytes: cloneBytes(queryBytes),
  };
}

/**
 * Install the wasm-side panic hook so Rust panics surface as
 * structured `Error: panicked at '<msg>', <file>:<line>` JS
 * exceptions. Wallets SHOULD call this once at module load before
 * any other PIR call.
 *
 * Idempotent and dependency-injected: takes the same `wasm`
 * module the SDK already accepts via `ClientPirContext`. Returns
 * `true` if the hook was installed, `false` if the underlying
 * wasm shim does not expose `init_panic_hook` (older builds).
 *
 * Without this hook, raven-inspire panics arrive at JS as
 * `RuntimeError: unreachable executed` with no Rust file:line, so
 * any production-side debugging is materially harder. With it,
 * every panic carries the originating `file.rs:N:C` and the
 * assertion message.
 */
export function installPanicHook(wasm: RavenInspireWasm): boolean {
  if (typeof wasm.init_panic_hook === "function") {
    wasm.init_panic_hook();
    return true;
  }
  return false;
}

/**
 * Inputs for [`loadClientPirContext`]. The wallet supplies the
 * already-fetched + decoded `/v1/instance/<id>/params` envelope
 * pieces; this function takes them and produces a
 * [`ClientPirContext`] ready for use, transparently using the
 * IndexedDB warm-cache when available.
 */
export interface LoadClientPirContextInput {
  /** WASM module exposing the `build_*` / `*_client_session` API. */
  readonly wasm: RavenInspireWasm;
  /** Stable identifier for the PIR instance (e.g.
   *  `commit-tree-0`). Used as the first component of the cache
   *  key so two instances with the same CRS hash never collide. */
  readonly instanceId: string;
  readonly crsBincode: Uint8Array;
  readonly shardConfigBincode: Uint8Array;
  readonly inspireParamsBincode: Uint8Array;
  readonly entrySize: number;
}

/**
 * Returned alongside the [`ClientPirContext`] so callers can
 * observe whether the warm cache was hit. Test-only signal; the
 * production path treats hit / miss interchangeably.
 */
export interface LoadClientPirContextResult {
  readonly context: ClientPirContext;
  /** `true` when the session was reconstituted from the cache;
   *  `false` when [`build_client_session`] was invoked from cold. */
  readonly cacheHit: boolean;
}

/**
 * Build a [`ClientPirContext`] from the operator-side params
 * bundle, transparently using the warm-cache path when the WASM
 * module exposes [`serialize_client_session`] +
 * [`deserialize_client_session`] AND a cached blob exists for
 * `(instanceId, sha256(crsBincode))`.
 *
 * Cold-path cost: ~12.6 s at production-cell d=2048 (the WASM-side
 * `PackParams::new` automorph-table O(d^3) search +
 * `ClientPackingKeys::generate`).
 *
 * Warm-path cost: a few hundred ms for the IndexedDB read +
 * bincode-deserialize of the cached session blob.
 *
 * The cache is keyed by `(instanceId, sha256(crsBincode))` so a
 * CRS rotation (e.g. operator restart with a new seed) auto-
 * invalidates every cached session without an explicit clear
 * step.
 *
 * Storage failures degrade silently to the cold path (the cache
 * is best-effort; correctness is preserved by always being able
 * to fall back to [`build_client_session`]).
 */
export async function loadClientPirContext(
  input: LoadClientPirContextInput,
): Promise<LoadClientPirContextResult> {
  const { wasm, instanceId, crsBincode, shardConfigBincode, inspireParamsBincode, entrySize } =
    input;

  const paramsBundle = wasm.build_instance_params_blob(
    inspireParamsBincode,
    shardConfigBincode,
  );

  // Try the warm path first when the WASM module exports the
  // serialize/deserialize pair AND the cache holds a live entry.
  const canCache =
    typeof wasm.serialize_client_session === "function" &&
    typeof wasm.deserialize_client_session === "function";

  if (canCache) {
    let crsHash: string;
    try {
      crsHash = await sha256Hex(crsBincode);
    } catch {
      // Web Crypto unavailable; degrade to cold.
      return coldPath();
    }
    const cached = await idbGet(instanceId, crsHash);
    if (cached) {
      try {
        const session = wasm.deserialize_client_session!(paramsBundle, crsBincode, cached);
        return {
          context: { wasm, session, crsBincode, shardConfigBincode, entrySize },
          cacheHit: true,
        };
      } catch {
        // Corrupt cache entry: fall through to cold rebuild + reseed.
      }
    }
    // Cold rebuild + reseed the cache for the next page load.
    const session = wasm.build_client_session(paramsBundle, crsBincode);
    try {
      const blob = wasm.serialize_client_session!(session);
      await idbPut(instanceId, crsHash, blob);
    } catch {
      // best-effort; the session is still valid even if seeding fails.
    }
    return {
      context: { wasm, session, crsBincode, shardConfigBincode, entrySize },
      cacheHit: false,
    };
  }

  return coldPath();

  function coldPath(): LoadClientPirContextResult {
    const session = wasm.build_client_session(paramsBundle, crsBincode);
    return {
      context: { wasm, session, crsBincode, shardConfigBincode, entrySize },
      cacheHit: false,
    };
  }
}

/**
 * Map the leading byte of a PIR-extracted plaintext row to the
 * Railgun POI status enum. Mirrors the server-side encoder
 * (`PerListStatusEncoder`) where the first byte of every row is the
 * status enum value.
 */
export function statusByteToPOIStatus(b: number): POIStatus {
  switch (b) {
    case 0:
      return "Valid";
    case 1:
      return "ShieldBlocked";
    case 2:
      return "ProofSubmitted";
    case 3:
      return "Missing";
    default:
      return "Missing";
  }
}

function readU64LE(view: DataView, offset: number): number {
  // bincode v1 emits u64 LE. JS only safely represents integers up
  // to 2^53; the bincode payloads we decode here are byte vectors
  // whose lengths are always well under that ceiling (~hundreds of
  // KB), so the truncation to Number is safe in practice.
  const lo = view.getUint32(offset, true);
  const hi = view.getUint32(offset + 4, true);
  if (hi !== 0) {
    // Defensive: no byte vector we decode should hit 4 GB.
    throw RavenError.decodeError(`readU64LE: payload length exceeds 2^32 (hi=${hi})`);
  }
  return lo;
}

function cloneBytes(src: Uint8Array): Uint8Array {
  const out = new Uint8Array(src.length);
  out.set(src);
  return out;
}

/**
 * Convert a hex string (with or without 0x prefix) to a Uint8Array.
 * Accepts both upper- and lowercase. Used for searching wire bodies
 * for BC bytes during the privacy-invariant test.
 */
export function hexToBytes(hex: string): Uint8Array {
  const stripped = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (stripped.length % 2 !== 0) {
    throw RavenError.invalidQuery(`hexToBytes: odd-length input (${stripped.length})`);
  }
  const out = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const byte = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw RavenError.invalidQuery(`hexToBytes: invalid hex pair at offset ${i * 2}`);
    }
    out[i] = byte;
  }
  return out;
}

/**
 * Lower-case hex (no 0x prefix) of a Uint8Array. Used by tests +
 * by the SDK's own logging.
 */
export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

/**
 * Returns true if `haystack` contains every byte of `needle` in
 * order, contiguous. Used by the privacy-invariant test to assert
 * no BC bytes appear anywhere in any wire request body.
 */
export function containsByteSequence(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0) return true;
  if (needle.length > haystack.length) return false;
  outer: for (let i = 0; i <= haystack.length - needle.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

/**
 * Tree-depth used by the Railgun commitment-tree (16). Mirrors the
 * Rust constant in `raven-railgun-engine::imt::TREE_DEPTH`.
 */
export const TREE_DEPTH = 16;

/**
 * Maximum leaves per tree (`2 ^ TREE_DEPTH`).
 */
export const TREE_MAX_LEAVES = 1 << TREE_DEPTH;

/**
 * Validate a hex-encoded blinded commitment: must decode to exactly
 * 32 bytes. Throws `RavenError.invalidQuery` on failure with the
 * offending value embedded in the message.
 */
export function validateBcHex(bc: string, label: string = "blindedCommitment"): void {
  const stripped = bc.startsWith("0x") || bc.startsWith("0X") ? bc.slice(2) : bc;
  if (stripped.length !== 64) {
    throw RavenError.invalidQuery(
      `${label}: expected 64 hex chars (32 bytes), got ${stripped.length}`,
    );
  }
  if (!/^[0-9a-fA-F]+$/.test(stripped)) {
    throw RavenError.invalidQuery(`${label}: contains non-hex characters`);
  }
}

/**
 * Validate a hex-encoded list_key: must decode to exactly 32 bytes.
 */
export function validateListKeyHex(listKey: string, label: string = "listKey"): void {
  const stripped = listKey.startsWith("0x") || listKey.startsWith("0X") ? listKey.slice(2) : listKey;
  if (stripped.length !== 64) {
    throw RavenError.invalidQuery(
      `${label}: expected 64 hex chars (32 bytes), got ${stripped.length}`,
    );
  }
  if (!/^[0-9a-fA-F]+$/.test(stripped)) {
    throw RavenError.invalidQuery(`${label}: contains non-hex characters`);
  }
}

/**
 * Validate a leaf-index against the tree's leaf range.
 */
export function validateLeafIndex(idx: number, label: string = "leafIndex"): void {
  if (!Number.isInteger(idx)) {
    throw RavenError.invalidQuery(`${label}: ${idx} must be an integer`);
  }
  if (idx < 0) {
    throw RavenError.invalidQuery(`${label}: ${idx} must be >= 0`);
  }
  if (idx >= TREE_MAX_LEAVES) {
    throw RavenError.invalidQuery(`${label}: ${idx} >= 2^${TREE_DEPTH} (${TREE_MAX_LEAVES})`);
  }
}

/**
 * Validate a tree number against the chain's known tree set
 * (range-only here; the upstream Railgun protocol caps trees at
 * `0..2^32` via the `treeNumber: u32` shape).
 */
export function validateTreeNumber(treeNumber: number, label: string = "treeNumber"): void {
  if (!Number.isInteger(treeNumber)) {
    throw RavenError.invalidQuery(`${label}: ${treeNumber} must be an integer`);
  }
  if (treeNumber < 0) {
    throw RavenError.invalidQuery(`${label}: ${treeNumber} must be >= 0`);
  }
  if (treeNumber > 0xffffffff) {
    throw RavenError.invalidQuery(`${label}: ${treeNumber} exceeds u32 range`);
  }
}

// ---------------------------------------------------------------------------
// Path-indices helpers (TS-side wrappers over the WASM exports)
// ---------------------------------------------------------------------------

/**
 * Wrap `wasm.path_indices_for_leaf` with TS-side validation +
 * defensive copy. Returns a plain `number[]` of length 16; throws
 * `RavenError.invalidQuery` on out-of-range input or
 * `RavenError.decodeError` if the wasm output isn't the expected
 * shape (defensive guard).
 */
export function pathIndicesForLeaf(
  wasm: RavenInspireWasm,
  treeNumber: number,
  leafIdx: number,
): number[] {
  validateTreeNumber(treeNumber);
  validateLeafIndex(leafIdx);
  let raw: Uint32Array;
  try {
    raw = wasm.path_indices_for_leaf(treeNumber, leafIdx);
  } catch (cause) {
    throw RavenError.invalidQuery(
      `path_indices_for_leaf: wasm threw on (tree=${treeNumber}, leaf=${leafIdx})`,
      { cause: String(cause) },
    );
  }
  if (raw.length !== TREE_DEPTH) {
    throw RavenError.decodeError(
      `path_indices_for_leaf: wasm returned ${raw.length} indices (expected ${TREE_DEPTH})`,
    );
  }
  const out: number[] = new Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    out[i] = raw[i];
  }
  return out;
}

/**
 * Wrap `wasm.path_indices_for_per_list_leaf` with TS-side validation
 * + defensive copy.
 */
export function pathIndicesForPerListLeaf(
  wasm: RavenInspireWasm,
  listKeyHex: string,
  idx: number,
): number[] {
  validateListKeyHex(listKeyHex);
  validateLeafIndex(idx, "perListIndex");
  const listKeyBytes = hexToBytes(listKeyHex);
  let raw: Uint32Array;
  try {
    raw = wasm.path_indices_for_per_list_leaf(listKeyBytes, idx);
  } catch (cause) {
    throw RavenError.invalidQuery(
      `path_indices_for_per_list_leaf: wasm threw on (idx=${idx})`,
      { cause: String(cause) },
    );
  }
  if (raw.length !== TREE_DEPTH) {
    throw RavenError.decodeError(
      `path_indices_for_per_list_leaf: wasm returned ${raw.length} indices (expected ${TREE_DEPTH})`,
    );
  }
  const out: number[] = new Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    out[i] = raw[i];
  }
  return out;
}

