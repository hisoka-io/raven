/** Client-side PIR helper over `raven-inspire-client-wasm`; only the encrypted blob crosses the wire. */

import type { POIStatus } from "./raven-poi-node-interface";
import { RavenError } from "./errors";
import { idbGet, idbPut, sha256Hex } from "./session-cache";

/** Structural contract for the subset of `raven-inspire-client-wasm` this SDK consumes. */
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
  /** Install the WASM panic hook so Rust panics carry file:line; idempotent. Optional on older builds. */
  init_panic_hook?(): void;
  build_instance_params_blob(
    inspireParamsBincode: Uint8Array,
    shardConfigBincode: Uint8Array,
  ): Uint8Array;
  /** Serialize a session to a cacheable bincode blob. Optional; treat as `undefined` and skip warm-cache on older builds. */
  serialize_client_session?(session: RavenInspireClientSession): Uint8Array;
  /** Reconstitute a session from a cached blob + same params/CRS. Optional; fall through to `build_client_session` on older builds. */
  deserialize_client_session?(
    paramsBundleBincode: Uint8Array,
    crsBincode: Uint8Array,
    sessionBincode: Uint8Array,
  ): RavenInspireClientSession;
  /** 16 flat-global auth-path row indices for a commit-tree leaf. Throws on `leaf_idx >= 2^16`. */
  path_indices_for_leaf(treeNumber: number, leafIdx: number): Uint32Array;
  /** 16 flat-global auth-path row indices for a per-list leaf. Throws on `list_key.length != 32` or `idx >= 2^16`. */
  path_indices_for_per_list_leaf(listKey: Uint8Array, idx: number): Uint32Array;
}

/** Opaque wasm-owned handle; the SDK never inspects it. */
export interface RavenInspireClientSession {
  free(): void;
}

/** Cached per-instance PIR state; built once at boot, reused across all queries. */
export interface ClientPirContext {
  readonly wasm: RavenInspireWasm;
  readonly session: RavenInspireClientSession;
  readonly crsBincode: Uint8Array;
  readonly shardConfigBincode: Uint8Array;
  readonly entrySize: number;
}

/** BC -> idx map for one PPOI list, fetched once from `GET /v1/poi/:list/bc-to-idx-map`. */
export type BcToIdxMap = Map<string, number>;

/** Decoded client-PIR query bundle; mirrors the Rust `WasmSeededQueryOutput` bincode struct. */
export interface ClientPirQueryBundle {
  /** Local-only; replayed into `extract_response`, never sent to the server. */
  clientStateBincode: Uint8Array;
  /** Encrypted PIR query blob; POSTed to `/v1/instance/:id/query`. */
  queryBytes: Uint8Array;
}

/** Decode the bincode `{ client_state: Vec<u8>, query_bytes: Vec<u8> }` from `build_seeded_query`. */
export function decodeClientPirQueryBundle(buf: Uint8Array): ClientPirQueryBundle {
  // bincode v1: u64 LE length prefix per Vec<u8>
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

/** Install the wasm panic hook so Rust panics carry file:line. Returns false on older builds lacking the symbol. */
export function installPanicHook(wasm: RavenInspireWasm): boolean {
  if (typeof wasm.init_panic_hook === "function") {
    wasm.init_panic_hook();
    return true;
  }
  return false;
}

/** Decoded `/v1/instance/<id>/params` pieces consumed by [`loadClientPirContext`]. */
export interface LoadClientPirContextInput {
  /** WASM module exposing the `build_*` / `*_client_session` API. */
  readonly wasm: RavenInspireWasm;
  /** PIR instance id; first component of the cache key so same-CRS instances never collide. */
  readonly instanceId: string;
  readonly crsBincode: Uint8Array;
  readonly shardConfigBincode: Uint8Array;
  readonly inspireParamsBincode: Uint8Array;
  readonly entrySize: number;
}

/** [`ClientPirContext`] plus a warm-cache hit signal (test-only; prod treats hit/miss alike). */
export interface LoadClientPirContextResult {
  readonly context: ClientPirContext;
  /** `true` when reconstituted from cache; `false` on a cold `build_client_session`. */
  readonly cacheHit: boolean;
}

/**
 * Build a [`ClientPirContext`], using the IndexedDB warm cache when the WASM
 * exposes serialize/deserialize and a blob exists. Cache key is
 * `(instanceId, sha256(crsBincode))` so a CRS rotation auto-invalidates every
 * session. Storage failures degrade to the cold `build_client_session` path.
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

  const canCache =
    typeof wasm.serialize_client_session === "function" &&
    typeof wasm.deserialize_client_session === "function";

  if (canCache) {
    let crsHash: string;
    try {
      crsHash = await sha256Hex(crsBincode);
    } catch {
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
        // corrupt entry: fall through to cold rebuild + reseed
      }
    }
    const session = wasm.build_client_session(paramsBundle, crsBincode);
    try {
      const blob = wasm.serialize_client_session!(session);
      await idbPut(instanceId, crsHash, blob);
    } catch {
      // best-effort seed
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

/** Map the leading plaintext-row byte to the POI status enum; mirrors `PerListStatusEncoder`. */
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
  // payload lengths stay far under 2^32, so truncating the u64 to Number is safe
  const lo = view.getUint32(offset, true);
  const hi = view.getUint32(offset + 4, true);
  if (hi !== 0) {
    throw RavenError.decodeError(`readU64LE: payload length exceeds 2^32 (hi=${hi})`);
  }
  return lo;
}

function cloneBytes(src: Uint8Array): Uint8Array {
  const out = new Uint8Array(src.length);
  out.set(src);
  return out;
}

/** Convert a hex string (optional 0x prefix, any case) to a Uint8Array. */
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

/** Lower-case hex (no 0x prefix) of a Uint8Array. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

/** True if `haystack` contains `needle` as a contiguous byte subsequence. */
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

/** Commitment-tree depth; mirrors Rust `raven-railgun-engine::imt::TREE_DEPTH`. */
export const TREE_DEPTH = 16;

/** Maximum leaves per tree (`2 ^ TREE_DEPTH`). */
export const TREE_MAX_LEAVES = 1 << TREE_DEPTH;

/** Validate a hex blinded commitment decodes to exactly 32 bytes. */
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

/** Validate a hex list_key decodes to exactly 32 bytes. */
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

/** Validate a leaf-index against the tree's leaf range. */
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

/** Validate a tree number against the `u32` range upstream uses for `treeNumber`. */
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

/** Validated, defensively-copied wrapper over `wasm.path_indices_for_leaf`; returns 16 indices. */
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

/** Validated, defensively-copied wrapper over `wasm.path_indices_for_per_list_leaf`. */
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

