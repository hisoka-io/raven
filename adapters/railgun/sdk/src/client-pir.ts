/** Client-side PIR helper over `raven-inspire-client-wasm`; only the encrypted blob crosses the wire. */

import { RavenError } from "./errors";
import type { RavenPOIPathWasm } from "./poi-pir";
import { idbGet, idbPut, sha256Hex } from "./session-cache";

/** Structural contract for the subset of `raven-inspire-client-wasm` this SDK consumes. */
export interface RavenInspireWasm extends RavenPOIPathWasm {
  build_client_session(
    paramsBundleBincode: Uint8Array,
    crsBincode: Uint8Array,
  ): RavenInspireClientSession;
  build_seeded_query(
    session: RavenInspireClientSession,
    shardConfigBincode: Uint8Array,
    targetIdx: bigint,
  ): Uint8Array;
  /** Replace only the clear shard selector in one serialized seeded query. */
  retarget_seeded_query_shard(queryBincode: Uint8Array, nominalShardId: number): Uint8Array;
  extract_response(
    session: RavenInspireClientSession,
    crsBincode: Uint8Array,
    clientStateBincode: Uint8Array,
    responseBytes: Uint8Array,
    entrySize: number,
  ): Uint8Array;
  /** Bind the session to the server's instance params. Throws on a geometry
   * mismatch, which would otherwise return a plausible record from the wrong row. */
  register_client_session(
    session: RavenInspireClientSession,
    instanceParamsBincode: Uint8Array,
  ): void;
  /** Emit the versioned client packing-key body for the remote session endpoint. */
  client_packing_keys_versioned(session: RavenInspireClientSession): Uint8Array;
  /** Install the bare server-issued handle so later queries omit inline packing keys. */
  install_server_session_handle(session: RavenInspireClientSession, handle: bigint): void;
  /** Install the WASM panic hook so Rust panics carry file:line; idempotent. */
  init_panic_hook?(): void;
  build_instance_params_blob(
    inspireParamsBincode: Uint8Array,
    shardConfigBincode: Uint8Array,
  ): Uint8Array;
  /** Serialize a session to a cacheable blob; absent on older builds. */
  serialize_client_session?(session: RavenInspireClientSession): Uint8Array;
  /** Reconstitute a session from a cached blob and the same params/CRS. */
  deserialize_client_session?(
    paramsBundleBincode: Uint8Array,
    crsBincode: Uint8Array,
    sessionBincode: Uint8Array,
  ): RavenInspireClientSession;
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

/** Decoded client-PIR query bundle; mirrors the Rust `WasmSeededQueryOutput` bincode struct. */
export interface ClientPirQueryBundle {
  /** Local-only; replayed into `extract_response`, never sent to the server. */
  clientStateBincode: Uint8Array;
  /** Encrypted PIR query payload sent inside the instance batch body. */
  queryBytes: Uint8Array;
}

/** Decode the bincode `{ client_state: Vec<u8>, query_bytes: Vec<u8> }` from `build_seeded_query`. */
export function decodeClientPirQueryBundle(buf: Uint8Array): ClientPirQueryBundle {
  // bincode v1: u64 LE length prefix per Vec<u8>.
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
  /** PIR instance id; first cache-key component, so same-CRS instances never collide. */
  readonly instanceId: string;
  readonly crsBincode: Uint8Array;
  readonly shardConfigBincode: Uint8Array;
  readonly inspireParamsBincode: Uint8Array;
  readonly entrySize: number;
  /**
   * Opt in to caching the session across page loads. The blob holds the client's RLWE
   * secret key, so enabling it places that secret at rest and needs the user's informed
   * consent. Defaults to `false`.
   */
  readonly persistSession?: boolean;
}

/** [`ClientPirContext`] plus a test-only warm-cache hit signal. */
export interface LoadClientPirContextResult {
  readonly context: ClientPirContext;
  /** `true` when reconstituted from cache; `false` on a cold `build_client_session`. */
  readonly cacheHit: boolean;
}

/**
 * Build a [`ClientPirContext`]. With `persistSession` the IndexedDB warm cache is
 * preferred, keyed `(instanceId, sha256(crsBincode))` so a CRS rotation self-invalidates;
 * storage failures degrade to the cold `build_client_session` path. Without it no session
 * blob is read or written, because that blob is the client's secret key at rest.
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
    input.persistSession === true &&
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
      }
    }
    const session = wasm.build_client_session(paramsBundle, crsBincode);
    wasm.register_client_session(session, paramsBundle);
    try {
      const blob = wasm.serialize_client_session!(session);
      await idbPut(instanceId, crsHash, blob);
    } catch {
    }
    return {
      context: { wasm, session, crsBincode, shardConfigBincode, entrySize },
      cacheHit: false,
    };
  }

  return coldPath();

  function coldPath(): LoadClientPirContextResult {
    const session = wasm.build_client_session(paramsBundle, crsBincode);
    wasm.register_client_session(session, paramsBundle);
    return {
      context: { wasm, session, crsBincode, shardConfigBincode, entrySize },
      cacheHit: false,
    };
  }
}

function readU64LE(view: DataView, offset: number): number {
  // Payload lengths stay far under 2^32, so truncating the u64 is safe.
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
