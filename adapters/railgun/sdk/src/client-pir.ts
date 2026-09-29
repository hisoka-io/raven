/** Client-side PIR helper over `@hisoka-io/raven-inspire-client-wasm`; only the encrypted blob crosses the wire. */

import { RavenError } from "./errors";
import { idbGet, idbPut, sha256Hex } from "./session-cache";

/** Structural contract for the subset of `@hisoka-io/raven-inspire-client-wasm` this SDK consumes. */
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
  /** Serialize a session to a cacheable blob; optional in the wasm interface. */
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

/** Validated shard addressing needed to choose cover queries. */
export interface ShardGeometry {
  readonly entriesPerShard: number;
  readonly shardCount: number;
  /** Rows the instance holds; an index at or past it has no row. */
  readonly totalEntries: number;
}

/** Decode bincode `ShardConfig { shard_size_bytes, entry_size_bytes, total_entries }`. */
export function decodeShardGeometry(shardConfigBincode: Uint8Array): ShardGeometry {
  if (shardConfigBincode.length !== 24) {
    throw RavenError.invalidQuery(
      `ShardConfig bincode must be exactly 24 bytes, got ${shardConfigBincode.length}`,
    );
  }
  const view = new DataView(
    shardConfigBincode.buffer,
    shardConfigBincode.byteOffset,
    shardConfigBincode.byteLength,
  );
  const shardSizeBytes = view.getBigUint64(0, true);
  const entrySizeBytes = view.getBigUint64(8, true);
  const totalEntries = view.getBigUint64(16, true);
  if (entrySizeBytes === 0n) {
    throw RavenError.invalidQuery("ShardConfig entry_size_bytes must be non-zero");
  }
  if (shardSizeBytes === 0n || shardSizeBytes % entrySizeBytes !== 0n) {
    throw RavenError.invalidQuery(
      `ShardConfig shard_size_bytes ${shardSizeBytes} is not divisible by ` +
        `entry_size_bytes ${entrySizeBytes}`,
    );
  }
  if (totalEntries === 0n) {
    throw RavenError.invalidQuery("ShardConfig total_entries must be non-zero");
  }
  if (totalEntries > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw RavenError.invalidQuery("ShardConfig total_entries exceeds JavaScript safe integer range");
  }
  const entriesPerShard = shardSizeBytes / entrySizeBytes;
  const shardCount = (totalEntries + entriesPerShard - 1n) / entriesPerShard;
  if (
    entriesPerShard > BigInt(Number.MAX_SAFE_INTEGER) ||
    shardCount > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    throw RavenError.invalidQuery("ShardConfig geometry exceeds JavaScript safe integer range");
  }
  return {
    entriesPerShard: Number(entriesPerShard),
    shardCount: Number(shardCount),
    totalEntries: Number(totalEntries),
  };
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

const FLOOR_REFUSAL = "parameter floor refused";
const ENTROPY_REFUSAL = "OS entropy unavailable";

/**
 * Run one call into the wasm, raising what it throws as a `RavenError`: the wasm throws bare
 * strings. A parameter set outside the client's floors is a `DecodeError`, as is anything else the
 * wasm refuses, since it refuses only bytes the node served: the same bytes are refused again, so
 * none is retryable. A missing OS random source is `InvalidQuery`, as in `uniformRandomBelow`.
 */
export function callWasm<T>(operation: string, call: () => T): T {
  try {
    return call();
  } catch (cause) {
    if (cause instanceof RavenError) throw cause;
    const detail = cause instanceof Error ? cause.message : String(cause);
    if (detail.startsWith(FLOOR_REFUSAL)) {
      throw RavenError.decodeError(
        `${operation}: the node serves a PIR parameter set outside this client's floors ` +
          `(${detail}); use a node that serves the shipped parameters`,
        { cause: detail },
      );
    }
    if (detail.startsWith(ENTROPY_REFUSAL)) {
      throw RavenError.invalidQuery(
        `${operation}: no OS random source for the PIR keys (${detail}); run the client where ` +
          "globalThis.crypto.getRandomValues is available",
        { cause: detail },
      );
    }
    throw RavenError.decodeError(
      `${operation}: the PIR client refused what the node served (${detail})`,
      { cause: detail },
    );
  }
}

/** Install the wasm panic hook so Rust panics carry file:line. Returns false when the wasm does not export it. */
export function installPanicHook(wasm: RavenInspireWasm): boolean {
  if (typeof wasm.init_panic_hook === "function") {
    wasm.init_panic_hook();
    return true;
  }
  return false;
}

/** Decoded `/v1/instance/<id>/params` pieces consumed by `loadClientPirContext`. */
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

/** The built `ClientPirContext`, and whether it came from the session cache. */
export interface LoadClientPirContextResult {
  readonly context: ClientPirContext;
  /** `true` when reconstituted from cache; `false` on a cold `build_client_session`. */
  readonly cacheHit: boolean;
}

/**
 * Build a `ClientPirContext`. With `persistSession` the IndexedDB warm cache is
 * preferred, keyed `(instanceId, sha256(crsBincode))` so a CRS rotation self-invalidates;
 * storage failures degrade to the cold `build_client_session` path. Without it no session
 * blob is read or written, because that blob is the client's secret key at rest.
 */
export async function loadClientPirContext(
  input: LoadClientPirContextInput,
): Promise<LoadClientPirContextResult> {
  const { wasm, instanceId, crsBincode, shardConfigBincode, inspireParamsBincode, entrySize } =
    input;

  const paramsBundle = callWasm("loadClientPirContext", () =>
    wasm.build_instance_params_blob(inspireParamsBincode, shardConfigBincode),
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
    const session = buildSession();
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

  function buildSession(): RavenInspireClientSession {
    return callWasm("loadClientPirContext", () => {
      const session = wasm.build_client_session(paramsBundle, crsBincode);
      wasm.register_client_session(session, paramsBundle);
      return session;
    });
  }

  function coldPath(): LoadClientPirContextResult {
    const session = buildSession();
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
