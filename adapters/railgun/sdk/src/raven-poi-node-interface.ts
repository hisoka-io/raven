import {
  type BcToIdxMap,
  type ClientPirContext,
  bytesToHex,
  containsByteSequence,
  decodeClientPirQueryBundle,
  decodeStatusRow,
  hexToBytes,
  pathIndicesForLeaf,
  pathIndicesForPerListLeaf,
  validateBcHex,
  validateLeafIndex,
  validateListKeyHex,
  validateTreeNumber,
  TREE_DEPTH,
} from "./client-pir";
import { paddedBatchLength } from "./batch-ladder";
import { ChainRegistry, type ChainRegistryEntry } from "./chain-registry";
import { RavenError } from "./errors";
import { ImtCache, imtCacheKey, imtCacheScopeKey } from "./imt-cache";
import { foldMerkleRoot } from "./poseidon";

/**
 * Uniform integer in `[0, bound)` from Web Crypto, rejection-sampled so the modulus does
 * not bias low values.
 *
 * Used to draw batch pads. `Math.random` would do for a cosmetic shuffle but not here:
 * the draw hides the cache-miss count from a server that sees every `shard_id` in
 * cleartext, so a predictable sequence is a predictable leak.
 */
function randomBelow(bound: number): number {
  if (!Number.isInteger(bound) || bound <= 0) {
    throw RavenError.invalidQuery(`randomBelow: bound must be a positive integer, got ${bound}`);
  }
  if (bound === 1) return 0;
  const c = globalThis.crypto;
  if (!c || typeof c.getRandomValues !== "function") {
    throw RavenError.invalidQuery(
      "randomBelow: globalThis.crypto.getRandomValues is unavailable; batch padding " +
        "cannot be drawn without a CSPRNG and cycling pads leaks the cache-miss count",
    );
  }
  // Largest multiple of `bound` that fits a u32; draws at or above it are rejected.
  const limit = Math.floor(0x1_0000_0000 / bound) * bound;
  const buf = new Uint32Array(1);
  for (;;) {
    c.getRandomValues(buf);
    const v = buf[0];
    if (v < limit) return v % bound;
  }
}

export type POIStatus = "Valid" | "ShieldBlocked" | "ProofSubmitted" | "Missing";
export type BlindedCommitmentType = "Shield" | "Transact" | "Unshield";

/**
 * `GET /v1/poi/:list_key/status-header`, in the shape the server actually sends.
 *
 * Keys are camelCase because the handler carries `#[serde(rename_all = "camelCase")]`.
 * Declaring them snake_case made TypeScript report `string[]` for fields that were
 * `undefined` at runtime, so `new Set(h.blocked_bcs ?? [])` produced an empty set and
 * every ShieldBlocked commitment on the list read as clean.
 */
export interface StatusHeader {
  /** Block height of the snapshot. */
  epoch: number;
  /** Hex-encoded 32-byte list key. */
  listKey: string;
  /** Shield-blocked blinded commitments, hex. */
  blockedBcs: string[];
  /** Proof-submitted (pending) blinded commitments, hex. */
  pendingBcs: string[];
}

/** Throws rather than defaulting a missing array to empty: an absent blocked set and an
 *  empty one mean opposite things to a wallet. */
function parseStatusHeader(body: unknown, url: string): StatusHeader {
  const stringArray = (value: unknown, field: string): string[] => {
    if (!Array.isArray(value) || value.some((v) => typeof v !== "string")) {
      throw RavenError.serverError(
        `status-header: ${field} must be an array of hex strings; an absent or malformed ` +
          `blocked set would silently read as "nothing is blocked"`,
        { url },
      );
    }
    return value as string[];
  };
  if (typeof body !== "object" || body === null) {
    throw RavenError.serverError("status-header: body is not an object", { url });
  }
  const raw = body as Record<string, unknown>;
  if (typeof raw.epoch !== "number") {
    throw RavenError.serverError("status-header: epoch must be a number", { url });
  }
  if (typeof raw.listKey !== "string") {
    throw RavenError.serverError("status-header: listKey must be a hex string", { url });
  }
  return {
    epoch: raw.epoch,
    listKey: raw.listKey,
    blockedBcs: stringArray(raw.blockedBcs, "blockedBcs"),
    pendingBcs: stringArray(raw.pendingBcs, "pendingBcs"),
  };
}

export interface MerkleProof {
  leaf: string;
  elements: string[];
  indices: string;
  root: string;
}

/** Commit-tree auth path with no root: sibling hashes and the leaf's path bits only. */
export interface CommitTreeAuthPath {
  /** 64-char no-prefix hex sibling hashes, level 0 (sibling of the leaf) first. */
  elements: string[];
  /** `nToHex(leafIndex, UINT_256)`; bit `i` set means right child at level `i`. */
  indices: string;
}

/**
 * Commit-tree proof, discriminated by whether a root is available. Client-PIR retrieves
 * auth-path siblings and never the leaf, so it cannot fold a root and does not claim one;
 * only the plaintext route, which the adapter answers with its own root, carries `rooted`.
 */
export type CommitTreeProof =
  | { readonly kind: "rooted"; readonly proof: MerkleProof }
  | ({ readonly kind: "authPath" } & CommitTreeAuthPath);

// Upstream Railgun Chain shape (engine/src/models/engine-types.ts); numeric `type` matches upstream wire shape.
/** Upstream Chain shape; numeric `type` matches the upstream wire shape. */
export interface Chain {
  /** Upstream `ChainType` enum: 0 = EVM. */
  type: number;
  id: number;
}

// Upstream `Proof` shape (engine/src/models/prover-types.ts), carried verbatim.
/** Upstream `Proof` shape, carried verbatim. */
export interface Proof {
  pi_a: [string, string];
  pi_b: [[string, string], [string, string]];
  pi_c: [string, string];
}

/** SDK constructor options; a supplied `chainRegistry` takes precedence over the single-chain `endpoint`/`bearerToken`/`chainId`. */
export interface RavenConfig {
  endpoint: string;
  bearerToken: string;
  /** EVM chain id this adapter serves; defaults to 1 (mainnet). */
  chainId?: number;
  /** Upstream `chainType` (0 = EVM); a path segment in PPOI passthrough URLs. */
  chainType?: number;
  /** Multi-chain routing table; when omitted an internal one-entry registry is built. */
  chainRegistry?: ChainRegistry;
  upstreamFallbackEndpoint?: string;
  txidVersion?: string;
  fetchImpl?: typeof fetch;
  freshnessConfidenceFloor?: number;
  /** When true (default), PIR queries are built client-side; plaintext blinded commitments never cross the wire. */
  useClientPir?: boolean;
  /** Pre-loaded client-PIR contexts keyed `t1Status|t2Path|t3CommitTree:<chainId>:<id>`;
   * the chain-less legacy key is accepted as a fallback. */
  clientPirContexts?: Map<string, ClientPirContext>;
  /** Pre-loaded BC -> idx maps, keyed by `<chainId>:<listKeyHex>` or legacy `<listKeyHex>`. */
  bcToIdxMaps?: Map<string, BcToIdxMap>;
  /** IMT cache for auth-path reconstruction; defaults to in-memory 1024 entries plus IndexedDB when available. */
  imtCache?: ImtCache;
}

interface BlindedCommitmentData {
  blindedCommitment: string;
  type: BlindedCommitmentType;
}

interface PoisPerListResponse {
  // Outer key BC hex, inner list-key hex; mirrors upstream POIsPerListMap.
  // Outer key BC hex, inner list-key hex; mirrors upstream POIsPerListMap (shared-models/src/models/proof-of-innocence.ts:153).
  [bcHex: string]: { [listKey: string]: POIStatus };
}

interface FreshnessHeader {
  lagBlocks: number;
  appliedHeight: number;
  epoch: number;
  confidence: number;
}

/** Captured outbound HTTP request; the privacy-invariant test harness asserts no BC bytes appear in any body. */
export interface CapturedWireRequest {
  url: string;
  method: string;
  /** Raw bytes of the request body. Empty Uint8Array if no body. */
  body: Uint8Array;
}

const X_RAVEN_FRESHNESS = "x-raven-freshness";
const X_RAVEN_EPOCH = "x-raven-epoch";
const X_RAVEN_SCHEMA_VERSION = "x-raven-schema-version";
const DEFAULT_TXID_VERSION = "V2_PoseidonMerkle";
const DEFAULT_CONFIDENCE_FLOOR = 0.5;
const DEFAULT_CHAIN_ID = 1;
const DEFAULT_CHAIN_TYPE = 0; // upstream `ChainType.EVM`
const NODE_HASH_BYTES = 32;
const PATH_RECORD_BYTES = TREE_DEPTH * NODE_HASH_BYTES;
/** Epoch tag before the instance has ever reported one; never collides with a real epoch. */
const UNOBSERVED_EPOCH = "";
const AUTH_PATH_ATTEMPTS = 2;

export class RavenPOINodeInterface {
  private readonly chainId: number;
  private readonly chainType: number;
  private readonly registry: ChainRegistry;
  private readonly upstream: string | undefined;
  private readonly txidVersion: string;
  private readonly fetchImpl: typeof fetch;
  private readonly confidenceFloor: number;
  private readonly useClientPir: boolean;
  private readonly clientPirContexts: Map<string, ClientPirContext>;
  private readonly bcToIdxMaps: Map<string, BcToIdxMap>;
  private readonly cache: ImtCache;
  // Last snapshot epoch each instance reported; auth-path cache entries are tagged with it.
  private readonly observedEpochs: Map<string, string> = new Map();

  // Bounded ring for the privacy-invariant test harness.
  private readonly capturedRequests: CapturedWireRequest[] = [];

  constructor(config: RavenConfig) {
    this.chainId = config.chainId ?? DEFAULT_CHAIN_ID;
    this.chainType = config.chainType ?? DEFAULT_CHAIN_TYPE;
    this.upstream = config.upstreamFallbackEndpoint?.replace(/\/$/, "");
    this.txidVersion = config.txidVersion ?? DEFAULT_TXID_VERSION;
    this.fetchImpl = config.fetchImpl ?? fetch;
    this.confidenceFloor = config.freshnessConfidenceFloor ?? DEFAULT_CONFIDENCE_FLOOR;
    this.useClientPir = config.useClientPir ?? true;
    this.clientPirContexts = config.clientPirContexts ?? new Map();
    this.bcToIdxMaps = config.bcToIdxMaps ?? new Map();
    this.cache = config.imtCache ?? new ImtCache();

    if (config.chainRegistry) {
      this.registry = config.chainRegistry;
      this.registry.resolve(this.chainId);
    } else {
      this.registry = new ChainRegistry(
        [
          {
            chainId: this.chainId,
            endpoint: config.endpoint,
            bearerToken: config.bearerToken,
          },
        ],
        this.fetchImpl,
      );
    }
  }

  private route(): ChainRegistryEntry {
    return this.registry.resolve(this.chainId);
  }

  /** Test-only snapshot of recent captured requests; order is not guaranteed. */
  lastWireRequests(): CapturedWireRequest[] {
    return this.capturedRequests.map((r) => ({
      url: r.url,
      method: r.method,
      body: r.body,
    }));
  }

  /** Reset the captured wire-request ring. */
  resetWireCapture(): void {
    this.capturedRequests.length = 0;
  }

  async getPOIsPerList(
    listKeys: string[],
    blindedCommitmentDatas: BlindedCommitmentData[],
  ): Promise<PoisPerListResponse> {
    for (const lk of listKeys) {
      validateListKeyHex(lk);
    }
    // Pre-init BC slots so unknown-BC rows still surface; matches upstream merge (poi-merkletree-manager.ts:215-218).
    for (const { blindedCommitment } of blindedCommitmentDatas) {
      validateBcHex(blindedCommitment);
    }
    if (this.useClientPir) {
      return this.getPOIsPerListClientPir(listKeys, blindedCommitmentDatas);
    }
    const body = {
      txidVersion: this.txidVersion,
      listKeys,
      blindedCommitmentDatas,
    };
    const { json, freshness } = await this.postJson<PoisPerListResponse>(
      "/v1/poi/pois-per-list",
      body,
    );
    if (this.shouldFallback(freshness) && this.upstream) {
      return this.passthroughPoisPerList(listKeys, blindedCommitmentDatas);
    }
    return json;
  }

  async getPOIMerkleProofs(
    listKey: string,
    blindedCommitments: string[],
  ): Promise<MerkleProof[]> {
    validateListKeyHex(listKey);
    for (const bc of blindedCommitments) {
      validateBcHex(bc);
    }
    if (this.useClientPir) {
      return this.getPOIMerkleProofsClientPir(listKey, blindedCommitments);
    }
    const body = {
      txidVersion: this.txidVersion,
      listKey,
      blindedCommitments,
    };
    const { json, freshness } = await this.postJson<MerkleProof[]>(
      "/v1/poi/merkle-proofs",
      body,
    );
    if (this.shouldFallback(freshness) && this.upstream) {
      return this.passthroughMerkleProofs(listKey, blindedCommitments);
    }
    return json;
  }

  async getMerkleProof(treeNumber: number, leafIndex: number): Promise<CommitTreeProof> {
    validateTreeNumber(treeNumber);
    validateLeafIndex(leafIndex);
    if (this.useClientPir) {
      return this.getMerkleProofClientPir(treeNumber, leafIndex);
    }
    const { json } = await this.postJson<MerkleProof>(
      `/v1/commit-tree/${treeNumber}/merkle-proof`,
      { leafIndex },
    );
    return { kind: "rooted", proof: json };
  }

  // `POINodeInterface.validatePOIMerkleroots` (engine/src/poi/poi-node-interface.ts:30-35);
  // body field `poiMerkleroots` matches upstream `ValidatePOIMerklerootsParams` (api.ts:786).
  /** Mirrors upstream `POINodeInterface.validatePOIMerkleroots`. */
  async validatePOIMerkleroots(
    listKey: string,
    poiMerkleroots: string[],
  ): Promise<boolean> {
    if (!this.upstream) return true;
    const body = JSON.stringify({
      chainType: String(this.chainType),
      chainID: String(this.chainId),
      txidVersion: this.txidVersion,
      listKey,
      poiMerkleroots,
    });
    const url = `${this.upstream}/validate-poi-merkleroots/${this.chainType}/${this.chainId}`;
    this.captureRequest(url, "POST", new TextEncoder().encode(body));
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      });
    } catch (cause) {
      throw RavenError.network("validatePOIMerkleroots", { url, cause: String(cause) });
    }
    if (!res.ok) {
      throw RavenError.serverError(`upstream validate-poi-merkleroots: ${res.status}`, {
        url,
        status: res.status,
      });
    }
    return (await res.json()) as boolean;
  }

  // `POINodeInterface.submitPOI` (engine/src/poi/poi-node-interface.ts:37-47);
  /** Mirrors upstream's 9-arg `POINodeInterface.submitPOI`. */
  async submitPOI(
    txidVersion: string,
    chain: Chain,
    listKey: string,
    snarkProof: Proof,
    poiMerkleroots: string[],
    txidMerkleroot: string,
    txidMerklerootIndex: number,
    blindedCommitmentsOut: string[],
    railgunTxidIfHasUnshield: string,
  ): Promise<void> {
    if (!this.upstream) {
      throw RavenError.invalidQuery("submitPOI requires upstreamFallbackEndpoint");
    }
    const body = JSON.stringify({
      chainType: String(chain.type),
      chainID: String(chain.id),
      txidVersion,
      listKey,
      transactProofData: {
        snarkProof,
        poiMerkleroots,
        txidMerkleroot,
        txidMerklerootIndex,
        blindedCommitmentsOut,
        railgunTxidIfHasUnshield,
      },
    });
    const url = `${this.upstream}/submit-transact-proof/${chain.type}/${chain.id}`;
    this.captureRequest(url, "POST", new TextEncoder().encode(body));
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      });
    } catch (cause) {
      throw RavenError.network("submitPOI", { url, cause: String(cause) });
    }
    if (!res.ok) {
      throw RavenError.serverError(`upstream submit-transact-proof: ${res.status}`, {
        url,
        status: res.status,
      });
    }
  }

  // `POINodeInterface.submitLegacyTransactProofs` (engine/src/poi/poi-node-interface.ts:49-54);
  /** Mirrors upstream `POINodeInterface.submitLegacyTransactProofs`. */
  async submitLegacyTransactProofs(
    listKeys: string[],
    legacyTransactProofDatas: unknown[],
  ): Promise<void> {
    if (!this.upstream) {
      throw RavenError.invalidQuery("submitLegacyTransactProofs requires upstreamFallbackEndpoint");
    }
    const body = JSON.stringify({
      chainType: String(this.chainType),
      chainID: String(this.chainId),
      txidVersion: this.txidVersion,
      listKeys,
      legacyTransactProofDatas,
    });
    const url = `${this.upstream}/submit-legacy-transact-proofs/${this.chainType}/${this.chainId}`;
    this.captureRequest(url, "POST", new TextEncoder().encode(body));
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      });
    } catch (cause) {
      throw RavenError.network("submitLegacyTransactProofs", { url, cause: String(cause) });
    }
    if (!res.ok) {
      throw RavenError.serverError(`upstream submit-legacy-transact-proofs: ${res.status}`, {
        url,
        status: res.status,
      });
    }
  }

  async fetchBcToIdxMap(listKey: string): Promise<{ epoch: number; entries: { bc: string; idx: number }[] }> {
    validateListKeyHex(listKey);
    const route = this.route();
    const url = `${route.endpoint}/v1/poi/${listKey}/bc-to-idx-map`;
    this.captureRequest(url, "GET", new Uint8Array());
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        headers: { authorization: `Bearer ${route.bearerToken}` },
      });
    } catch (cause) {
      throw RavenError.network("fetchBcToIdxMap", { url, cause: String(cause) });
    }
    if (!res.ok) {
      throw RavenError.serverError(`bc-to-idx-map: ${res.status}`, {
        url,
        status: res.status,
      });
    }
    return await res.json();
  }

  async fetchStatusHeader(listKey: string): Promise<StatusHeader> {
    validateListKeyHex(listKey);
    const route = this.route();
    const url = `${route.endpoint}/v1/poi/${listKey}/status-header`;
    this.captureRequest(url, "GET", new Uint8Array());
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        headers: { authorization: `Bearer ${route.bearerToken}` },
      });
    } catch (cause) {
      throw RavenError.network("fetchStatusHeader", { url, cause: String(cause) });
    }
    if (!res.ok) {
      throw RavenError.serverError(`status-header: ${res.status}`, {
        url,
        status: res.status,
      });
    }
    return parseStatusHeader(await res.json(), url);
  }

  // Chain-aware key first, then the legacy fallback.
  private lookupContext(prefix: string, scope: string): ClientPirContext | undefined {
    const chainAware = this.clientPirContexts.get(`${prefix}:${this.chainId}:${scope}`);
    if (chainAware) return chainAware;
    return this.clientPirContexts.get(`${prefix}:${scope}`);
  }

  private lookupBcMap(listKeyHex: string): BcToIdxMap | undefined {
    const chainAware = this.bcToIdxMaps.get(`${this.chainId}:${listKeyHex}`);
    if (chainAware) return chainAware;
    return this.bcToIdxMaps.get(listKeyHex);
  }

  private async getPOIsPerListClientPir(
    listKeys: string[],
    blindedCommitmentDatas: BlindedCommitmentData[],
  ): Promise<PoisPerListResponse> {
    const out: PoisPerListResponse = {};
    // Pre-init so unknown-BC rows still surface; matches the upstream merge.
    for (const { blindedCommitment } of blindedCommitmentDatas) {
      const bcHex = normalizeHex(blindedCommitment);
      out[bcHex] ??= {};
    }

    for (const listKey of listKeys) {
      const lkHex = normalizeHex(listKey);
      const ctx = this.lookupContext("t1Status", lkHex);
      const bcMap = this.lookupBcMap(lkHex);
      if (!ctx || !bcMap) {
        throw RavenError.invalidQuery(
          `client-PIR: missing context or bc-to-idx-map for list ${listKey}; ` +
            "preload via loadClientPirContext + fetchBcToIdxMap before calling getPOIsPerList",
        );
      }
      for (const { blindedCommitment } of blindedCommitmentDatas) {
        const bcHex = normalizeHex(blindedCommitment);
        const idx = bcMap.get(bcHex);
        if (idx === undefined) {
          out[bcHex][lkHex] = "Missing";
          continue;
        }
        let status: POIStatus;
        try {
          const label = `client-PIR t1Status-${lkHex} idx ${idx}`;
          const plaintext = await this.runClientPirQuery(`t1Status-${lkHex}`, ctx, BigInt(idx));
          status = decodeStatusRow(plaintext, bcHex, label);
        } catch (cause) {
          // KNOWN FAIL-OPEN, retained deliberately pending an owner ruling. `Missing` is
          // the NON-blocking verdict, so degrading a transport failure to it tells the
          // wallet a possibly-ShieldBlocked commitment is merely unproven. Removing the
          // downgrade surfaces those as errors, which is correct only once an oversized
          // upload reliably receives its 401 rather than a socket reset.
          if (cause instanceof RavenError && cause.kind === "Network") {
            status = "Missing";
          } else {
            throw cause;
          }
        }
        out[bcHex][lkHex] = status;
      }
    }
    return out;
  }

  private async getPOIMerkleProofsClientPir(
    listKey: string,
    blindedCommitments: string[],
  ): Promise<MerkleProof[]> {
    const lkHex = normalizeHex(listKey);
    const ctx = this.lookupContext("t2Path", lkHex);
    const bcMap = this.lookupBcMap(lkHex);
    if (!ctx || !bcMap) {
      throw RavenError.invalidQuery(
        `client-PIR: missing context or bc-to-idx-map for list ${listKey}; ` +
          "preload via loadClientPirContext + fetchBcToIdxMap before calling getPOIMerkleProofs",
      );
    }
    const out: MerkleProof[] = [];
    for (const bc of blindedCommitments) {
      const bcHex = normalizeHex(bc);
      const idx = bcMap.get(bcHex);
      if (idx === undefined) {
        throw RavenError.invalidQuery(
          `client-PIR: BC ${bcHex} not present in list ${lkHex} (idx unknown)`,
        );
      }
      // The leaf index never crosses the wire, only encrypted row queries.
      const indices = pathIndicesForPerListLeaf(ctx.wasm, lkHex, idx);
      const siblings = await this.fetchAuthPathNodes(
        `t2Path-${lkHex}`,
        ctx,
        indices,
        `list-${lkHex}`,
      );
      out.push(buildMerkleProof(idx, bcHex, siblings));
    }
    return out;
  }

  private async getMerkleProofClientPir(
    treeNumber: number,
    leafIndex: number,
  ): Promise<CommitTreeProof> {
    const ctx = this.lookupContext("t3CommitTree", String(treeNumber));
    if (!ctx) {
      throw RavenError.invalidQuery(
        `client-PIR: missing context for commit tree ${treeNumber}; ` +
          "preload via loadClientPirContext before calling getMerkleProof",
      );
    }
    const indices = pathIndicesForLeaf(ctx.wasm, treeNumber, leafIndex);
    const siblings = await this.fetchAuthPathNodes(
      `commit-tree-${treeNumber}`,
      ctx,
      indices,
      `tree-${treeNumber}`,
    );
    return {
      kind: "authPath",
      elements: siblings.map((s) => bytesToHex(s)),
      indices: leafIndexToIndicesHex(leafIndex),
    };
  }

  /** Auth-path sibling hashes indexed by level (0 = sibling of the leaf); every level
   * resolves against one snapshot epoch, retrying once if the adapter re-snapshots mid-assembly. */
  private async fetchAuthPathNodes(
    instanceLabel: string,
    ctx: ClientPirContext,
    indices: number[],
    cacheScope: string,
  ): Promise<Uint8Array[]> {
    if (indices.length !== TREE_DEPTH) {
      throw RavenError.batchMismatch(
        `fetchAuthPathNodes: expected ${TREE_DEPTH} indices, got ${indices.length}`,
      );
    }
    for (let attempt = 0; attempt < AUTH_PATH_ATTEMPTS; attempt += 1) {
      const nodes = await this.assembleAuthPath(instanceLabel, ctx, indices, cacheScope);
      if (nodes) return nodes;
    }
    throw RavenError.staleAdapter(
      `client-PIR ${instanceLabel}: snapshot epoch advanced on all ${AUTH_PATH_ATTEMPTS} ` +
        `assembly attempts; the adapter is re-snapshotting faster than one auth path resolves`,
    );
  }

  /** One single-epoch assembly attempt; `undefined` when the epoch moved under it and the
   * levels gathered so far can no longer be certified by one root. Cache misses batch into
   * one `POST /v1/instance/<id>/batch`. */
  private async assembleAuthPath(
    instanceLabel: string,
    ctx: ClientPirContext,
    indices: number[],
    cacheScope: string,
  ): Promise<Uint8Array[] | undefined> {
    const route = this.route();
    const out: (Uint8Array | undefined)[] = new Array(indices.length).fill(undefined);
    const missing: number[] = [];
    const epochTag = this.observedEpochs.get(instanceLabel) ?? UNOBSERVED_EPOCH;
    const schemaVersion = route.schemaVersion ?? 0;
    const scopeKey = imtCacheScopeKey({ chainId: this.chainId, scope: cacheScope });
    const keyAt = (level: number, tag: string): string =>
      imtCacheKey({
        chainId: this.chainId,
        scope: cacheScope,
        level,
        idxAtLevel: indices[level],
        epochTag: tag,
        schemaVersion,
      });

    for (let i = 0; i < indices.length; i += 1) {
      const hit = this.cache.getSync(keyAt(i, epochTag));
      if (hit) {
        out[i] = hit;
      } else {
        missing.push(i);
      }
    }

    const stillMissing: number[] = [];
    for (const i of missing) {
      const hit = await this.cache.getAsync(keyAt(i, epochTag));
      if (hit) {
        out[i] = hit;
      } else {
        stillMissing.push(i);
      }
    }

    // A zero-miss path re-queries every level rather than skipping the batch: an absent
    // request publishes a fully-warm cache more precisely than any batch length does.
    const queryLevels =
      stillMissing.length > 0 ? stillMissing : indices.map((_unused, level) => level);
    const foldsCachedLevels = queryLevels.length < indices.length;

    // Padded to a ladder step so the length publishes a bucket, not the exact
    // cache-miss count. Pads re-query a real level, so they are drawn from the
    // real slots' distribution and cost the server a full pass.
    //
    // Pads are drawn at RANDOM, never cycled. `SeededClientQuery.shard_id` is
    // unencrypted on the wire, so `queryLevels[slot % len]` made slot j and slot j+len
    // address the identical global index - the server reads the repeat period straight
    // off the shard sequence and recovers the exact miss count, which is the one
    // quantity the ladder exists to hide. Mirrors the Rust `build_padded_batch` fix.
    const paddedCount = paddedBatchLength(queryLevels.length);
    const queryBundles = Array.from({ length: paddedCount }, (_unused, slot) => {
      const level =
        slot < queryLevels.length
          ? queryLevels[slot]
          : queryLevels[randomBelow(queryLevels.length)];
      const target = BigInt(indices[level]);
      return decodeClientPirQueryBundle(
        ctx.wasm.build_seeded_query(ctx.session, ctx.shardConfigBincode, target),
      );
    });
    const batchBody = encodeBatchBody(queryBundles.map((b) => b.queryBytes));
    const url = `${route.endpoint}/v1/instance/${encodeURIComponent(instanceLabel)}/batch`;
    this.captureRequest(url, "POST", batchBody);
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        method: "POST",
        headers: {
          "content-type": "application/octet-stream",
          authorization: `Bearer ${route.bearerToken}`,
        },
        body: copyForBody(batchBody),
      });
    } catch (cause) {
      throw RavenError.network(`client-PIR batch ${instanceLabel}`, {
        url,
        cause: String(cause),
      });
    }
    if (res.status === 400) {
      const sv = res.headers.get(X_RAVEN_SCHEMA_VERSION);
      if (sv) {
        throw RavenError.staleAdapter(`client-PIR batch ${instanceLabel}: schema mismatch`, {
          url,
          status: 400,
          serverWireSchemaVersion: parseSchemaVersion(sv) ?? undefined,
          clientWireSchemaVersion: schemaVersion,
        });
      }
    }
    if (!res.ok) {
      throw RavenError.serverError(`client-PIR batch ${instanceLabel}: ${res.status}`, {
        url,
        status: res.status,
      });
    }
    // Header absent and header empty both arrive as UNOBSERVED_EPOCH, which would re-key
    // every node as never-observed and silently defeat the epoch tag.
    const servedEpoch = res.headers.get(X_RAVEN_EPOCH) ?? UNOBSERVED_EPOCH;
    if (servedEpoch === UNOBSERVED_EPOCH) {
      throw RavenError.staleAdapter(
        `client-PIR batch ${instanceLabel}: reply carries no ${X_RAVEN_EPOCH}, so the ` +
          `${indices.length} nodes it returned cannot be pinned to one snapshot`,
        { url, status: res.status },
      );
    }
    // A non-numeric version would reach the cache as NaN, and `NaN !== NaN` makes its
    // unchanged-tuple comparison unreachable, purging the scope on every reply forever.
    const serverSchemaRaw = res.headers.get(X_RAVEN_SCHEMA_VERSION)?.trim() ?? "";
    const serverSchema =
      serverSchemaRaw === "" ? schemaVersion : parseSchemaVersion(serverSchemaRaw);
    if (serverSchema === null) {
      throw RavenError.staleAdapter(
        `client-PIR batch ${instanceLabel}: ${X_RAVEN_SCHEMA_VERSION} is "${serverSchemaRaw}", ` +
          "not a decimal non-negative integer, so the reply cannot be pinned to a wire schema",
        { url, status: res.status, clientWireSchemaVersion: schemaVersion },
      );
    }
    this.cache.noteFreshness(scopeKey, servedEpoch, serverSchema);
    if (servedEpoch !== epochTag) {
      this.observedEpochs.set(instanceLabel, servedEpoch);
      if (foldsCachedLevels) {
        // Cached levels predate this snapshot; folding them with fresh siblings would
        // build a path no single root ever certified.
        return undefined;
      }
    }

    const bytes = new Uint8Array(await res.arrayBuffer());
    const responses = decodeBatchBody(bytes);
    if (responses.length !== queryBundles.length) {
      throw RavenError.batchMismatch(
        `client-PIR batch ${instanceLabel}: expected ${queryBundles.length} responses, got ${responses.length}`,
        { url },
      );
    }
    for (let k = 0; k < queryLevels.length; k += 1) {
      const level = queryLevels[k];
      let plaintext: Uint8Array;
      try {
        plaintext = ctx.wasm.extract_response(
          ctx.session,
          ctx.crsBincode,
          queryBundles[k].clientStateBincode,
          responses[k],
          ctx.entrySize,
        );
      } catch (cause) {
        throw RavenError.decodeError(
          `client-PIR batch ${instanceLabel}: extract_response failed at level ${level}`,
          { cause: String(cause) },
        );
      }
      const node = plaintext.subarray(0, NODE_HASH_BYTES);
      if (node.length !== NODE_HASH_BYTES) {
        throw RavenError.decodeError(
          `client-PIR batch ${instanceLabel}: node hash truncated at level ${level} ` +
            `(${node.length} < ${NODE_HASH_BYTES})`,
        );
      }
      const cached = new Uint8Array(node);
      out[level] = cached;
      this.cache.set(keyAt(level, servedEpoch), cached);
    }

    return collectAuthPath(out);
  }

  /** Single-query path (T1 status): build query, POST to `/v1/instance/:id/query`, decrypt the response. */
  private async runClientPirQuery(
    instanceLabel: string,
    ctx: ClientPirContext,
    targetIdx: bigint,
  ): Promise<Uint8Array> {
    const route = this.route();
    const queryBundle = decodeClientPirQueryBundle(
      ctx.wasm.build_seeded_query(ctx.session, ctx.shardConfigBincode, targetIdx),
    );
    const url = `${route.endpoint}/v1/instance/${encodeURIComponent(instanceLabel)}/query`;
    // `[u16 BE schema_version][bincode]`, matching server-side read_versioned.
    const wirePayload = wrapWithSchemaEnvelope(queryBundle.queryBytes);
    this.captureRequest(url, "POST", wirePayload);
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        method: "POST",
        headers: {
          "content-type": "application/octet-stream",
          authorization: `Bearer ${route.bearerToken}`,
        },
        body: copyForBody(wirePayload),
      });
    } catch (cause) {
      throw RavenError.network(`client-PIR query ${instanceLabel}`, {
        url,
        cause: String(cause),
      });
    }
    if (res.status === 400) {
      const sv = res.headers.get(X_RAVEN_SCHEMA_VERSION);
      if (sv) {
        throw RavenError.staleAdapter(`client-PIR query ${instanceLabel}: schema mismatch`, {
          url,
          status: 400,
          serverWireSchemaVersion: parseSchemaVersion(sv) ?? undefined,
          clientWireSchemaVersion: route.schemaVersion ?? 0,
        });
      }
    }
    if (!res.ok) {
      throw RavenError.serverError(`client-PIR query ${instanceLabel}: ${res.status}`, {
        url,
        status: res.status,
      });
    }
    // extract_response expects bincode-only.
    const envelopedBytes = new Uint8Array(await res.arrayBuffer());
    const responseBytes = stripSchemaEnvelope(envelopedBytes, instanceLabel);
    const plaintext = ctx.wasm.extract_response(
      ctx.session,
      ctx.crsBincode,
      queryBundle.clientStateBincode,
      responseBytes,
      ctx.entrySize,
    );
    return plaintext;
  }

  private async postJson<T>(
    path: string,
    body: unknown,
  ): Promise<{ json: T; freshness: FreshnessHeader | null }> {
    const route = this.route();
    const bodyText = JSON.stringify(body);
    const url = `${route.endpoint}${path}`;
    this.captureRequest(url, "POST", new TextEncoder().encode(bodyText));
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${route.bearerToken}`,
        },
        body: bodyText,
      });
    } catch (cause) {
      throw RavenError.network(`POST ${path}`, { url, cause: String(cause) });
    }
    if (!res.ok) {
      throw RavenError.serverError(`${path}: ${res.status}`, { url, status: res.status });
    }
    const freshness = parseFreshnessHeader(res.headers.get(X_RAVEN_FRESHNESS));
    let json: T;
    try {
      json = (await res.json()) as T;
    } catch (cause) {
      throw RavenError.decodeError(`${path}: malformed JSON response`, {
        url,
        cause: String(cause),
      });
    }
    return { json, freshness };
  }

  private shouldFallback(freshness: FreshnessHeader | null): boolean {
    if (!freshness) return false;
    return freshness.confidence < this.confidenceFloor;
  }

  private async passthroughPoisPerList(
    listKeys: string[],
    blindedCommitmentDatas: BlindedCommitmentData[],
  ): Promise<PoisPerListResponse> {
    if (!this.upstream) {
      throw RavenError.invalidQuery("upstream fallback not configured");
    }
    const body = JSON.stringify({
      chainType: String(this.chainType),
      chainID: String(this.chainId),
      txidVersion: this.txidVersion,
      listKeys,
      blindedCommitmentDatas,
    });
    // Upstream path pois-per-list/:chainType/:chainID (api.ts:713).
    const url = `${this.upstream}/pois-per-list/${this.chainType}/${this.chainId}`;
    this.captureRequest(url, "POST", new TextEncoder().encode(body));
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      });
    } catch (cause) {
      throw RavenError.network("upstream pois-per-list", { url, cause: String(cause) });
    }
    if (!res.ok) {
      throw RavenError.serverError(`upstream pois-per-list: ${res.status}`, {
        url,
        status: res.status,
      });
    }
    return (await res.json()) as PoisPerListResponse;
  }

  private async passthroughMerkleProofs(
    listKey: string,
    blindedCommitments: string[],
  ): Promise<MerkleProof[]> {
    if (!this.upstream) {
      throw RavenError.invalidQuery("upstream fallback not configured");
    }
    const body = JSON.stringify({
      chainType: String(this.chainType),
      chainID: String(this.chainId),
      txidVersion: this.txidVersion,
      listKey,
      blindedCommitments,
    });
    // Upstream segment is `merkle-proofs`, not `poi-merkle-proofs`.
    // Upstream segment is `merkle-proofs`, not `poi-merkle-proofs` (api.ts:739).
    const url = `${this.upstream}/merkle-proofs/${this.chainType}/${this.chainId}`;
    this.captureRequest(url, "POST", new TextEncoder().encode(body));
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      });
    } catch (cause) {
      throw RavenError.network("upstream poi-merkle-proofs", { url, cause: String(cause) });
    }
    if (!res.ok) {
      throw RavenError.serverError(`upstream poi-merkle-proofs: ${res.status}`, {
        url,
        status: res.status,
      });
    }
    return (await res.json()) as MerkleProof[];
  }

  private captureRequest(url: string, method: string, body: Uint8Array): void {
    const cap = 64;
    if (this.capturedRequests.length >= cap) {
      this.capturedRequests.shift();
    }
    this.capturedRequests.push({ url, method, body });
  }
}

function collectAuthPath(levels: (Uint8Array | undefined)[]): Uint8Array[] {
  const out: Uint8Array[] = new Array(levels.length);
  for (let i = 0; i < levels.length; i += 1) {
    const v = levels[i];
    if (!v) {
      throw RavenError.decodeError(`fetchAuthPathNodes: missing sibling at level ${i}`);
    }
    out[i] = v;
  }
  return out;
}

/** Wrap a bincode body in the read_versioned envelope `[u16 BE version][body]`. */
function wrapWithSchemaEnvelope(body: Uint8Array): Uint8Array {
  const out = new Uint8Array(2 + body.length);
  out[0] = 0;
  out[1] = 1;
  out.set(body, 2);
  return out;
}

/** Inverse of `wrapWithSchemaEnvelope`; validates the prefix and throws a typed error on a missing/unexpected envelope. */
function stripSchemaEnvelope(buf: Uint8Array, label: string): Uint8Array {
  if (buf.length < 2) {
    throw RavenError.decodeError(
      `${label}: response too short for schema envelope (${buf.length})`,
    );
  }
  const envelope = (buf[0] << 8) | buf[1];
  if (envelope !== 1) {
    throw RavenError.decodeError(
      `${label}: unexpected schema envelope version ${envelope}`,
    );
  }
  return buf.subarray(2);
}

/** Encode the `Vec<SeededClientQuery>` shape `dispatch_batch` expects:
 * `[u16 BE version][u64 LE count][concatenated per-query bincode]`. */
function encodeBatchBody(queries: Uint8Array[]): Uint8Array {
  const schemaPrefix = new Uint8Array([0, 1]);
  let bodyBytes = 8;
  for (const q of queries) {
    bodyBytes += q.length;
  }
  const out = new Uint8Array(schemaPrefix.length + bodyBytes);
  out.set(schemaPrefix, 0);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  view.setUint32(schemaPrefix.length, queries.length, true);
  view.setUint32(schemaPrefix.length + 4, 0, true);
  let offset = schemaPrefix.length + 8;
  for (const q of queries) {
    out.set(q, offset);
    offset += q.length;
  }
  return out;
}

/** Decode `[u16 version][u64 LE count][{u64 LE len, bincode}*]` into one slice per query. */
function decodeBatchBody(buf: Uint8Array): Uint8Array[] {
  if (buf.length < 2 + 8) {
    throw RavenError.decodeError(`decodeBatchBody: buffer too short (${buf.length})`);
  }
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let offset = 2;
  const lenLo = view.getUint32(offset, true);
  const lenHi = view.getUint32(offset + 4, true);
  if (lenHi !== 0) {
    throw RavenError.decodeError(`decodeBatchBody: count exceeds 2^32 (hi=${lenHi})`);
  }
  offset += 8;
  const out: Uint8Array[] = [];
  for (let i = 0; i < lenLo; i += 1) {
    if (offset + 8 > buf.length) {
      throw RavenError.decodeError(
        `decodeBatchBody: truncated length prefix at element ${i} (offset ${offset}, buf ${buf.length})`,
      );
    }
    const elemLenLo = view.getUint32(offset, true);
    const elemLenHi = view.getUint32(offset + 4, true);
    if (elemLenHi !== 0) {
      throw RavenError.decodeError(
        `decodeBatchBody: element ${i} length exceeds 2^32 (hi=${elemLenHi})`,
      );
    }
    offset += 8;
    if (offset + elemLenLo > buf.length) {
      throw RavenError.decodeError(
        `decodeBatchBody: truncated element ${i} (need ${offset + elemLenLo}, have ${buf.length})`,
      );
    }
    out.push(new Uint8Array(buf.subarray(offset, offset + elemLenLo)));
    offset += elemLenLo;
  }
  return out;
}

/** `nToHex(leafIndex, UINT_256)` - 64 chars, NOT 8-char uint32 (engine/src/merkletree/merkletree.ts). */
function leafIndexToIndicesHex(leafIndex: number): string {
  return leafIndex.toString(16).padStart(64, "0");
}

/**
 * `MerkleProof` in upstream wire shape: 64-char no-prefix hex for
 * `leaf`/`elements[i]`/`root`. `root` is folded client-side from `bcHex` because the
 * adapter returns only auth-path nodes, so an empty `bcHex` would fold a root over a
 * leaf the caller never proved and is refused.
 */
function buildMerkleProof(
  leafIndex: number,
  bcHex: string,
  siblings: Uint8Array[],
): MerkleProof {
  const leaf = normalizeHex(bcHex);
  if (leaf.length !== 64) {
    throw RavenError.invalidQuery(
      `buildMerkleProof: leaf must be 64 hex chars to fold a root, got ${leaf.length}`,
    );
  }
  const elements = siblings.map((s) => bytesToHex(s));
  const root = elements.length > 0
    ? foldMerkleRoot(leaf, elements, BigInt(leafIndex))
    : leaf;
  return {
    leaf,
    elements,
    indices: leafIndexToIndicesHex(leafIndex),
    root,
  };
}

// BodyInit rejects SharedArrayBuffer-backed views, and the owning Blob would free
// the wasm-side source.
function copyForBody(src: Uint8Array): Blob {
  const buf = new ArrayBuffer(src.byteLength);
  new Uint8Array(buf).set(src);
  return new Blob([buf], { type: "application/octet-stream" });
}

function normalizeHex(hex: string): string {
  return (hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex).toLowerCase();
}

/** Decimal non-negative wire-schema version, or `null` when the value is not one. */
function parseSchemaVersion(raw: string): number | null {
  if (!/^[0-9]+$/.test(raw)) return null;
  const parsed = Number(raw);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function parseFreshnessHeader(value: string | null): FreshnessHeader | null {
  if (!value) return null;
  const out: Partial<FreshnessHeader> = {};
  for (const pair of value.trim().split(/\s+/)) {
    const eq = pair.indexOf("=");
    if (eq < 0) continue;
    const k = pair.slice(0, eq);
    const v = pair.slice(eq + 1);
    if (k === "lag_blocks") out.lagBlocks = Number(v);
    else if (k === "applied_height") out.appliedHeight = Number(v);
    else if (k === "epoch") out.epoch = Number(v);
    else if (k === "confidence") out.confidence = Number(v);
  }
  if (
    !Number.isFinite(out.lagBlocks) ||
    !Number.isFinite(out.appliedHeight) ||
    !Number.isFinite(out.epoch) ||
    !Number.isFinite(out.confidence)
  ) {
    return null;
  }
  return out as FreshnessHeader;
}

export {
  containsByteSequence,
  hexToBytes,
  bytesToHex,
  pathIndicesForLeaf,
  pathIndicesForPerListLeaf,
  TREE_DEPTH,
  PATH_RECORD_BYTES,
};
export type {
  BcToIdxMap,
  ClientPirContext,
  RavenInspireWasm,
  RavenInspireClientSession,
  ClientPirQueryBundle,
} from "./client-pir";
