import {
  type BcToIdxMap,
  type ClientPirContext,
  bytesToHex,
  containsByteSequence,
  decodeClientPirQueryBundle,
  hexToBytes,
  pathIndicesForLeaf,
  pathIndicesForPerListLeaf,
  statusByteToPOIStatus,
  validateBcHex,
  validateLeafIndex,
  validateListKeyHex,
  validateTreeNumber,
  TREE_DEPTH,
} from "./client-pir";
import { ChainRegistry, type ChainRegistryEntry } from "./chain-registry";
import { RavenError } from "./errors";
import { ImtCache, imtCacheKey } from "./imt-cache";
import { foldMerkleRoot } from "./poseidon";

export type POIStatus = "Valid" | "ShieldBlocked" | "ProofSubmitted" | "Missing";
export type BlindedCommitmentType = "Shield" | "Transact" | "Unshield";

export interface MerkleProof {
  leaf: string;
  elements: string[];
  indices: string;
  root: string;
}

/**
 * Upstream Railgun Chain shape (mirrors
 * `engine/src/models/engine-types.ts`). EVM is currently the only
 * `ChainType` member; we keep `type` numeric to match upstream wire
 * shape.
 */
export interface Chain {
  /** Upstream `ChainType` enum: 0 = EVM. */
  type: number;
  id: number;
}

/**
 * Upstream `Proof` shape (mirrors
 * `engine/src/models/prover-types.ts`). Carried through verbatim by
 * the SDK since the Raven adapter is not the proof generator.
 */
export interface Proof {
  pi_a: [string, string];
  pi_b: [[string, string], [string, string]];
  pi_c: [string, string];
}

/**
 * Constructor options for the SDK. The wallet supplies a single
 * `RavenConfig` per chain (legacy mode) or a `ChainRegistry` carrying
 * per-chain entries (multi-chain mode); when both are provided the
 * registry takes precedence.
 */
export interface RavenConfig {
  endpoint: string;
  bearerToken: string;
  /** EVM chain id this adapter serves. Required when using
   *  `ChainRegistry`; defaults to 1 (Ethereum mainnet) for the
   *  single-chain legacy constructor shape. */
  chainId?: number;
  /** Upstream Railgun `chainType` (0 = EVM). Used to build upstream
   *  PPOI passthrough URLs of the form
   *  `<upstream>/<segment>/<chainType>/<chainID>` per
   *  `private-proof-of-innocence/packages/node/src/api/api.ts`.
   *  Defaults to `0` (EVM) when omitted. */
  chainType?: number;
  /** Multi-chain routing table. When supplied the SDK consults this
   *  per request; when omitted the SDK builds an internal one-entry
   *  registry from `endpoint` + `bearerToken` + `chainId`. */
  chainRegistry?: ChainRegistry;
  upstreamFallbackEndpoint?: string;
  txidVersion?: string;
  fetchImpl?: typeof fetch;
  freshnessConfidenceFloor?: number;
  /**
   * When true (default), the SDK builds encrypted PIR queries
   * client-side via the bundled `raven-inspire-client-wasm` module
   * and POSTs only the encrypted blob. Plaintext blinded commitments
   * never cross the wire.
   */
  useClientPir?: boolean;
  /**
   * Pre-loaded client-PIR contexts, keyed by instance ID. The SDK
   * looks up the appropriate context per request.
   *
   * Mapping convention:
   * - `t1Status:<chainId>:<listKeyHex>` -> the T1 PPOI status PIR instance
   * - `t2Path:<chainId>:<listKeyHex>`   -> the T2 PPOI auth-path PIR instance
   *   (for client-side auth-path: per-list-node encoder)
   * - `t3CommitTree:<chainId>:<treeNumber>` -> the T3 commit-tree per-node PIR instance
   *
   * For backward compatibility the legacy keys
   * `t1Status:<listKeyHex>` / `t2Path:<listKeyHex>` /
   * `t3CommitTree:<treeNumber>` (without chain id) are accepted as
   * fallbacks; the SDK prefers the chain-aware key when both are present.
   */
  clientPirContexts?: Map<string, ClientPirContext>;
  /**
   * Pre-loaded BC -> idx maps, keyed by `<listKeyHex>` (legacy) or
   * `<chainId>:<listKeyHex>` (multi-chain).
   */
  bcToIdxMaps?: Map<string, BcToIdxMap>;
  /**
   * IMT cache for client-side auth-path reconstruction. Optional;
   * when omitted the SDK builds one with default settings (in-memory
   * 1024 entries; IndexedDB if `globalThis.indexedDB` is available).
   */
  imtCache?: ImtCache;
}

interface BlindedCommitmentData {
  blindedCommitment: string;
  type: BlindedCommitmentType;
}

interface PoisPerListResponse {
  // Outer key is BC hex, inner is list-key hex. Mirrors upstream
  // POIsPerListMap from
  // shared-models/src/models/proof-of-innocence.ts:153.
  [bcHex: string]: { [listKey: string]: POIStatus };
}

interface FreshnessHeader {
  lagBlocks: number;
  appliedHeight: number;
  epoch: number;
  confidence: number;
}

/**
 * Captured outbound HTTP request shape. Used by the privacy-invariant
 * test harness to assert no BC bytes appear in any body.
 */
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

  /**
   * Bounded ring of recent outbound HTTP requests. Recorded for the
   * privacy-invariant test harness and never exposed to user code
   * (mutated only via the `lastWireRequests` getter). Capacity-
   * bounded at 64 to prevent unbounded memory growth in long-running
   * wallets.
   */
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
      // Ensure the requested chain id is registered.
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

  /** Convenience: resolve to the active per-chain entry. */
  private route(): ChainRegistryEntry {
    return this.registry.resolve(this.chainId);
  }

  /**
   * Returns a snapshot of the most recent outbound HTTP requests
   * captured by this SDK instance. Test-only hook; production code
   * should not depend on the ordering or completeness of this array.
   * The returned array is a defensive copy.
   */
  lastWireRequests(): CapturedWireRequest[] {
    return this.capturedRequests.map((r) => ({
      url: r.url,
      method: r.method,
      body: r.body,
    }));
  }

  /**
   * Reset the captured wire-request ring. Useful between test cases.
   */
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

  async getMerkleProof(treeNumber: number, leafIndex: number): Promise<MerkleProof> {
    validateTreeNumber(treeNumber);
    validateLeafIndex(leafIndex);
    if (this.useClientPir) {
      return this.getMerkleProofClientPir(treeNumber, leafIndex);
    }
    const { json } = await this.postJson<MerkleProof>(
      `/v1/commit-tree/${treeNumber}/merkle-proof`,
      { leafIndex },
    );
    return json;
  }

  /**
   * Validate a list of POI merkleroots against the upstream PPOI
   * service. Mirrors upstream
   * `POINodeInterface.validatePOIMerkleroots`
   * (`engine/src/poi/poi-node-interface.ts:30-35`) and posts to
   * `<upstream>/validate-poi-merkleroots/<chainType>/<chainID>` per
   * `private-proof-of-innocence/packages/node/src/api/api.ts:786`.
   * Body field name is `poiMerkleroots` to match upstream
   * `ValidatePOIMerklerootsParams`.
   */
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

  /**
   * Submit a POI proof to upstream PPOI. Matches upstream's 9-arg
   * `POINodeInterface.submitPOI` signature
   * (`engine/src/poi/poi-node-interface.ts:37-47`):
   * `(txidVersion, chain, listKey, snarkProof, poiMerkleroots,
   * txidMerkleroot, txidMerklerootIndex, blindedCommitmentsOut,
   * railgunTxidIfHasUnshield)`.
   *
   * Posts to `<upstream>/submit-transact-proof/<chainType>/<chainID>`
   * per upstream `api.ts:653` carrying `transactProofData` in the
   * body.
   */
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

  /**
   * Submit legacy transact proofs to upstream PPOI. Mirrors upstream
   * `POINodeInterface.submitLegacyTransactProofs`
   * (`engine/src/poi/poi-node-interface.ts:49-54`) shape and posts to
   * `<upstream>/submit-legacy-transact-proofs/<chainType>/<chainID>`
   * per upstream `api.ts:673`.
   */
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

  async fetchStatusHeader(listKey: string): Promise<{ epoch: number; blocked_bcs: string[]; pending_bcs: string[] }> {
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
    return await res.json();
  }

  // ------------------------------------------------------------------
  // Client-PIR paths
  // ------------------------------------------------------------------

  /**
   * Look up a context first by chain-aware key, then fall back to
   * the legacy non-chain-aware key shape. Returning undefined defers
   * the "missing context" error to the caller (which carries the
   * domain-appropriate message).
   */
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
    // Outer key is BC hex, inner is list-key hex. Mirrors upstream
    // POIsPerListMap shape from
    // shared-models/src/models/proof-of-innocence.ts:153.
    const out: PoisPerListResponse = {};
    // Pre-init the BC slots so unknown-BC rows still surface in the
    // map even if no list yields a status. Matches the upstream
    // merge behaviour at poi-merkletree-manager.ts:215-218.
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
          // BC not present in this list yet. Mirror upstream's
          // missing-BC semantics.
          out[bcHex][lkHex] = "Missing";
          continue;
        }
        let status: POIStatus;
        try {
          const plaintext = await this.runClientPirQuery(`t1Status-${lkHex}`, ctx, BigInt(idx));
          const statusByte = plaintext.length > 0 ? plaintext[0] : 0;
          status = statusByteToPOIStatus(statusByte);
        } catch (cause) {
          // Discriminate by error class. Only network-transient
          // failures fall through to Missing. Schema mismatches,
          // server errors and decode failures propagate so the
          // wallet can retry against a fresh routing table or fall
          // back to upstream PPOI rather than silently spending on
          // unmarked BCs.
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
      // Path indices are derived from the per-list Merkle layout via
      // the WASM helper. The leaf index never crosses the wire — only
      // the encrypted PIR row queries do.
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
  ): Promise<MerkleProof> {
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
    return buildMerkleProof(leafIndex, "", siblings);
  }

  /**
   * Fetch the 16 sibling node hashes for an auth path. For each
   * `(level, idxAtLevel)` tuple we first probe the IMT cache; cache
   * misses are batched into a single `POST /v1/instance/<id>/batch`
   * request whose body carries one encrypted PIR query per missing
   * index.
   *
   * Returns a `Uint8Array[]` of length `TREE_DEPTH = 16`, indexed by
   * level (level 0 = sibling of the leaf).
   */
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
    const route = this.route();
    const out: (Uint8Array | undefined)[] = new Array(indices.length).fill(undefined);
    const missing: number[] = [];
    const epochTag = String(route.epoch ?? 0);
    const schemaVersion = route.schemaVersion ?? 0;

    // L1 (synchronous in-memory) probe.
    for (let i = 0; i < indices.length; i += 1) {
      const key = imtCacheKey({
        chainId: this.chainId,
        scope: cacheScope,
        level: i,
        idxAtLevel: indices[i],
        epochTag,
        schemaVersion,
      });
      const hit = this.cache.getSync(key);
      if (hit) {
        out[i] = hit;
      } else {
        missing.push(i);
      }
    }

    // L2 (async IndexedDB) probe for any L1 misses.
    const stillMissing: number[] = [];
    for (const i of missing) {
      const key = imtCacheKey({
        chainId: this.chainId,
        scope: cacheScope,
        level: i,
        idxAtLevel: indices[i],
        epochTag,
        schemaVersion,
      });
      const hit = await this.cache.getAsync(key);
      if (hit) {
        out[i] = hit;
      } else {
        stillMissing.push(i);
      }
    }

    if (stillMissing.length > 0) {
      // Build one encrypted PIR query per missing level + dispatch as a
      // single batch. Path-indices computation is local; only the
      // encrypted batch crosses the wire.
      const queryBundles = stillMissing.map((level) => {
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
        // 400 with `X-Raven-Schema-Version` set means a schema mismatch.
        const sv = res.headers.get(X_RAVEN_SCHEMA_VERSION);
        if (sv) {
          throw RavenError.staleAdapter(`client-PIR batch ${instanceLabel}: schema mismatch`, {
            url,
            status: 400,
            serverWireSchemaVersion: Number(sv),
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
      // Note freshness from the server response so the cache layer
      // invalidates on epoch / schema-version drift.
      const serverEpoch = res.headers.get(X_RAVEN_EPOCH);
      const serverSchema = res.headers.get(X_RAVEN_SCHEMA_VERSION);
      if (serverEpoch !== null && serverSchema !== null) {
        this.cache.noteFreshness(serverEpoch, Number(serverSchema));
      }

      const bytes = new Uint8Array(await res.arrayBuffer());
      const responses = decodeBatchBody(bytes);
      if (responses.length !== queryBundles.length) {
        throw RavenError.batchMismatch(
          `client-PIR batch ${instanceLabel}: expected ${queryBundles.length} responses, got ${responses.length}`,
          { url },
        );
      }
      for (let k = 0; k < stillMissing.length; k += 1) {
        const level = stillMissing[k];
        let plaintext: Uint8Array;
        try {
          plaintext = ctx.wasm.extract_response(
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
        // The PerNodeEncoder row is exactly 32 bytes per node; the
        // first 32 bytes of the plaintext is the node hash.
        const node = plaintext.subarray(0, NODE_HASH_BYTES);
        if (node.length !== NODE_HASH_BYTES) {
          throw RavenError.decodeError(
            `client-PIR batch ${instanceLabel}: node hash truncated at level ${level} ` +
              `(${node.length} < ${NODE_HASH_BYTES})`,
          );
        }
        const cached = new Uint8Array(node);
        out[level] = cached;
        const key = imtCacheKey({
          chainId: this.chainId,
          scope: cacheScope,
          level,
          idxAtLevel: indices[level],
          epochTag,
          schemaVersion,
        });
        this.cache.set(key, cached);
      }
    }

    const final: Uint8Array[] = new Array(indices.length);
    for (let i = 0; i < indices.length; i += 1) {
      const v = out[i];
      if (!v) {
        // Should be impossible: every level was either a cache hit
        // or filled from the batch response above.
        throw RavenError.decodeError(`fetchAuthPathNodes: missing sibling at level ${i}`);
      }
      final[i] = v;
    }
    return final;
  }

  /**
   * Single-query path used by the T1 status flow. Wraps the wasm
   * query builder + POST to `/v1/instance/:id/query` and decrypts
   * the response.
   */
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
    this.captureRequest(url, "POST", queryBundle.queryBytes);
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        method: "POST",
        headers: {
          "content-type": "application/octet-stream",
          authorization: `Bearer ${route.bearerToken}`,
        },
        body: copyForBody(queryBundle.queryBytes),
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
          serverWireSchemaVersion: Number(sv),
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
    const responseBytes = new Uint8Array(await res.arrayBuffer());
    const plaintext = ctx.wasm.extract_response(
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
    // Upstream path: pois-per-list/:chainType/:chainID per
    // private-proof-of-innocence/packages/node/src/api/api.ts:713.
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
    // Upstream literal segment is `merkle-proofs` (NOT
    // `poi-merkle-proofs`) per
    // private-proof-of-innocence/packages/node/src/api/api.ts:739.
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

/**
 * Encode a batch body as a length-prefixed sequence of bincode-shaped
 * `Vec<SeededClientQuery>`. The HTTP layer already speaks
 * `read_versioned`+ versioned-bincode of `Vec<S::Query>`; this encoder
 * mirrors that layout: u16 schema version + u64 LE length prefix +
 * concatenated query bytes.
 *
 * NOTE: we hand the server *the same* per-query bincode-encoded
 * `SeededClientQuery` shape it would receive on `/v1/instance/:id/query`,
 * concatenated by a u64 LE length prefix. This is the
 * `bincode::serialize(&Vec<SeededClientQuery>)` shape the
 * `dispatch_batch::<S>` worker expects.
 */
function encodeBatchBody(queries: Uint8Array[]): Uint8Array {
  // 2 bytes BE schema version (matches WIRE_SCHEMA_VERSION = 1) +
  // 8 bytes LE length prefix + concatenated bodies.
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

/**
 * Decode the server's batch reply: u16 schema version + u64 LE length
 * + concatenated `bincode(ServerResponse)` blobs. The SDK doesn't try
 * to parse the inner blobs structurally; it slices them into one
 * `Uint8Array` per query and hands each to `extract_response`.
 *
 * The server emits responses delimited by a per-element u64 LE length
 * prefix (since `ServerResponse` is variable-length).
 */
function decodeBatchBody(buf: Uint8Array): Uint8Array[] {
  if (buf.length < 2 + 8) {
    throw RavenError.decodeError(`decodeBatchBody: buffer too short (${buf.length})`);
  }
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  // Skip 2-byte schema version prefix.
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

/**
 * Build a `MerkleProof` value from the leaf index + the 16 sibling
 * node hashes.
 *
 * Wire-format conventions (mirrors upstream
 * `engine/src/merkletree/merkletree.ts:128-160`):
 *
 * - `leaf`, `elements[i]`, `root` — 64-char no-`0x`-prefix hex.
 * - `indices` — `nToHex(BigInt(leafIndex), UINT_256)` = 64-char
 *   no-`0x`-prefix hex (NOT 8-char uint32 hex). Bit `i` of the
 *   indices value is the path bit at level `i`: bit set means the
 *   leaf at that level is the right child (matches upstream
 *   `merkletree/merkle-proof.ts:32-49 verifyMerkleProof`).
 * - `root` is computed by folding `leaf` with `siblings` via
 *   Poseidon `hashLeftRight` — the PIR adapter does NOT return the
 *   on-chain root, only the auth-path nodes, so the SDK must
 *   reconstruct it client-side. Upstream's `getMerkleProof` reads
 *   the root from a separately-stored top-level node which we don't
 *   have access to via the PIR adapter.
 */
function buildMerkleProof(
  leafIndex: number,
  bcHex: string,
  siblings: Uint8Array[],
): MerkleProof {
  const elements = siblings.map((s) => bytesToHex(s));
  const leaf = bcHex !== "" ? normalizeHex(bcHex) : "0".repeat(64);
  // Compute the verifiable root by folding leaf with siblings using
  // Poseidon, matching upstream's verifyMerkleProof shape.
  const root = elements.length > 0
    ? foldMerkleRoot(leaf, elements, BigInt(leafIndex))
    : leaf;
  // Upstream nToHex(BigInt(index), UINT_256) -> 64-char no-prefix
  // hex. NOT 8-char uint32.
  const indicesHex = leafIndex.toString(16).padStart(64, "0");
  return {
    leaf,
    elements,
    indices: indicesHex,
    root,
  };
}

/**
 * Copy a Uint8Array into a new ArrayBuffer suitable for use as a
 * `BodyInit`. Two reasons: (1) BodyInit's union rejects
 * `ArrayBufferLike` (which includes SharedArrayBuffer), and (2) the
 * Blob owns the copy so wasm-side memory backing the source is safe
 * to free after the call.
 */
function copyForBody(src: Uint8Array): Blob {
  const buf = new ArrayBuffer(src.byteLength);
  new Uint8Array(buf).set(src);
  return new Blob([buf], { type: "application/octet-stream" });
}

function normalizeHex(hex: string): string {
  return (hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex).toLowerCase();
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
    out.lagBlocks == null ||
    out.appliedHeight == null ||
    out.epoch == null ||
    out.confidence == null
  ) {
    return null;
  }
  return out as FreshnessHeader;
}

// Re-export client-PIR primitives + helper utilities so consumers can
// pre-load contexts and inspect captured wire requests in tests.
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
