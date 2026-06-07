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

/** Upstream Railgun Chain shape (engine/src/models/engine-types.ts); numeric `type` matches upstream wire shape. */
export interface Chain {
  /** Upstream `ChainType` enum: 0 = EVM. */
  type: number;
  id: number;
}

/** Upstream `Proof` shape (engine/src/models/prover-types.ts), carried verbatim. */
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
  /** Upstream Railgun `chainType` (0 = EVM); used in PPOI passthrough URLs `<upstream>/<segment>/<chainType>/<chainID>`. */
  chainType?: number;
  /** Multi-chain routing table; when omitted an internal one-entry registry is built. */
  chainRegistry?: ChainRegistry;
  upstreamFallbackEndpoint?: string;
  txidVersion?: string;
  fetchImpl?: typeof fetch;
  freshnessConfidenceFloor?: number;
  /** When true (default), PIR queries are built client-side; plaintext blinded commitments never cross the wire. */
  useClientPir?: boolean;
  /**
   * Pre-loaded client-PIR contexts. Chain-aware keys are preferred;
   * legacy non-chain-aware keys are accepted as fallbacks:
   * - `t1Status:<chainId>:<listKeyHex>` / `t1Status:<listKeyHex>`
   * - `t2Path:<chainId>:<listKeyHex>` / `t2Path:<listKeyHex>`
   * - `t3CommitTree:<chainId>:<treeNumber>` / `t3CommitTree:<treeNumber>`
   */
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

  // Bounded ring (cap 64) of recent outbound requests for the privacy-invariant test harness.
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

  /** Defensive-copy snapshot of recent captured requests. Test-only; ordering/completeness not guaranteed. */
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
   * Validate POI merkleroots against upstream PPOI. Mirrors
   * `POINodeInterface.validatePOIMerkleroots` (engine/src/poi/poi-node-interface.ts:30-35);
   * posts to `<upstream>/validate-poi-merkleroots/<chainType>/<chainID>`
   * (api.ts:786). Body field `poiMerkleroots` matches upstream `ValidatePOIMerklerootsParams`.
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
   * `POINodeInterface.submitPOI` (engine/src/poi/poi-node-interface.ts:37-47);
   * posts to `<upstream>/submit-transact-proof/<chainType>/<chainID>`
   * (api.ts:653) carrying `transactProofData`.
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
   * Submit legacy transact proofs to upstream PPOI. Mirrors
   * `POINodeInterface.submitLegacyTransactProofs` (engine/src/poi/poi-node-interface.ts:49-54);
   * posts to `<upstream>/submit-legacy-transact-proofs/<chainType>/<chainID>` (api.ts:673).
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

  // Chain-aware key first, then legacy non-chain-aware fallback; undefined defers the error to the caller.
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
    // Pre-init BC slots so unknown-BC rows still surface; matches upstream merge (poi-merkletree-manager.ts:215-218).
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
          const plaintext = await this.runClientPirQuery(`t1Status-${lkHex}`, ctx, BigInt(idx));
          const statusByte = plaintext.length > 0 ? plaintext[0] : 0;
          status = statusByteToPOIStatus(statusByte);
        } catch (cause) {
          // Only transient network failures degrade to Missing; schema/server/decode errors propagate so
          // the wallet retries or falls back rather than spending on unmarked BCs.
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
      // Leaf index never crosses the wire; only the encrypted PIR row queries do.
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
   * Fetch the TREE_DEPTH sibling node hashes for an auth path, indexed by
   * level (0 = sibling of the leaf). Cache misses batch into a single
   * `POST /v1/instance/<id>/batch` of encrypted PIR queries.
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

    // L1 synchronous in-memory probe.
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

    // L2 async IndexedDB probe for L1 misses.
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
      // One encrypted query per missing level, dispatched as one batch; only the encrypted batch crosses the wire.
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
        // 400 with X-Raven-Schema-Version set signals a schema mismatch.
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
      // Cache layer invalidates on epoch / schema-version drift.
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
        // PerNodeEncoder row is one NODE_HASH_BYTES node hash.
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
        // Unreachable: every level is a cache hit or filled from the batch above.
        throw RavenError.decodeError(`fetchAuthPathNodes: missing sibling at level ${i}`);
      }
      final[i] = v;
    }
    return final;
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
    // Wire-schema envelope `[u16 BE schema_version][bincode]` mirrors server-side read_versioned; without it the server returns 400.
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
    // Strip the 2-byte envelope; extract_response expects bincode-only.
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

/** Wrap a bincode body with the server-side read_versioned envelope `[u16 BE schema_version][body]`; without it `/v1/instance/:id/query` returns 400. */
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

/** Encode `[u16 BE schema_version][u64 LE count][concatenated per-query bincode]`, the `Vec<SeededClientQuery>` shape `dispatch_batch` expects. */
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

/** Decode `[u16 schema_version][u64 LE count][per-element u64 LE len + bincode(ServerResponse)]` into one slice per query. */
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

/**
 * Build a `MerkleProof` matching upstream wire shape (engine/src/merkletree/merkletree.ts:128-160):
 * `leaf`/`elements[i]`/`root` are 64-char no-prefix hex; `indices` is
 * `nToHex(leafIndex, UINT_256)` (64-char, NOT 8-char uint32), bit `i`
 * set meaning right child at level `i`. The adapter returns only
 * auth-path nodes, so `root` is folded client-side.
 */
function buildMerkleProof(
  leafIndex: number,
  bcHex: string,
  siblings: Uint8Array[],
): MerkleProof {
  const elements = siblings.map((s) => bytesToHex(s));
  const leaf = bcHex !== "" ? normalizeHex(bcHex) : "0".repeat(64);
  const root = elements.length > 0
    ? foldMerkleRoot(leaf, elements, BigInt(leafIndex))
    : leaf;
  const indicesHex = leafIndex.toString(16).padStart(64, "0");
  return {
    leaf,
    elements,
    indices: indicesHex,
    root,
  };
}

// Owned copy: BodyInit rejects SharedArrayBuffer-backed views, and the Blob owning it frees the wasm-side source.
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
