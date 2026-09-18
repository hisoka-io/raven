import {
  type ClientPirContext,
  decodeClientPirQueryBundle,
} from "./client-pir";
import {
  type BcToIdxMap,
  type POIStatus,
  bytesToHex,
  containsByteSequence,
  decodeStatusRow,
  hexToBytes,
  pathIndicesForLeaf,
  pathIndicesForPerListLeaf,
  validateBcHex,
  validateLeafIndex,
  validateListKeyHex,
  validateTreeNumber,
  TREE_DEPTH,
} from "./poi-pir";
import { drawPaddedSlots, MAX_BATCH_SIZE } from "./batch-ladder";
import {
  buildFanoutCoverPlan,
  recoverRealFanoutResponses,
  type FanoutCoverPlan,
} from "./fanout-cover";
import { ChainRegistry, type ChainRegistryEntry } from "./chain-registry";
import { RavenError, type StaleDataContext } from "./errors";
import { ImtCache, imtCacheKey, imtCacheScopeKey } from "./imt-cache";
import { foldMerkleRoot } from "./poseidon";

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

/** Upstream legacy transact proof payload, carried verbatim. */
export interface LegacyTransactProofData {
  txidIndex: string;
  npk: string;
  value: string;
  tokenHash: string;
  blindedCommitment: string;
}

interface RavenConfigBase {
  endpoint: string;
  bearerToken: string;
  /** EVM chain id this adapter serves; defaults to 1 (mainnet). */
  chainId?: number;
  /** Upstream `chainType` (0 = EVM); a path segment in PPOI passthrough URLs. */
  chainType?: number;
  /** Multi-chain routing table; when omitted an internal one-entry registry is built. */
  chainRegistry?: ChainRegistry;
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

/** Private stale-response policy; upstream disclosure is explicit and requires an endpoint. */
export type PrivateStalePolicy =
  | {
      readonly privateStalePolicy?: "refuse";
      readonly upstreamFallbackEndpoint?: string;
    }
  | {
      readonly privateStalePolicy: "allow-upstream-disclosure";
      readonly upstreamFallbackEndpoint: string;
    };

/** SDK constructor options; omitted private-stale policy fails closed. */
export type RavenConfig = RavenConfigBase & PrivateStalePolicy;

export interface BlindedCommitmentData {
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

type PrivateFreshness =
  | { readonly kind: "valid"; readonly value: FreshnessHeader }
  | { readonly kind: "absent" }
  | { readonly kind: "malformed" };

interface PrivateQueryBatchResult {
  plaintexts: Uint8Array[];
  freshness: PrivateFreshness;
}

interface AuthPathResult {
  nodes: Uint8Array[];
  freshness: PrivateFreshness;
}

interface SessionLease {
  readonly key: string;
  readonly handshake: Promise<bigint>;
}

class SessionHandleRefused extends Error {
  constructor(readonly url: string) {
    super("server refused the installed session handle");
  }
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
const WIRE_SCHEMA_VERSION = 6;
const MAX_FANOUT_BODY_BYTES = 8 * 1024 * 1024;
const DEFAULT_TXID_VERSION = "V2_PoseidonMerkle";
const DEFAULT_CONFIDENCE_FLOOR = 0.5;
const DEFAULT_CHAIN_ID = 1;
const DEFAULT_CHAIN_TYPE = 0; // upstream `ChainType.EVM`
const NODE_HASH_BYTES = 32;
const PATH_RECORD_BYTES = TREE_DEPTH * NODE_HASH_BYTES;
/** Epoch tag before the instance has ever reported one; never collides with a real epoch. */
const UNOBSERVED_EPOCH = "";
const AUTH_PATH_ATTEMPTS = 2;
const SESSION_QUERY_ATTEMPTS = 2;

type UpstreamJsonRpcMethod =
  | "ppoi_pois_per_list"
  | "ppoi_merkle_proofs"
  | "ppoi_validate_poi_merkleroots"
  | "ppoi_submit_transact_proof"
  | "ppoi_submit_legacy_transact_proofs";

export class RavenPOINodeInterface {
  private readonly chainId: number;
  private readonly chainType: number;
  private readonly registry: ChainRegistry;
  private readonly upstream: string | undefined;
  private readonly privateStalePolicy: "refuse" | "allow-upstream-disclosure";
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
  private readonly sessionHandshakes = new Map<string, Promise<bigint>>();
  private readonly clientPirIds = new Map<string, string>();
  private nextUpstreamRequestId = 1;

  constructor(config: RavenConfig) {
    this.chainId = config.chainId ?? DEFAULT_CHAIN_ID;
    this.chainType = config.chainType ?? DEFAULT_CHAIN_TYPE;
    this.upstream = config.upstreamFallbackEndpoint?.replace(/\/$/, "");
    this.privateStalePolicy = config.privateStalePolicy ?? "refuse";
    this.txidVersion = config.txidVersion ?? DEFAULT_TXID_VERSION;
    this.fetchImpl = config.fetchImpl ?? fetch;
    this.confidenceFloor = config.freshnessConfidenceFloor ?? DEFAULT_CONFIDENCE_FLOOR;
    if (
      !Number.isFinite(this.confidenceFloor) ||
      this.confidenceFloor < 0 ||
      this.confidenceFloor > 1
    ) {
      throw RavenError.invalidQuery(
        `freshnessConfidenceFloor must be finite and within [0,1], got ${this.confidenceFloor}`,
      );
    }
    this.useClientPir = config.useClientPir ?? true;
    this.clientPirContexts = config.clientPirContexts ?? new Map();
    this.bcToIdxMaps = config.bcToIdxMaps ?? new Map();
    this.cache = config.imtCache ?? new ImtCache();

    if (
      this.privateStalePolicy !== "refuse" &&
      this.privateStalePolicy !== "allow-upstream-disclosure"
    ) {
      throw RavenError.invalidQuery(
        `privateStalePolicy must be "refuse" or "allow-upstream-disclosure"`,
      );
    }
    if (this.privateStalePolicy === "allow-upstream-disclosure" && !this.upstream) {
      throw RavenError.invalidQuery(
        "privateStalePolicy allow-upstream-disclosure requires upstreamFallbackEndpoint",
      );
    }

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

  isActive(chain: Chain): boolean {
    return chain.type === this.chainType && this.registry.knownChainIds().includes(chain.id);
  }

  async isRequired(chain: Chain): Promise<boolean> {
    return this.isActive(chain);
  }

  private requireConfiguredInvocation(txidVersion: string, chain: Chain, operation: string): void {
    if (txidVersion !== this.txidVersion) {
      throw RavenError.invalidQuery(
        `${operation}: txidVersion ${txidVersion} does not match configured ${this.txidVersion}`,
      );
    }
    if (!this.isActive(chain)) {
      throw RavenError.invalidQuery(
        `${operation}: chain ${chain.type}:${chain.id} is not active on this interface`,
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
      body: new Uint8Array(r.body),
    }));
  }

  /** Reset the captured wire-request ring. */
  resetWireCapture(): void {
    this.capturedRequests.length = 0;
  }

  /** Query one encrypted local index across real and cover shards.
   *
   * The request uploads one seeded query, retargets its clear shard marker to an independently
   * sampled wire slot, and returns only caller-real plaintext rows in caller shard order.
   */
  async queryClientPirFanout(
    instanceLabel: string,
    ctx: ClientPirContext,
    targetIndex: bigint,
    realShardIds: readonly number[],
    shardCount: number,
  ): Promise<Uint8Array[]> {
    if (instanceLabel.length === 0) {
      throw RavenError.invalidQuery("client-PIR fanout instance label must not be empty");
    }
    if (
      typeof targetIndex !== "bigint" ||
      targetIndex < 0n ||
      targetIndex > 0xffff_ffff_ffff_ffffn
    ) {
      throw RavenError.invalidQuery(`client-PIR fanout target index is not a u64: ${targetIndex}`);
    }
    return this.withClientPirSessionRetry(
      instanceLabel,
      ctx,
      async () => {
        const plan = buildFanoutCoverPlan(realShardIds, shardCount, MAX_BATCH_SIZE);
        const queryBundle = decodeClientPirQueryBundle(
          ctx.wasm.build_seeded_query(ctx.session, ctx.shardConfigBincode, targetIndex),
        );
        if (typeof ctx.wasm.retarget_seeded_query_shard !== "function") {
          throw RavenError.staleAdapter(
            "client-PIR fanout requires a WASM build with typed seeded-query retargeting",
          );
        }
        const queryBytes = ctx.wasm.retarget_seeded_query_shard(
          queryBundle.queryBytes,
          plan.nominalShardId,
        );
        const requestBody = encodeFanoutRequest(queryBytes, plan);
        const route = this.route();
        const url = `${route.endpoint}/v1/instance/${encodeURIComponent(instanceLabel)}/fanout`;
        this.captureRequest(url, "POST", requestBody);
        const response = await this.postClientPirRequest(
          instanceLabel,
          url,
          requestBody,
          "fanout",
        );
        const freshness = parsePrivateFreshnessHeader(response.headers.get(X_RAVEN_FRESHNESS));
        void this.privateFreshnessAction(freshness, "fanout");
        const responseBytes = new Uint8Array(await response.arrayBuffer());
        void stripSchemaEnvelope(responseBytes, instanceLabel);
        const wireResponses = decodeBatchBody(responseBytes);
        const realResponses = recoverRealFanoutResponses(plan, wireResponses);
        return realResponses.map((serverResponse, realPosition) => {
          try {
            return ctx.wasm.extract_response(
              ctx.session,
              ctx.crsBincode,
              queryBundle.clientStateBincode,
              serverResponse,
              ctx.entrySize,
            );
          } catch (cause) {
            throw RavenError.decodeError(
              `client-PIR fanout ${instanceLabel}: extract_response failed at real position ${realPosition}`,
              { url, cause: String(cause) },
            );
          }
        });
      },
      "fanout",
    );
  }

  async getPOIsPerList(
    txidVersion: string,
    chain: Chain,
    listKeys: string[],
    blindedCommitmentDatas: BlindedCommitmentData[],
  ): Promise<PoisPerListResponse>;
  async getPOIsPerList(
    listKeys: string[],
    blindedCommitmentDatas: BlindedCommitmentData[],
  ): Promise<PoisPerListResponse>;
  async getPOIsPerList(
    txidVersionOrListKeys: string | string[],
    chainOrCommitments: Chain | BlindedCommitmentData[],
    upstreamListKeys?: string[],
    upstreamCommitments?: BlindedCommitmentData[],
  ): Promise<PoisPerListResponse> {
    const upstreamShape = typeof txidVersionOrListKeys === "string";
    if (upstreamShape) {
      this.requireConfiguredInvocation(
        txidVersionOrListKeys,
        chainOrCommitments as Chain,
        "getPOIsPerList",
      );
    }
    const listKeys = upstreamShape ? upstreamListKeys : txidVersionOrListKeys;
    const blindedCommitmentDatas = upstreamShape
      ? upstreamCommitments
      : (chainOrCommitments as BlindedCommitmentData[]);
    if (!listKeys || !blindedCommitmentDatas) {
      throw RavenError.invalidQuery("getPOIsPerList: missing list keys or commitments");
    }
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
    txidVersion: string,
    chain: Chain,
    listKey: string,
    blindedCommitments: string[],
  ): Promise<MerkleProof[]>;
  async getPOIMerkleProofs(
    listKey: string,
    blindedCommitments: string[],
  ): Promise<MerkleProof[]>;
  async getPOIMerkleProofs(
    txidVersionOrListKey: string,
    chainOrCommitments: Chain | string[],
    upstreamListKey?: string,
    upstreamCommitments?: string[],
  ): Promise<MerkleProof[]> {
    const upstreamShape = !Array.isArray(chainOrCommitments);
    if (upstreamShape) {
      this.requireConfiguredInvocation(
        txidVersionOrListKey,
        chainOrCommitments,
        "getPOIMerkleProofs",
      );
    }
    const listKey = upstreamShape ? upstreamListKey : txidVersionOrListKey;
    const blindedCommitments = upstreamShape
      ? upstreamCommitments
      : chainOrCommitments;
    if (!listKey || !blindedCommitments) {
      throw RavenError.invalidQuery("getPOIMerkleProofs: missing list key or commitments");
    }
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
    txidVersion: string,
    chain: Chain,
    listKey: string,
    poiMerkleroots: string[],
  ): Promise<boolean>;
  async validatePOIMerkleroots(listKey: string, poiMerkleroots: string[]): Promise<boolean>;
  async validatePOIMerkleroots(
    txidVersionOrListKey: string,
    chainOrRoots: Chain | string[],
    upstreamListKey?: string,
    upstreamRoots?: string[],
  ): Promise<boolean> {
    const upstreamShape = !Array.isArray(chainOrRoots);
    if (upstreamShape) {
      this.requireConfiguredInvocation(
        txidVersionOrListKey,
        chainOrRoots,
        "validatePOIMerkleroots",
      );
    }
    const listKey = upstreamShape ? upstreamListKey : txidVersionOrListKey;
    const poiMerkleroots = upstreamShape ? upstreamRoots : chainOrRoots;
    if (!listKey || !poiMerkleroots) {
      throw RavenError.invalidQuery("validatePOIMerkleroots: missing list key or roots");
    }
    if (!this.upstream) {
      throw RavenError.invalidQuery(
        "validatePOIMerkleroots requires upstreamFallbackEndpoint",
      );
    }
    const verdict = await this.upstreamJsonRpc<unknown>("ppoi_validate_poi_merkleroots", {
      chainType: String(this.chainType),
      chainID: String(this.chainId),
      txidVersion: this.txidVersion,
      listKey,
      poiMerkleroots,
    });
    if (typeof verdict !== "boolean") {
      throw RavenError.decodeError(
        `validatePOIMerkleroots: upstream response must be a boolean verdict, got ${typeof verdict}`,
        { url: this.upstream },
      );
    }
    return verdict;
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
    await this.upstreamJsonRpc<unknown>("ppoi_submit_transact_proof", {
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
  }

  // `POINodeInterface.submitLegacyTransactProofs` (engine/src/poi/poi-node-interface.ts:49-54);
  /** Mirrors upstream `POINodeInterface.submitLegacyTransactProofs`. */
  async submitLegacyTransactProofs(
    txidVersion: string,
    chain: Chain,
    listKeys: string[],
    legacyTransactProofDatas: LegacyTransactProofData[],
  ): Promise<void>;
  async submitLegacyTransactProofs(
    listKeys: string[],
    legacyTransactProofDatas: LegacyTransactProofData[],
  ): Promise<void>;
  async submitLegacyTransactProofs(
    txidVersionOrListKeys: string | string[],
    chainOrProofs: Chain | LegacyTransactProofData[],
    upstreamListKeys?: string[],
    upstreamProofs?: LegacyTransactProofData[],
  ): Promise<void> {
    const upstreamShape = typeof txidVersionOrListKeys === "string";
    if (upstreamShape) {
      this.requireConfiguredInvocation(
        txidVersionOrListKeys,
        chainOrProofs as Chain,
        "submitLegacyTransactProofs",
      );
    }
    const listKeys = upstreamShape ? upstreamListKeys : txidVersionOrListKeys;
    const legacyTransactProofDatas = upstreamShape
      ? upstreamProofs
      : (chainOrProofs as LegacyTransactProofData[]);
    if (!listKeys || !legacyTransactProofDatas) {
      throw RavenError.invalidQuery(
        "submitLegacyTransactProofs: missing list keys or legacy proof data",
      );
    }
    if (!this.upstream) {
      throw RavenError.invalidQuery("submitLegacyTransactProofs requires upstreamFallbackEndpoint");
    }
    await this.upstreamJsonRpc<unknown>("ppoi_submit_legacy_transact_proofs", {
      chainType: String(this.chainType),
      chainID: String(this.chainId),
      txidVersion: this.txidVersion,
      listKeys,
      legacyTransactProofDatas,
    });
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
      const members: {
        commitmentData: BlindedCommitmentData;
        bcHex: string;
        idx: number;
      }[] = [];
      for (const commitmentData of blindedCommitmentDatas) {
        const bcHex = normalizeHex(commitmentData.blindedCommitment);
        const idx = bcMap.get(bcHex);
        if (idx === undefined) {
          out[bcHex][lkHex] = "Missing";
        } else {
          members.push({ commitmentData, bcHex, idx });
        }
      }

      const chunkCount = Math.max(1, Math.ceil(members.length / MAX_BATCH_SIZE));
      for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
        const chunk = members.slice(
          chunkIndex * MAX_BATCH_SIZE,
          (chunkIndex + 1) * MAX_BATCH_SIZE,
        );
        try {
          const privateReply = await this.runClientPirQueryBatch(
            `t1Status-${lkHex}`,
            ctx,
            chunk.map(({ idx }) => idx),
          );
          if (this.privateFreshnessAction(privateReply.freshness, "t1-status") === "fallback") {
            // This deliberately reveals the exact BC/list to upstream. Returning a stale
            // spend-authorizing verdict would preserve lookup privacy at the cost of correctness.
            const fallback = await this.passthroughPoisPerList(
              [listKey],
              chunk.map(({ commitmentData }) => commitmentData),
            );
            for (const { bcHex } of chunk) {
              const fallbackStatus = fallback[bcHex]?.[lkHex];
              if (!fallbackStatus) {
                throw RavenError.decodeError(
                  `upstream pois-per-list omitted BC ${bcHex} on list ${lkHex}`,
                );
              }
              out[bcHex][lkHex] = fallbackStatus;
            }
          } else {
            for (let slot = 0; slot < chunk.length; slot += 1) {
              const { bcHex, idx } = chunk[slot];
              const label = `client-PIR t1Status-${lkHex} idx ${idx}`;
              out[bcHex][lkHex] = decodeStatusRow(
                privateReply.plaintexts[slot],
                bcHex,
                label,
              );
            }
          }
        } catch (cause) {
          if (cause instanceof RavenError && cause.kind === "Network") {
            for (const { bcHex } of chunk) {
              out[bcHex][lkHex] = "Unreachable";
            }
          } else {
            throw cause;
          }
        }
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
      const privateReply = await this.fetchAuthPathNodes(
        `t2Path-${lkHex}`,
        ctx,
        indices,
        `list-${lkHex}`,
      );
      if (this.privateFreshnessAction(privateReply.freshness, "t2-auth-path") === "fallback") {
        // This deliberately reveals the exact BC/list to upstream. The alternative is to
        // return an auth path whose freshness is below the operator-selected confidence floor.
        const fallback = await this.passthroughMerkleProofs(listKey, [bc]);
        const proof = fallback[0];
        if (!proof) {
          throw RavenError.decodeError(
            `upstream merkle-proofs omitted BC ${bcHex} on list ${lkHex}`,
          );
        }
        out.push(proof);
      } else {
        out.push(buildMerkleProof(idx, bcHex, privateReply.nodes));
      }
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
    const { nodes: siblings } = await this.fetchAuthPathNodes(
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
  ): Promise<AuthPathResult> {
    if (indices.length !== TREE_DEPTH) {
      throw RavenError.batchMismatch(
        `fetchAuthPathNodes: expected ${TREE_DEPTH} indices, got ${indices.length}`,
      );
    }
    for (let attempt = 0; attempt < AUTH_PATH_ATTEMPTS; attempt += 1) {
      const assembled = await this.withClientPirSessionRetry(instanceLabel, ctx, () =>
        this.assembleAuthPath(instanceLabel, ctx, indices, cacheScope),
      );
      if (assembled) return assembled;
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
  ): Promise<AuthPathResult | undefined> {
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
    const queryBundles = drawPaddedSlots(queryLevels).map((level) => {
      const target = BigInt(indices[level]);
      return decodeClientPirQueryBundle(
        ctx.wasm.build_seeded_query(ctx.session, ctx.shardConfigBincode, target),
      );
    });
    const batchBody = encodeBatchBody(queryBundles.map((b) => b.queryBytes));
    const url = `${route.endpoint}/v1/instance/${encodeURIComponent(instanceLabel)}/batch`;
    this.captureRequest(url, "POST", batchBody);
    const res = await this.postClientPirRequest(instanceLabel, url, batchBody, "batch");
    const freshness = parsePrivateFreshnessHeader(res.headers.get(X_RAVEN_FRESHNESS));
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
        { url, status: res.status, clientWireSchemaVersion: WIRE_SCHEMA_VERSION },
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
    void stripSchemaEnvelope(bytes, instanceLabel);
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

    return { nodes: collectAuthPath(out), freshness };
  }

  /** T1 status path: build, pad, and decrypt one `/batch` request. */
  private async runClientPirQueryBatch(
    instanceLabel: string,
    ctx: ClientPirContext,
    targetIndices: readonly number[],
  ): Promise<PrivateQueryBatchResult> {
    return this.withClientPirSessionRetry(instanceLabel, ctx, async () => {
      const route = this.route();
      const realTargets = targetIndices.length > 0 ? targetIndices : [0];
      const queryBundles = drawPaddedSlots(realTargets).map((targetIdx) =>
        decodeClientPirQueryBundle(
          ctx.wasm.build_seeded_query(ctx.session, ctx.shardConfigBincode, BigInt(targetIdx)),
        ),
      );
      const batchBody = encodeBatchBody(queryBundles.map(({ queryBytes }) => queryBytes));
      const url = `${route.endpoint}/v1/instance/${encodeURIComponent(instanceLabel)}/batch`;
      this.captureRequest(url, "POST", batchBody);
      const res = await this.postClientPirRequest(instanceLabel, url, batchBody, "batch");
      const freshness = parsePrivateFreshnessHeader(res.headers.get(X_RAVEN_FRESHNESS));
      const responseBytes = new Uint8Array(await res.arrayBuffer());
      void stripSchemaEnvelope(responseBytes, instanceLabel);
      const responses = decodeBatchBody(responseBytes);
      if (responses.length !== queryBundles.length) {
        throw RavenError.batchMismatch(
          `client-PIR batch ${instanceLabel}: expected ${queryBundles.length} responses, got ${responses.length}`,
          { url },
        );
      }
      const plaintexts = realTargets.map((_targetIdx, slot) =>
        ctx.wasm.extract_response(
          ctx.session,
          ctx.crsBincode,
          queryBundles[slot].clientStateBincode,
          responses[slot],
          ctx.entrySize,
        ),
      );
      return { plaintexts, freshness };
    });
  }

  private async withClientPirSessionRetry<T>(
    instanceLabel: string,
    ctx: ClientPirContext,
    query: () => Promise<T>,
    operation: "batch" | "fanout" = "batch",
  ): Promise<T> {
    for (let attempt = 0; attempt < SESSION_QUERY_ATTEMPTS; attempt += 1) {
      const lease = await this.ensureClientPirSession(instanceLabel, ctx);
      try {
        return await query();
      } catch (cause) {
        if (!(cause instanceof SessionHandleRefused)) throw cause;
        this.invalidateClientPirSession(lease);
        if (attempt + 1 === SESSION_QUERY_ATTEMPTS) {
          throw RavenError.serverError(
            `client-PIR ${operation} ${instanceLabel}: replacement session handle was refused`,
            { url: cause.url, status: 409 },
          );
        }
      }
    }
    throw RavenError.serverError(
      `client-PIR ${operation} ${instanceLabel}: session retry exhausted`,
      { status: 409 },
    );
  }

  private async postClientPirRequest(
    instanceLabel: string,
    url: string,
    requestBody: Uint8Array,
    operation: "batch" | "fanout",
  ): Promise<Response> {
    const route = this.route();
    const clientId = this.clientPirClientId(instanceLabel);
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method: "POST",
        headers: {
          "content-type": "application/octet-stream",
          authorization: `Bearer ${route.bearerToken}`,
          "x-raven-client-id": clientId,
        },
        body: copyForBody(requestBody),
      });
    } catch (cause) {
      throw RavenError.network(`client-PIR ${operation} ${instanceLabel}`, {
        url,
        cause: String(cause),
      });
    }
    if (response.status === 409) {
      throw new SessionHandleRefused(url);
    }
    if (response.status === 400) {
      const serverVersion = parseSchemaVersion(
        response.headers.get(X_RAVEN_SCHEMA_VERSION)?.trim() ?? "",
      );
      if (
        response.headers.has(X_RAVEN_SCHEMA_VERSION) &&
        serverVersion !== WIRE_SCHEMA_VERSION
      ) {
        throw RavenError.staleAdapter(`client-PIR ${operation} ${instanceLabel}: schema mismatch`, {
          url,
          status: 400,
          serverWireSchemaVersion: serverVersion ?? undefined,
          clientWireSchemaVersion: WIRE_SCHEMA_VERSION,
        });
      }
    }
    if (!response.ok) {
      throw RavenError.serverError(`client-PIR ${operation} ${instanceLabel}: ${response.status}`, {
        url,
        status: response.status,
      });
    }
    return response;
  }

  private async ensureClientPirSession(
    instanceLabel: string,
    ctx: ClientPirContext,
  ): Promise<SessionLease> {
    const route = this.route();
    const handshakeKey = this.clientPirSessionKey(instanceLabel, route.endpoint);
    let handshake = this.sessionHandshakes.get(handshakeKey);
    if (!handshake) {
      handshake = this.establishClientPirSession(instanceLabel, ctx);
      this.sessionHandshakes.set(handshakeKey, handshake);
    }
    try {
      const handle = await handshake;
      ctx.wasm.install_server_session_handle(ctx.session, handle);
    } catch (cause) {
      if (this.sessionHandshakes.get(handshakeKey) === handshake) {
        this.sessionHandshakes.delete(handshakeKey);
      }
      throw cause;
    }
    return { key: handshakeKey, handshake };
  }

  private invalidateClientPirSession(lease: SessionLease): void {
    if (this.sessionHandshakes.get(lease.key) === lease.handshake) {
      this.sessionHandshakes.delete(lease.key);
    }
  }

  private async establishClientPirSession(
    instanceLabel: string,
    ctx: ClientPirContext,
  ): Promise<bigint> {
    if (
      typeof ctx.wasm.client_packing_keys_versioned !== "function" ||
      typeof ctx.wasm.install_server_session_handle !== "function"
    ) {
      throw RavenError.staleAdapter(
        `client-PIR ${instanceLabel}: WASM lacks the remote-session exports; rebuild ` +
          "raven-inspire-client-wasm before querying",
      );
    }
    const route = this.route();
    const clientId = this.clientPirClientId(instanceLabel);
    const body = ctx.wasm.client_packing_keys_versioned(ctx.session);
    const url = `${route.endpoint}/v1/instance/${encodeURIComponent(instanceLabel)}/session`;
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method: "POST",
        headers: {
          "content-type": "application/octet-stream",
          authorization: `Bearer ${route.bearerToken}`,
          "x-raven-client-id": clientId,
        },
        body: copyForBody(body),
      });
    } catch (cause) {
      throw RavenError.network(`client-PIR session ${instanceLabel}`, {
        url,
        cause: String(cause),
      });
    }
    if (!response.ok) {
      throw RavenError.serverError(
        `client-PIR session ${instanceLabel}: ${response.status}`,
        { url, status: response.status },
      );
    }
    const handle = parseSessionHandle(response.headers.get("x-raven-session"), instanceLabel);
    return handle;
  }

  private clientPirClientId(instanceLabel: string): string {
    const key = this.clientPirSessionKey(instanceLabel, this.route().endpoint);
    const existing = this.clientPirIds.get(key);
    if (existing) return existing;
    const cryptoApi = globalThis.crypto;
    if (!cryptoApi || typeof cryptoApi.getRandomValues !== "function") {
      throw RavenError.serverError(
        "client-PIR session: crypto.getRandomValues is unavailable for client binding",
      );
    }
    const bytes = new Uint8Array(16);
    cryptoApi.getRandomValues(bytes);
    const clientId = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    this.clientPirIds.set(key, clientId);
    return clientId;
  }

  private clientPirSessionKey(instanceLabel: string, endpoint: string): string {
    return `${this.chainId}\u0000${endpoint}\u0000${instanceLabel}`;
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

  private privateFreshnessAction(
    privateFreshness: PrivateFreshness,
    operation: StaleDataContext["operation"],
  ): "accept" | "fallback" {
    if (privateFreshness.kind === "absent") {
      throw RavenError.staleAdapter(
        `private ${operation} response has no ${X_RAVEN_FRESHNESS}; freshness cannot be verified`,
      );
    }
    if (privateFreshness.kind === "malformed") {
      throw RavenError.decodeError(
        `private ${operation} response has malformed ${X_RAVEN_FRESHNESS}`,
      );
    }
    const freshness = privateFreshness.value;
    if (!this.shouldFallback(freshness)) return "accept";
    if (this.privateStalePolicy === "allow-upstream-disclosure" && operation !== "fanout") {
      return "fallback";
    }
    throw RavenError.staleData(
      `private ${operation} response is stale: confidence ${freshness.confidence} < floor ` +
        `${this.confidenceFloor} (lag_blocks=${freshness.lagBlocks}, ` +
        `applied_height=${freshness.appliedHeight}, epoch=${freshness.epoch}); ` +
        (operation === "fanout"
          ? "fanout has no plaintext upstream fallback"
          : "upstream disclosure is disabled"),
      {
        operation,
        lagBlocks: freshness.lagBlocks,
        appliedHeight: freshness.appliedHeight,
        epoch: freshness.epoch,
        confidence: freshness.confidence,
        confidenceFloor: this.confidenceFloor,
      },
    );
  }

  private async passthroughPoisPerList(
    listKeys: string[],
    blindedCommitmentDatas: BlindedCommitmentData[],
  ): Promise<PoisPerListResponse> {
    if (!this.upstream) {
      throw RavenError.invalidQuery("upstream fallback not configured");
    }
    return this.upstreamJsonRpc<PoisPerListResponse>("ppoi_pois_per_list", {
      chainType: String(this.chainType),
      chainID: String(this.chainId),
      txidVersion: this.txidVersion,
      listKeys,
      blindedCommitmentDatas,
    });
  }

  private async passthroughMerkleProofs(
    listKey: string,
    blindedCommitments: string[],
  ): Promise<MerkleProof[]> {
    if (!this.upstream) {
      throw RavenError.invalidQuery("upstream fallback not configured");
    }
    return this.upstreamJsonRpc<MerkleProof[]>("ppoi_merkle_proofs", {
      chainType: String(this.chainType),
      chainID: String(this.chainId),
      txidVersion: this.txidVersion,
      listKey,
      blindedCommitments,
    });
  }

  private async upstreamJsonRpc<T>(
    method: UpstreamJsonRpcMethod,
    params: Readonly<Record<string, unknown>>,
  ): Promise<T> {
    if (!this.upstream) {
      throw RavenError.invalidQuery("upstream fallback not configured");
    }
    const id = this.nextUpstreamRequestId;
    this.nextUpstreamRequestId = id === Number.MAX_SAFE_INTEGER ? 1 : id + 1;
    const body = JSON.stringify({ jsonrpc: "2.0", method, params, id });
    const url = this.upstream;
    this.captureRequest(url, "POST", new TextEncoder().encode(body));

    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      });
    } catch (cause) {
      throw RavenError.network(`upstream ${method}`, { url, cause: String(cause) });
    }

    let decoded: unknown;
    try {
      decoded = await response.json();
    } catch (cause) {
      throw RavenError.decodeError(`upstream ${method}: response is not valid JSON`, {
        url,
        status: response.status,
        cause: String(cause),
      });
    }
    if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
      throw RavenError.decodeError(`upstream ${method}: JSON-RPC response is not an object`, {
        url,
        status: response.status,
      });
    }
    const envelope = decoded as Record<string, unknown>;
    if (envelope.jsonrpc !== "2.0" || envelope.id !== id) {
      throw RavenError.decodeError(
        `upstream ${method}: JSON-RPC envelope mismatch: version ${String(envelope.jsonrpc)}, id ${String(envelope.id)}, expected 2.0/${id}`,
        { url, status: response.status },
      );
    }
    const hasResult = Object.prototype.hasOwnProperty.call(envelope, "result");
    const hasError = Object.prototype.hasOwnProperty.call(envelope, "error");
    if (hasResult === hasError) {
      throw RavenError.decodeError(
        `upstream ${method}: JSON-RPC response must contain exactly one of result or error`,
        { url, status: response.status },
      );
    }
    if (hasError) {
      const error = envelope.error;
      if (typeof error !== "object" || error === null || Array.isArray(error)) {
        throw RavenError.decodeError(`upstream ${method}: JSON-RPC error is not an object`, {
          url,
          status: response.status,
        });
      }
      const rpcError = error as Record<string, unknown>;
      if (!Number.isInteger(rpcError.code) || typeof rpcError.message !== "string") {
        throw RavenError.decodeError(
          `upstream ${method}: JSON-RPC error requires an integer code and string message`,
          { url, status: response.status },
        );
      }
      throw RavenError.serverError(
        `upstream ${method} JSON-RPC error ${String(rpcError.code)}: ${rpcError.message}`,
        { url, status: response.status },
      );
    }
    if (!response.ok) {
      throw RavenError.serverError(`upstream ${method}: HTTP ${response.status}`, {
        url,
        status: response.status,
      });
    }
    return envelope.result as T;
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

/** Validate a response's `[u16 BE version]` prefix. */
function stripSchemaEnvelope(buf: Uint8Array, label: string): Uint8Array {
  if (buf.length < 2) {
    throw RavenError.decodeError(
      `${label}: response too short for schema envelope (${buf.length})`,
    );
  }
  const envelope = (buf[0] << 8) | buf[1];
  if (envelope !== WIRE_SCHEMA_VERSION) {
    throw RavenError.decodeError(
      `${label}: unexpected schema envelope version ${envelope}`,
    );
  }
  return buf.subarray(2);
}

/** Encode the `Vec<SeededClientQuery>` shape `dispatch_batch` expects:
 * `[u16 BE version][u64 LE count][concatenated per-query bincode]`. */
function encodeBatchBody(queries: Uint8Array[]): Uint8Array {
  const schemaPrefix = new Uint8Array([
    (WIRE_SCHEMA_VERSION >>> 8) & 0xff,
    WIRE_SCHEMA_VERSION & 0xff,
  ]);
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

function encodeFanoutRequest(queryBytes: Uint8Array, plan: FanoutCoverPlan): Uint8Array {
  if (queryBytes.length === 0) {
    throw RavenError.invalidQuery("fanout cover: query bytes must not be empty");
  }
  const total = 2 + queryBytes.length + 8 + plan.wireShardIds.length * 4;
  if (!Number.isSafeInteger(total) || total > MAX_FANOUT_BODY_BYTES) {
    throw RavenError.invalidQuery(
      `fanout cover: encoded request length ${total} exceeds body cap ${MAX_FANOUT_BODY_BYTES}`,
    );
  }

  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  view.setUint16(0, WIRE_SCHEMA_VERSION, false);
  out.set(queryBytes, 2);
  let offset = 2 + queryBytes.length;
  view.setUint32(offset, plan.wireShardIds.length, true);
  view.setUint32(offset + 4, 0, true);
  offset += 8;
  for (const shardId of plan.wireShardIds) {
    view.setUint32(offset, shardId, true);
    offset += 4;
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
  if (offset !== buf.length) {
    throw RavenError.decodeError(
      `decodeBatchBody: ${buf.length - offset} trailing bytes after ${lenLo} elements`,
    );
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

function parseSessionHandle(raw: string | null, instanceLabel: string): bigint {
  if (raw === null || !/^[0-9]+$/.test(raw)) {
    throw RavenError.decodeError(
      `client-PIR session ${instanceLabel}: x-raven-session must be a decimal u64`,
    );
  }
  const handle = BigInt(raw);
  if (handle > 0xffffffffffffffffn) {
    throw RavenError.decodeError(
      `client-PIR session ${instanceLabel}: x-raven-session exceeds u64`,
    );
  }
  return handle;
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

function parsePrivateFreshnessHeader(value: string | null): PrivateFreshness {
  if (value === null) return { kind: "absent" };
  const parsed = parseFreshnessHeader(value);
  return parsed ? { kind: "valid", value: parsed } : { kind: "malformed" };
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
  ClientPirContext,
  RavenInspireWasm,
  RavenInspireClientSession,
  ClientPirQueryBundle,
} from "./client-pir";
export type { BcToIdxMap, POIStatus, RavenPOIPathWasm } from "./poi-pir";
