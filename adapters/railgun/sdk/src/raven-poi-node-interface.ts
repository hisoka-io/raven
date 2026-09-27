import type { POIsPerList as EnginePOIsPerList } from "@railgun-community/engine";
import {
  type ClientPirContext,
  decodeClientPirQueryBundle,
  decodeShardGeometry,
} from "./client-pir";
import {
  type BcIdxEntry,
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
import { MAX_BATCH_SIZE } from "./batch-ladder";
import { authPathQueryLevels, buildPaddedQueryPlan } from "./batch-cover";
import {
  type BcPrefixIndex,
  BC_INDEX_PREFIX_BYTES,
  assertBcPrefixIndex,
  bcPrefixIndexFromRows,
  fetchBcPrefixIndex,
  indexCandidatesForEach,
  resumeBcPrefixIndex,
  sharesOnlyPrefix,
} from "./bc-prefix-index";
import { bearerHeaders } from "./bearer-auth";
import {
  buildFanoutCoverPlan,
  recoverRealFanoutResponses,
  type FanoutCoverPlan,
} from "./fanout-cover";
import { ChainRegistry, type ChainRegistryEntry } from "./chain-registry";
import { RavenError, type StaleDataContext } from "./errors";
import { ImtCache, imtCacheKey, imtCacheScopeKey } from "./imt-cache";
import { LEAVES_PER_PPOI_BLOCK, type ResolvedPins, UpstreamPinResolver } from "./pin-resolver";
import {
  type PoiListIndexStore,
  decodePoiListIndexRecord,
  encodePoiListIndexRecord,
  indexedDbPoiListIndexStore,
  poiListIndexStoreKey,
} from "./poi-list-index-store";
import { foldMerkleRoot } from "./poseidon";
import { checkedRequestTimeoutMs, fetchWithDeadline } from "./request-deadline";

export type BlindedCommitmentType = "Shield" | "Transact" | "Unshield";

/**
 * `GET /v1/poi/:list_key/status-header`, in the shape the server actually sends.
 *
 * Keys are camelCase because the handler carries `#[serde(rename_all = "camelCase")]`. A
 * snake_case key would type-check yet read `undefined`, leaving the blocked set empty and every
 * ShieldBlocked commitment on the list reading as clean.
 */
export interface StatusHeader {
  /** Lowest block height any store covering the list has applied; 0 for a mirrored PPOI list. */
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
 * Commit-tree proof, on both routes: siblings and path bits, never a root. Client-PIR never
 * retrieves the leaf, so it has nothing to fold one from. The plaintext route sends a root, but
 * only the serving node vouches for it, so it is dropped with the leaf: the wallet folds its own
 * note, and the contract's root history is what checks the result.
 */
export type CommitTreeProof = { readonly kind: "authPath" } & CommitTreeAuthPath;

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
  /** Adapter credential; omit for a node that serves its routes without one.
   * Read from `chainRegistry` instead when one is supplied. */
  bearerToken?: string;
  /** EVM chain id this adapter serves; defaults to 1 (mainnet). */
  chainId?: number;
  /** Upstream `chainType` (0 = EVM); a path segment in PPOI passthrough URLs. */
  chainType?: number;
  /** Multi-chain routing table; when omitted an internal one-entry registry is built. */
  chainRegistry?: ChainRegistry;
  txidVersion?: string;
  fetchImpl?: typeof fetch;
  /** Deadline for each request, from sending it to its last body byte; defaults to 60 000 ms, as
   *  the stock wallet interface allows. A request past it fails as `Network`. */
  requestTimeoutMs?: number;
  freshnessConfidenceFloor?: number;
  /** When true (default), PIR queries are built client-side; plaintext blinded commitments never cross the wire. */
  useClientPir?: boolean;
  /** Pre-loaded client-PIR contexts keyed `t1Status|t2Path|t3CommitTree:<chainId>:<id>`;
   * the chain-less legacy key is accepted as a fallback. */
  clientPirContexts?: Map<string, ClientPirContext>;
  /** Deployed instance ids keyed by the same semantic context key. A path label keyed
   *  `t2Path:<chainId>:<listKey>:<block>` names an instance holding that block alone, asked at the
   *  leaf's row in it; any other label names one instance for the whole list, asked at the list
   *  index. An index past the rows an instance's shard config declares is refused by name. */
  clientPirInstanceLabels?: Map<string, string>;
  /** Pinned PPOI block roots keyed `<chainId>:<listKey>:<block>`;
   * the chain-less legacy key is accepted as a fallback. A caller-supplied pin always wins.
   * With `useClientPir: false` no route names a proof's block, so `getPOIMerkleProofs` refuses
   * before any request unless the list has a pin here, and accepts only a proof folding to one. */
  ppoiPinnedRoots?: Map<string, string>;
  /** Upstream PPOI aggregator to read block roots from when no root is pinned. Defaults to
   * `upstreamFallbackEndpoint`; `false` disables the resolver and restores the bare refusal.
   *
   * The default introduces no new party and no new connection: the wallet already opens TLS
   * to that host for validation and submission. There is deliberately no fallback hostname --
   * an invented default would send every unconfigured wallet to a host nobody chose.
   *
   * A stale-fallback proof comes from `upstreamFallbackEndpoint` itself, and a root from the
   * proof's own source checks nothing, so the resolver is not asked for it on that origin. Under
   * the default such a proof refuses unless its block is pinned or this names another aggregator. */
  pinUpstream?: string | false;
  /** Upstream `NetworkName` under `forNetwork`; defaults from `chainType`/`chainId`. */
  pinUpstreamNetworkName?: string;
  /** In-memory TTL for the filling block's roots. Frozen blocks are cached forever. */
  pinTailTtlMs?: number;
  /** Pre-loaded BC -> idx maps, keyed by `<chainId>:<listKeyHex>` or legacy `<listKeyHex>`.
   *  A map carries no row count, so an absence read from one cannot be shown current; see
   *  `indexStalenessPolicy`. */
  bcToIdxMaps?: Map<string, BcToIdxMap>;
  /** List indexes carrying the row count they cover, keyed as `bcToIdxMaps`; `syncPoiListIndex`
   *  builds one. Every client-PIR call brings the index up to the node's list before using it, and
   *  the first one re-reads every row of an index given here, since this node did not produce it. */
  poiListIndexes?: Map<string, BcPrefixIndex>;
  /** Where list indexes persist between runs: IndexedDB where the runtime has it, which Node does
   *  not, so a Node caller passes its own. `false` keeps them in memory only. */
  poiListIndexStore?: PoiListIndexStore | false;
  /** An absence that cannot be shown current is refused by default. `"answer-at-index-rows"`
   *  answers it `MissingStale` as of the rows held, and `indexCounters()` counts it apart. */
  indexStalenessPolicy?: IndexStalenessPolicy;
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

/** What an absence is answered with when it cannot be shown current against the node's list. */
export type IndexStalenessPolicy = "refuse" | "answer-at-index-rows";

/** How each index-derived absence was answered. Only `absent` speaks for the list served now.
 *  A proof has no answer for an absence, so `getPOIMerkleProofs` refuses every kind and counts it
 *  under the field its status would have taken. */
export interface PoiIndexCounters {
  /** `Missing`, from an index brought up to the node's list in the same call. */
  readonly absent: number;
  /** `MissingStale`, from an index whose sync failed, under `answer-at-index-rows`. */
  readonly absentFromStaleIndex: number;
  /** `MissingStale`, from a `bcToIdxMaps` entry, which has no row count, under
   *  `answer-at-index-rows`. */
  readonly absentFromBareMap: number;
  /** Per-list refusals of absences that could not be shown current: thrown, or `Unreachable`
   *  when the sync failed on the network; the engine-shaped call leaves them out instead. */
  readonly refused: number;
  /** Syncs that found the node's list longer than the index held. */
  readonly staleIndexesCaught: number;
}

/** `GET /v1/poi/:list/bc-to-idx-map`, checked rather than cast. */
export interface BcToIdxMapBody {
  /** As served; 0 for a mirrored PPOI list, so it says nothing about how current the rows are. */
  readonly epoch: number;
  readonly listKey: string;
  /** The body covers rows `[0, rows)`, one entry per row in index order. `rows` lies between the
   *  counts the node's prefix channel served just before and just after the body, and every row
   *  carries the prefix that channel serves for it. */
  readonly rows: number;
  readonly entries: BcIdxEntry[];
}

/** `failure` set means the index could not be brought up to the node's list: its present
 *  candidates still resolve, since a row the list holds never moves, but its absences are stale. */
type ListIndexSource =
  | { readonly kind: "bound"; readonly index: BcPrefixIndex; readonly failure?: unknown }
  | { readonly kind: "bare"; readonly map: BcToIdxMap };

export interface BlindedCommitmentData {
  blindedCommitment: string;
  type: BlindedCommitmentType;
}

/** Outer key BC hex, inner list-key hex; mirrors upstream `POIsPerListMap`. */
export interface PoisPerListResponse {
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
  addenda: Uint8Array[];
  freshness: PrivateFreshness;
}

interface AuthPathResult {
  nodes: Uint8Array[];
  freshness: PrivateFreshness;
}

/** Where one list index is asked, and where its leaf sits in its PPOI block's tree. */
interface ListRowTarget {
  readonly block: number;
  readonly leaf: number;
  readonly label: string;
  readonly row: number;
  /** Rows of the list this instance holds, which bounds where a cover query may point. */
  readonly rows: number;
}

/** One commitment's verdict row on the list being answered, under the caller's own key. */
interface PendingVerdict {
  readonly bcKey: string;
  readonly verdicts: { [listKey: string]: POIStatus };
}

/** Checks a fold against a root some party other than the proof's source vouches for. */
type RootAnchor = (folded: string, bcHex: string, label: string) => Promise<void>;

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
const WIRE_SCHEMA_VERSION = 8;
const MAX_FANOUT_BODY_BYTES = 8 * 1024 * 1024;
const DEFAULT_TXID_VERSION = "V2_PoseidonMerkle";
const DEFAULT_CONFIDENCE_FLOOR = 0.5;
const DEFAULT_CHAIN_ID = 1;
const DEFAULT_CHAIN_TYPE = 0; // upstream `ChainType.EVM`
const NODE_HASH_BYTES = 32;
const ROOT_HEX_CHARS = 64;
const PATH_RECORD_BYTES = TREE_DEPTH * NODE_HASH_BYTES;
/** Epoch tag before the instance has ever reported one; never collides with a real epoch. */
const UNOBSERVED_EPOCH = "";
const AUTH_PATH_ATTEMPTS = 2;
/** Commitments per request on the engine-shaped plaintext and legacy-submit paths, as the stock
 *  wallet interface batches them. */
const ENGINE_BATCH_SIZE = 20;
/** The verdicts engine's `TXOPOIListStatus` has; the others are SDK-local. */
const ENGINE_STATUSES: readonly string[] = ["Valid", "ShieldBlocked", "ProofSubmitted", "Missing"];
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
  private readonly clientPirInstanceLabels: Map<string, string>;
  private readonly ppoiPinnedRoots: Map<string, string>;
  private readonly pinResolver: UpstreamPinResolver | undefined;
  private readonly pinResolverSource: string | undefined;
  private readonly bcToIdxMaps: Map<string, BcToIdxMap>;
  private readonly poiListIndexes: Map<string, BcPrefixIndex>;
  private readonly indexStore: PoiListIndexStore | undefined;
  private readonly stalenessPolicy: IndexStalenessPolicy;
  private readonly heldIndexes = new Map<string, BcPrefixIndex>();
  // Keys whose held rows this node served or confirmed; any other index is re-read in full.
  private readonly confirmedIndexes = new Set<string>();
  // One sync per key at a time, so a slower one cannot land an older list over a newer one.
  private readonly syncQueues = new Map<string, Promise<BcPrefixIndex>>();
  // One store read per key, awaited by every caller: a caller arriving mid-read gets its result.
  private readonly storeLoads = new Map<string, Promise<void>>();
  private readonly counters = {
    absent: 0,
    absentFromStaleIndex: 0,
    absentFromBareMap: 0,
    refused: 0,
    staleIndexesCaught: 0,
  };
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
    this.fetchImpl = fetchWithDeadline(
      config.fetchImpl ?? fetch,
      checkedRequestTimeoutMs(config.requestTimeoutMs),
    );
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
    this.clientPirInstanceLabels = config.clientPirInstanceLabels ?? new Map();
    this.ppoiPinnedRoots = config.ppoiPinnedRoots ?? new Map();
    this.bcToIdxMaps = config.bcToIdxMaps ?? new Map();
    this.poiListIndexes = config.poiListIndexes ?? new Map();
    for (const [key, index] of this.poiListIndexes) {
      assertBcPrefixIndex(index, `poiListIndexes[${key}]`);
    }
    this.indexStore =
      config.poiListIndexStore === false
        ? undefined
        : (config.poiListIndexStore ?? indexedDbPoiListIndexStore());
    this.stalenessPolicy = config.indexStalenessPolicy ?? "refuse";
    if (this.stalenessPolicy !== "refuse" && this.stalenessPolicy !== "answer-at-index-rows") {
      throw RavenError.invalidQuery(
        `indexStalenessPolicy must be "refuse" or "answer-at-index-rows"`,
      );
    }
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

    // Only under `allow-upstream-disclosure`, whose entire meaning is "re-ask a DIFFERENT
    // party": pointing the fallback at this node makes the policy a lie, since the caller
    // consents to disclosure and gets the same stale answer from the same operator. Under
    // `refuse` the upstream is only a passthrough target for methods Raven does not
    // implement, and one process serving both roles is a legitimate topology. Checked after
    // the registry is built so it covers a caller-supplied `chainRegistry` too.
    if (
      this.upstream !== undefined &&
      this.privateStalePolicy === "allow-upstream-disclosure"
    ) {
      const served = this.registry.resolve(this.chainId).endpoint;
      if (samePartyOrUnknown(served, this.upstream) !== false) {
        throw RavenError.invalidQuery(
          "upstreamFallbackEndpoint must not be the endpoint it falls back from; both " +
            `resolve to ${this.upstream}, so the fallback discloses to the same operator`,
        );
      }
    }

    // A root supplied by the node that served the siblings verifies nothing. Same
    // normalization as the disclosure guard above, aimed at a different circularity.
    // An EXPLICIT `pinUpstream` pointed at this node is a configuration error and throws;
    // one merely inherited from `upstreamFallbackEndpoint` cannot, because that field is
    // also the passthrough target and one process serving both roles is legitimate there.
    // It goes inert instead, and the fold-time refusal says so.
    const routeEndpoint = this.registry.resolve(this.chainId).endpoint.replace(/\/$/, "");
    const pinSource =
      config.pinUpstream === false
        ? undefined
        : (config.pinUpstream ?? this.upstream)?.replace(/\/$/, "");
    if (typeof config.pinUpstream === "string" && !isUsableEndpoint(pinSource ?? "")) {
      throw RavenError.invalidQuery(
        `pinUpstream must be an http(s) URL or a same-origin path, got ` +
          `${JSON.stringify(config.pinUpstream)}; pass false to disable pin verification`,
      );
    }
    if (typeof config.pinUpstream === "string" && samePartyOrUnknown(pinSource, routeEndpoint)) {
      throw RavenError.invalidQuery(
        "pinUpstream must not be the endpoint whose auth paths it verifies; both resolve to " +
          `${routeEndpoint}, so the pin would come from the party that supplied the siblings`,
      );
    }
    // An INHERITED pin source must never be fatal: `UpstreamPinResolver` throws on an unlisted
    // chain, and a wallet whose only relevant config is `upstreamFallbackEndpoint` -- the
    // configuration the README calls normal -- would fail to construct on any chain outside the
    // network map, taking down the status, commit-tree and passthrough paths, none of which use
    // pins. A caller who named `pinUpstream`, `pinUpstreamNetworkName` or `pinTailTtlMs` asked for
    // the resolver and still gets the throw, so a bad value is refused by name rather than
    // silently turning pin verification off.
    const pinRequestedByName =
      typeof config.pinUpstream === "string" ||
      config.pinUpstreamNetworkName !== undefined ||
      config.pinTailTtlMs !== undefined;
    if (pinSource === undefined || samePartyOrUnknown(pinSource, routeEndpoint) === true) {
      this.pinResolver = undefined;
      this.pinResolverSource = undefined;
    } else {
      const build = (): UpstreamPinResolver =>
        new UpstreamPinResolver({
          endpoint: pinSource,
          fetchImpl: this.fetchImpl,
          chainType: this.chainType,
          chainId: this.chainId,
          txidVersion: this.txidVersion,
          networkName: config.pinUpstreamNetworkName,
          tailTtlMs: config.pinTailTtlMs,
          onRequest: (url, method, body) => this.captureRequest(url, method, body),
        });
      if (pinRequestedByName) {
        this.pinResolver = build();
      } else {
        try {
          this.pinResolver = build();
        } catch {
          // Inert, exactly as the self-aiming inherited case is. The fold-time refusal names
          // the missing pin source, which is the diagnosis a caller can act on.
          this.pinResolver = undefined;
        }
      }
      this.pinResolverSource = this.pinResolver === undefined ? undefined : pinSource;
    }
  }

  isActive(chain: Chain): boolean {
    return chain.type === this.chainType && chain.id === this.chainId;
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

  /**
   * Engine's status is a nominal string enum that no literal union is assignable to, so the
   * engine-shaped overload answers in engine's own type, and as the stock wallet interface does:
   * it never rejects for a failed list or commitment. Engine replaces a commitment's whole stored
   * map with what it gets back, so a commitment whose verdict on any list could not be
   * established is left out, and engine keeps what it held. That includes the SDK-local
   * `Unreachable` and `MissingStale`, which are not engine statuses. The two-argument overload
   * keeps the typed errors and SDK-local verdicts.
   */
  async getPOIsPerList(
    txidVersion: string,
    chain: Chain,
    listKeys: string[],
    blindedCommitmentDatas: BlindedCommitmentData[],
  ): Promise<{ [blindedCommitment: string]: EnginePOIsPerList }>;
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
    if (upstreamShape) return this.getPOIsPerListForEngine(listKeys, blindedCommitmentDatas);
    for (const lk of listKeys) {
      validateListKeyHex(lk);
    }
    for (const { blindedCommitment } of blindedCommitmentDatas) {
      validateBcHex(blindedCommitment);
    }
    if (this.useClientPir) {
      return this.getPOIsPerListClientPir(listKeys, blindedCommitmentDatas);
    }
    return this.getPOIsPerListPlaintext(listKeys, blindedCommitmentDatas);
  }

  /** The engine-shaped contract: see the `getPOIsPerList` overloads. */
  private async getPOIsPerListForEngine(
    listKeys: string[],
    blindedCommitmentDatas: BlindedCommitmentData[],
  ): Promise<PoisPerListResponse> {
    const valid = (check: () => void): boolean => {
      try {
        check();
        return true;
      } catch {
        return false;
      }
    };
    if (!listKeys.every((lk) => valid(() => validateListKeyHex(lk)))) return {};
    const asked = blindedCommitmentDatas.filter(({ blindedCommitment }) =>
      valid(() => validateBcHex(blindedCommitment)),
    );
    const unestablished = new Set<string>();
    let answered: PoisPerListResponse = {};
    if (this.useClientPir) {
      try {
        answered = await this.getPOIsPerListClientPir(listKeys, asked, unestablished);
      } catch {
        return {};
      }
    } else {
      // Batched as the stock interface batches, so one failed request costs only its batch.
      for (let start = 0; start < asked.length; start += ENGINE_BATCH_SIZE) {
        const batch = asked.slice(start, start + ENGINE_BATCH_SIZE);
        try {
          Object.assign(answered, await this.getPOIsPerListPlaintext(listKeys, batch));
        } catch {
          for (const { blindedCommitment } of batch) unestablished.add(blindedCommitment);
        }
      }
    }
    return engineVerdicts(answered, listKeys, unestablished);
  }

  private async getPOIsPerListPlaintext(
    listKeys: string[],
    blindedCommitmentDatas: BlindedCommitmentData[],
  ): Promise<PoisPerListResponse> {
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
    return rekeyToCallerStrings(
      assertPoisPerListResponse(json, blindedCommitmentDatas, "/v1/poi/pois-per-list"),
      blindedCommitmentDatas,
    );
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
    if (blindedCommitments.length === 0) return [];
    const lkHex = normalizeHex(listKey);
    // Neither this route nor upstream names a proof's block, so only a caller pin can anchor it,
    // and a call with none for the list refuses before sending the commitments anywhere.
    const anchor = this.listPinAnchor(lkHex);
    const body = {
      txidVersion: this.txidVersion,
      listKey,
      blindedCommitments,
    };
    const { json, freshness } = await this.postJson<MerkleProof[]>(
      "/v1/poi/merkle-proofs",
      body,
    );
    const fromUpstream = this.shouldFallback(freshness) && Boolean(this.upstream);
    const proofs = fromUpstream
      ? await this.passthroughMerkleProofs(listKey, blindedCommitments)
      : assertMerkleProofArray(json, "/v1/poi/merkle-proofs");
    const label = fromUpstream ? "upstream ppoi_merkle_proofs" : "/v1/poi/merkle-proofs";
    const byLeaf = new Map(proofs.map((proof) => [normalizeHex(proof.leaf), proof]));
    const out: MerkleProof[] = [];
    for (const bc of blindedCommitments) {
      const bcHex = normalizeHex(bc);
      const proof = byLeaf.get(bcHex);
      if (!proof) {
        throw RavenError.decodeError(`${label}: omitted BC ${bcHex} on list ${lkHex}`);
      }
      await anchor(foldForeignProof(proof, bcHex, label), bcHex, label);
      out.push(proof);
    }
    return out;
  }

  async getMerkleProof(treeNumber: number, leafIndex: number): Promise<CommitTreeProof> {
    validateTreeNumber(treeNumber);
    validateLeafIndex(leafIndex);
    if (this.useClientPir) {
      return this.getMerkleProofClientPir(treeNumber, leafIndex);
    }
    const route = `/v1/commit-tree/${treeNumber}/merkle-proof`;
    const { json } = await this.postJson<unknown>(route, { leafIndex });
    return servedCommitTreeAuthPath(json, leafIndex, route);
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
    }, true);
  }

  // `POINodeInterface.submitLegacyTransactProofs` (engine/src/poi/poi-node-interface.ts:49-54);
  /** Mirrors upstream `POINodeInterface.submitLegacyTransactProofs`. The engine-shaped overload
   *  submits in batches and, as the stock wallet interface does, never rejects: a failed batch,
   *  or no upstream to send to, leaves the proofs for engine's next refresh. The two-argument
   *  overload sends one request and throws. */
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
    if (upstreamShape) {
      if (!this.upstream) return;
      for (let start = 0; start < legacyTransactProofDatas.length; start += ENGINE_BATCH_SIZE) {
        try {
          await this.submitLegacyBatch(
            listKeys,
            legacyTransactProofDatas.slice(start, start + ENGINE_BATCH_SIZE),
          );
        } catch {
          // Contained to this batch; engine resubmits what is still unproven on its next refresh.
        }
      }
      return;
    }
    if (!this.upstream) {
      throw RavenError.invalidQuery("submitLegacyTransactProofs requires upstreamFallbackEndpoint");
    }
    await this.submitLegacyBatch(listKeys, legacyTransactProofDatas);
  }

  private async submitLegacyBatch(
    listKeys: string[],
    legacyTransactProofDatas: LegacyTransactProofData[],
  ): Promise<void> {
    await this.upstreamJsonRpc<unknown>("ppoi_submit_legacy_transact_proofs", {
      chainType: String(this.chainType),
      chainID: String(this.chainId),
      txidVersion: this.txidVersion,
      listKeys,
      legacyTransactProofDatas,
    }, true);
  }

  /** Rows of the JSON index channel. Turn them into a preload map with `bcToIdxMapFrom`,
   *  which keeps the occurrence the adapter resolves to; `new Map(entries)` keeps the other one.
   *
   *  The body carries no count of its own, so every row is compared with the prefix channel, read
   *  just before it. The list only grows, so a body shorter than that read was cut or copied from
   *  an older list, and one longer than the list served just after it holds rows the node does not
   *  serve: both are refused, as is any row whose prefix differs. */
  async fetchBcToIdxMap(listKey: string): Promise<BcToIdxMapBody> {
    validateListKeyHex(listKey);
    const route = this.route();
    const lkHex = normalizeHex(listKey);
    const credential = bearerHeaders(route.bearerToken);
    const onPrefixRequest = (prefixUrl: string): void =>
      this.captureRequest(prefixUrl, "GET", new Uint8Array());
    const before = await fetchBcPrefixIndex(
      this.fetchImpl,
      route.endpoint,
      lkHex,
      credential,
      onPrefixRequest,
    );
    const url = `${route.endpoint}/v1/poi/${listKey}/bc-to-idx-map`;
    this.captureRequest(url, "GET", new Uint8Array());
    let res: Response;
    try {
      // Served cacheable: a copy from before the prefix read would be refused as short.
      res = await this.fetchImpl(url, { headers: credential, cache: "no-cache" });
    } catch (cause) {
      throw RavenError.network("fetchBcToIdxMap", { url, cause: String(cause) });
    }
    if (!res.ok) {
      throw RavenError.serverError(`bc-to-idx-map: ${res.status}`, {
        url,
        status: res.status,
      });
    }
    let body: unknown;
    try {
      body = await res.json();
    } catch (cause) {
      throw RavenError.decodeError("bc-to-idx-map: body is not valid JSON", {
        url,
        cause: String(cause),
      });
    }
    const parsed = parseBcToIdxMap(body, lkHex, url);
    if (parsed.rows < before.total) {
      throw RavenError.decodeError(
        `bc-to-idx-map: the body carries ${parsed.rows} rows and the node's prefix channel ` +
          `serves ${before.total}; a list that only grows cannot be shorter than it was just ` +
          "before, so the body was cut or copied from an older list",
        { url },
      );
    }
    // Longer is an append that landed between the two reads; the node's list must now cover it.
    const after =
      parsed.rows > before.total
        ? await resumeBcPrefixIndex(
            this.fetchImpl,
            route.endpoint,
            lkHex,
            credential,
            before,
            onPrefixRequest,
            before.total,
          )
        : before;
    if (parsed.rows > after.total) {
      throw RavenError.decodeError(
        `bc-to-idx-map: the body carries ${parsed.rows} rows, more than the ${after.total} the ` +
          "node's prefix channel serves",
        { url },
      );
    }
    const rows = bcPrefixIndexFromRows(parsed.epoch, parsed.entries).prefixes;
    for (let byte = 0; byte < rows.length; byte += 1) {
      if (rows[byte] !== after.prefixes[byte]) {
        throw RavenError.decodeError(
          `bc-to-idx-map: row ${Math.floor(byte / BC_INDEX_PREFIX_BYTES)} differs from the ` +
            "node's prefix channel, so the body is not the list the node serves",
          { url },
        );
      }
    }
    return parsed;
  }

  /**
   * Build, or bring up to the node's list, the index this client answers from, and persist it.
   * The first sync walks the whole prefix channel; every later one re-reads only the tail.
   */
  async syncPoiListIndex(listKey: string): Promise<BcPrefixIndex> {
    validateListKeyHex(listKey);
    return this.syncIndex(normalizeHex(listKey));
  }

  /** Candidate indices for a commitment, read from the index held in memory or in the store,
   *  with the row count they are complete for. Sends nothing. */
  async poiListIndexCandidates(
    listKey: string,
    blindedCommitment: string,
  ): Promise<{ rows: number; candidates: number[] }> {
    validateListKeyHex(listKey);
    validateBcHex(blindedCommitment);
    const lkHex = normalizeHex(listKey);
    const held = await this.heldIndex(lkHex);
    if (held === undefined) {
      throw RavenError.invalidQuery(
        `no index is held for list ${lkHex} on this node; call syncPoiListIndex first`,
      );
    }
    return {
      rows: held.total,
      candidates: indexCandidatesForEach(held, [normalizeHex(blindedCommitment)])[0],
    };
  }

  indexCounters(): PoiIndexCounters {
    return { ...this.counters };
  }

  private indexKey(lkHex: string): string {
    return poiListIndexStoreKey(this.chainId, this.route().endpoint.replace(/\/$/, ""), lkHex);
  }

  private async heldIndex(lkHex: string): Promise<BcPrefixIndex | undefined> {
    const key = this.indexKey(lkHex);
    const held = this.heldIndexes.get(key);
    if (held !== undefined) return held;
    const preloaded =
      this.poiListIndexes.get(`${this.chainId}:${lkHex}`) ?? this.poiListIndexes.get(lkHex);
    if (preloaded !== undefined) {
      this.heldIndexes.set(key, preloaded);
      return preloaded;
    }
    if (this.indexStore === undefined) return undefined;
    let load = this.storeLoads.get(key);
    if (load === undefined) {
      load = this.restoreIndex(lkHex, key, this.indexStore);
      this.storeLoads.set(key, load);
    }
    await load;
    return this.heldIndexes.get(key);
  }

  private async restoreIndex(lkHex: string, key: string, store: PoiListIndexStore): Promise<void> {
    let restored: BcPrefixIndex | undefined;
    try {
      const record = await store.load(key);
      restored = record === undefined ? undefined : await decodePoiListIndexRecord(lkHex, record);
    } catch {
      restored = undefined;
    }
    // Only a completed sync against this same node writes a record, so its rows are confirmed.
    // Every sync awaits this read first, so nothing newer can be held yet.
    if (restored !== undefined) {
      this.heldIndexes.set(key, restored);
      this.confirmedIndexes.add(key);
    }
  }

  private syncIndex(lkHex: string): Promise<BcPrefixIndex> {
    const key = this.indexKey(lkHex);
    const prior = this.syncQueues.get(key);
    const run =
      prior === undefined
        ? this.syncIndexNow(lkHex, key)
        : prior.then(
            () => this.syncIndexNow(lkHex, key),
            () => this.syncIndexNow(lkHex, key),
          );
    this.syncQueues.set(key, run);
    const settle = (): void => {
      if (this.syncQueues.get(key) === run) this.syncQueues.delete(key);
    };
    run.then(settle, settle);
    return run;
  }

  private async syncIndexNow(lkHex: string, key: string): Promise<BcPrefixIndex> {
    const held = await this.heldIndex(lkHex);
    const confirmed = held !== undefined && this.confirmedIndexes.has(key);
    const route = this.route();
    const headers = bearerHeaders(route.bearerToken);
    const onRequest = (url: string): void => this.captureRequest(url, "GET", new Uint8Array());
    const synced =
      held === undefined
        ? await fetchBcPrefixIndex(this.fetchImpl, route.endpoint, lkHex, headers, onRequest)
        : await resumeBcPrefixIndex(
            this.fetchImpl,
            route.endpoint,
            lkHex,
            headers,
            held,
            onRequest,
            confirmed ? held.total : 0,
          );
    if (held !== undefined && synced.total > held.total) this.counters.staleIndexesCaught += 1;
    this.heldIndexes.set(key, synced);
    this.confirmedIndexes.add(key);
    if (
      this.indexStore !== undefined &&
      (!confirmed || synced.total !== held.total || synced.epoch !== held.epoch)
    ) {
      try {
        await this.indexStore.save(key, await encodePoiListIndexRecord(lkHex, synced));
      } catch {
        // A failed save costs the next run a longer walk, never a wrong answer.
      }
    }
    return synced;
  }

  /** The index a call answers from. A bound index is synced first; a failed sync is carried, not
   *  thrown, since it decides only what the call's absences may say. */
  private async listSource(lkHex: string): Promise<ListIndexSource | undefined> {
    const held = await this.heldIndex(lkHex);
    if (held === undefined) {
      const map = this.lookupBcMap(lkHex);
      return map === undefined ? undefined : { kind: "bare", map };
    }
    try {
      return { kind: "bound", index: await this.syncIndex(lkHex) };
    } catch (failure) {
      return { kind: "bound", index: (await this.heldIndex(lkHex)) ?? held, failure };
    }
  }

  /** Returns a refusal rather than throwing it: the caller raises it once every list's queries
   *  have gone out, so whether a commitment was absent never changes what the node sees. With
   *  `unestablished`, an absence that cannot be shown current is recorded there instead of being
   *  answered, since the engine would persist any answer over the verdict it holds. */
  private answerAbsences(
    absent: readonly PendingVerdict[],
    lkHex: string,
    source: ListIndexSource,
    unestablished?: Set<string>,
  ): RavenError | undefined {
    if (absent.length === 0) return undefined;
    let verdict: POIStatus;
    if (source.kind === "bound" && source.failure === undefined) {
      this.counters.absent += absent.length;
      verdict = "Missing";
    } else if (unestablished !== undefined) {
      this.counters.refused += 1;
      for (const { bcKey } of absent) unestablished.add(bcKey);
      return undefined;
    } else if (this.stalenessPolicy === "answer-at-index-rows") {
      if (source.kind === "bound") this.counters.absentFromStaleIndex += absent.length;
      else this.counters.absentFromBareMap += absent.length;
      verdict = "MissingStale";
    } else {
      this.counters.refused += 1;
      if (source.kind === "bare") {
        return RavenError.invalidQuery(
          `client-PIR: ${absent.length} commitment(s) are absent from the bc-to-idx map for ` +
            `list ${lkHex}, which carries no row count, so the absence cannot be shown current; ` +
            `hold an index from syncPoiListIndex, or set indexStalenessPolicy to ` +
            `"answer-at-index-rows"`,
        );
      }
      if (!RavenError.is(source.failure, "Network")) {
        return indexSyncFailure(lkHex, source.index, source.failure);
      }
      verdict = "Unreachable";
    }
    for (const { verdicts } of absent) {
      verdicts[lkHex] = verdict;
    }
    return undefined;
  }

  async fetchStatusHeader(listKey: string): Promise<StatusHeader> {
    validateListKeyHex(listKey);
    const route = this.route();
    const url = `${route.endpoint}/v1/poi/${listKey}/status-header`;
    const credential = bearerHeaders(route.bearerToken);
    this.captureRequest(url, "GET", new Uint8Array());
    let res: Response;
    try {
      res = await this.fetchImpl(url, { headers: credential });
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

  private instanceLabel(prefix: string, scope: string): string | undefined {
    return (
      this.clientPirInstanceLabels.get(`${prefix}:${this.chainId}:${scope}`) ??
      this.clientPirInstanceLabels.get(`${prefix}:${scope}`)
    );
  }

  /**
   * Where a list index is asked, for the status and the path route alike. A block-keyed label is
   * asked at the leaf's row in its block; any other instance holds the whole list and is asked at
   * the list index, since localizing there would alias every block onto block 0's rows. Status is
   * never split by block: asking only the blocks that hold a commitment tells the node which.
   *
   * An index past the instance's rows is refused, as its row was never written. Returned, not
   * thrown, so the status route can raise it once every list has been asked.
   */
  private listRowTarget(
    route: "t1Status" | "t2Path",
    lkHex: string,
    idx: number,
    ctx: ClientPirContext,
    listRows: number,
  ): ListRowTarget | RavenError {
    const block = Math.floor(idx / LEAVES_PER_PPOI_BLOCK);
    const blockLabel =
      route === "t2Path" ? this.instanceLabel(route, `${lkHex}:${block}`) : undefined;
    const label = blockLabel ?? this.instanceLabel(route, lkHex) ?? `${route}-${lkHex}`;
    const leaf = idx - block * LEAVES_PER_PPOI_BLOCK;
    const row = blockLabel === undefined ? idx : leaf;
    let capacity: number;
    try {
      capacity = decodeShardGeometry(ctx.shardConfigBincode).totalEntries;
    } catch (cause) {
      return RavenError.invalidQuery(
        `client-PIR ${label}: the context's shard config gives no row count, so no index can be ` +
          `shown to be held (${cause instanceof Error ? cause.message : String(cause)})`,
      );
    }
    if (row >= capacity) {
      const within = row === idx ? "" : ` (row ${row} of block ${block})`;
      return RavenError.invalidQuery(
        `client-PIR ${label}: list index ${idx}${within} is past the instance's capacity of ` +
          `${capacity} rows, so no row there was ever written; refused rather than answered`,
      );
    }
    const rowsBelow = row === idx ? listRows : listRows - block * LEAVES_PER_PPOI_BLOCK;
    return { block, leaf, label, row, rows: Math.max(row + 1, Math.min(capacity, rowsBelow)) };
  }

  /** Pinned PPOI block roots resolve chain-aware first, then the chain-less legacy key. */
  private pinnedRootFor(rootKey: string): string | undefined {
    return (
      this.ppoiPinnedRoots.get(`${this.chainId}:${rootKey}`) ??
      this.ppoiPinnedRoots.get(rootKey)
    );
  }

  private lookupBcMap(listKeyHex: string): BcToIdxMap | undefined {
    const chainAware = this.bcToIdxMaps.get(`${this.chainId}:${listKeyHex}`);
    if (chainAware) return chainAware;
    return this.bcToIdxMaps.get(listKeyHex);
  }

  /** With `unestablished`, every failure is contained: the caller key of a commitment whose
   *  verdict on some list could not be established is added to it, and nothing is thrown. */
  private async getPOIsPerListClientPir(
    listKeys: string[],
    blindedCommitmentDatas: BlindedCommitmentData[],
    unestablished?: Set<string>,
  ): Promise<PoisPerListResponse> {
    const out: PoisPerListResponse = {};
    // Pre-init so unknown-BC rows still surface; matches the upstream merge.
    for (const { blindedCommitment } of blindedCommitmentDatas) {
      out[blindedCommitment] ??= {};
    }
    const failAll = (): void => {
      for (const { blindedCommitment } of blindedCommitmentDatas) {
        unestablished?.add(blindedCommitment);
      }
    };

    let refusal: RavenError | undefined;
    for (const listKey of listKeys) {
      const lkHex = normalizeHex(listKey);
      const ctx = this.lookupContext("t1Status", lkHex);
      let source: ListIndexSource | undefined;
      try {
        source = ctx === undefined ? undefined : await this.listSource(lkHex);
      } catch (cause) {
        if (unestablished === undefined) throw cause;
      }
      if (!ctx || !source) {
        if (unestablished !== undefined) {
          failAll();
          continue;
        }
        throw RavenError.invalidQuery(
          `client-PIR: missing context or bc-to-idx-map for list ${listKey}; ` +
            "preload via loadClientPirContext and syncPoiListIndex(listKey) before calling " +
            "getPOIsPerList",
        );
      }
      const listRows = rowsHeldBy(source);
      // `verdicts` IS the caller-keyed row, resolved where the caller's spelling is the only one
      // in scope, so the arms below have no key left to pick. `normalizeHex` output is a lookup
      // key and indexes nothing in `out`; the index signature types that miss as present, so a
      // verdict written under it throws at runtime with nothing to catch it at compile time.
      const bcHexes = blindedCommitmentDatas.map(({ blindedCommitment }) =>
        normalizeHex(blindedCommitment),
      );
      const candidateSets = candidatesIn(source, bcHexes);
      const absent: PendingVerdict[] = [];
      let pending: (PendingVerdict & {
        commitmentData: BlindedCommitmentData;
        bcHex: string;
        candidates: number[];
        next: number;
      })[] = [];
      blindedCommitmentDatas.forEach((commitmentData, position) => {
        const bcKey = commitmentData.blindedCommitment;
        const verdicts = out[bcKey];
        const candidates = candidateSets[position];
        if (candidates.length === 0) {
          absent.push({ bcKey, verdicts });
        } else {
          const bcHex = bcHexes[position];
          pending.push({ commitmentData, bcHex, bcKey, verdicts, candidates, next: 0 });
        }
      });

      // A later round exists only for a prefix collision, and asks the next candidate.
      for (let round = 0; round === 0 || pending.length > 0; round += 1) {
        const collided: typeof pending = [];
        const byInstance = new Map<
          string,
          { rows: number; asked: { member: (typeof pending)[number]; row: number }[] }
        >();
        for (const member of pending) {
          const at = this.listRowTarget(
            "t1Status",
            lkHex,
            member.candidates[member.next],
            ctx,
            listRows,
          );
          if (at instanceof RavenError) {
            refusal ??= at;
            unestablished?.add(member.bcKey);
            continue;
          }
          const group = byInstance.get(at.label);
          if (group === undefined) {
            byInstance.set(at.label, { rows: at.rows, asked: [{ member, row: at.row }] });
          } else {
            group.asked.push({ member, row: at.row });
          }
        }
        if (byInstance.size === 0) {
          const cover = this.listRowTarget("t1Status", lkHex, 0, ctx, listRows);
          if (cover instanceof RavenError) {
            refusal ??= cover;
            break;
          }
          byInstance.set(cover.label, { rows: cover.rows, asked: [] });
        }
        for (const [statusInstance, { rows, asked }] of byInstance) {
          const chunkCount = Math.max(1, Math.ceil(asked.length / MAX_BATCH_SIZE));
          for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
            const chunk = asked.slice(
              chunkIndex * MAX_BATCH_SIZE,
              (chunkIndex + 1) * MAX_BATCH_SIZE,
            );
            // A member's own failure is contained to it when containing; otherwise it is thrown.
            const settle = (bcKey: string, failure: RavenError): void => {
              if (unestablished === undefined) throw failure;
              unestablished.add(bcKey);
            };
            try {
              const privateReply = await this.runClientPirQueryBatch(
                statusInstance,
                ctx,
                chunk.map(({ row }) => row),
                rows,
              );
              if (this.privateFreshnessAction(privateReply.freshness, "t1-status") === "fallback") {
                // This deliberately reveals the exact BC/list to upstream. Returning a stale
                // spend-authorizing verdict would preserve lookup privacy at the cost of
                // correctness.
                const fallback = await this.passthroughPoisPerList(
                  [listKey],
                  chunk.map(({ member }) => member.commitmentData),
                );
                for (const { member } of chunk) {
                  const fallbackStatus = fallback[member.bcKey]?.[lkHex];
                  if (!fallbackStatus) {
                    settle(
                      member.bcKey,
                      RavenError.decodeError(
                        `upstream pois-per-list omitted BC ${member.bcKey} on list ${lkHex}`,
                      ),
                    );
                    continue;
                  }
                  member.verdicts[lkHex] = fallbackStatus;
                }
              } else {
                for (let slot = 0; slot < chunk.length; slot += 1) {
                  const { member } = chunk[slot];
                  const plaintext = privateReply.plaintexts[slot];
                  if (
                    source.kind === "bound" &&
                    sharesOnlyPrefix(plaintext.subarray(1), hexToBytes(member.bcHex))
                  ) {
                    member.next += 1;
                    if (member.next < member.candidates.length) collided.push(member);
                    else absent.push(member);
                    continue;
                  }
                  const label =
                    `client-PIR t1Status-${lkHex} idx ${member.candidates[member.next]}`;
                  try {
                    member.verdicts[lkHex] = decodeStatusRow(plaintext, member.bcHex, label);
                  } catch (cause) {
                    if (!(cause instanceof RavenError)) throw cause;
                    settle(member.bcKey, cause);
                  }
                }
              }
            } catch (cause) {
              if (unestablished !== undefined) {
                for (const { member } of chunk) unestablished.add(member.bcKey);
              } else if (cause instanceof RavenError && cause.kind === "Network") {
                for (const { member } of chunk) {
                  member.verdicts[lkHex] = "Unreachable";
                }
              } else {
                throw cause;
              }
            }
          }
        }
        pending = collided;
      }
      const refused = this.answerAbsences(absent, lkHex, source, unestablished);
      refusal ??= refused;
    }
    if (refusal !== undefined && unestablished === undefined) throw refusal;
    return out;
  }

  private async getPOIMerkleProofsClientPir(
    listKey: string,
    blindedCommitments: string[],
  ): Promise<MerkleProof[]> {
    const lkHex = normalizeHex(listKey);
    const ctx = this.lookupContext("t2Path", lkHex);
    const source = ctx === undefined ? undefined : await this.listSource(lkHex);
    if (!ctx || !source) {
      throw RavenError.invalidQuery(
        `client-PIR: missing context or bc-to-idx-map for list ${listKey}; ` +
          "preload via loadClientPirContext and syncPoiListIndex(listKey) before calling " +
          "getPOIMerkleProofs",
      );
    }
    // No proof exists for an absence, so every kind is refused; it is counted as getPOIsPerList
    // counts it, and the refusal says whether it could be shown current.
    const notPresent = (bcHex: string, absences: number): RavenError => {
      let scope: string;
      if (source.kind === "bare") {
        scope = "the bc-to-idx map carries no row count, so the absence cannot be shown current";
      } else if (source.failure === undefined) {
        scope = `the index holds the ${source.index.total} rows the node serves`;
      } else {
        scope =
          `the index holds ${source.index.total} rows and could not be brought up to the ` +
          "node's list, so the absence cannot be shown current";
      }
      if (source.kind === "bound" && source.failure === undefined) {
        this.counters.absent += absences;
      } else if (this.stalenessPolicy === "refuse") {
        this.counters.refused += 1;
        if (source.kind === "bound") return indexSyncFailure(lkHex, source.index, source.failure);
      } else if (source.kind === "bound") {
        this.counters.absentFromStaleIndex += absences;
      } else {
        this.counters.absentFromBareMap += absences;
      }
      return RavenError.invalidQuery(
        `client-PIR: BC ${bcHex} not present in list ${lkHex} (idx unknown; ${scope})`,
      );
    };
    // Resolve every commitment BEFORE any request goes out. Two things fall out of that: an
    // unknown BC refuses without having disclosed the others, and the grouping below
    // needs the whole set in hand.
    const bcHexes = blindedCommitments.map((bc) => normalizeHex(bc));
    const candidateSets = candidatesIn(source, bcHexes);
    const listRows = rowsHeldBy(source);
    const firstAbsent = candidateSets.findIndex((candidates) => candidates.length === 0);
    if (firstAbsent !== -1) {
      throw notPresent(
        bcHexes[firstAbsent],
        candidateSets.filter((candidates) => candidates.length === 0).length,
      );
    }
    let pending = blindedCommitments.map((bc, position) => ({
      bc,
      bcHex: bcHexes[position],
      position,
      candidates: candidateSets[position],
      next: 0,
    }));

    // Group by block, then pad each group on the ladder, as the T1 status path does. One
    // unpadded request per commitment would cost K round trips and hand the server the exact
    // count off a stable client id, which is what the ladder exists to hide.
    //
    // Two bounds on that. (1) Grouping is WITHIN a block, since each
    // block routes to its own instance label, so commitments spread over six blocks still cost six
    // round trips. (2) The ladder hides K within its dyadic bucket, never K itself: a chunk of k
    // real targets goes out as P = paddedBatchLength(k) queries, and P tells the server k is in
    // (P/2, P]. That bucket is a single value at P = 1 and P = 2, so a block group of K = 1 or
    // K = 2, or any K whose last 32-chunk holds one or two (K mod 32 in {1, 2}), is still disclosed
    // exactly. Zero cover slots is not the tell: K = 4 draws none and reads the same as K = 3.
    // Flooring the ladder at 2 would make {1, 2} one bucket and double the cost of the ordinary
    // single-note proof, which is a product decision rather than one to take here.
    //
    // A later round exists only for a prefix collision, and asks the next candidate.
    const out = new Array<MerkleProof>(pending.length);
    while (pending.length > 0) {
      const collided: typeof pending = [];
      const byBlock = new Map<
        number,
        {
          label: string;
          rows: number;
          group: { target: (typeof pending)[number]; at: ListRowTarget }[];
        }
      >();
      for (const target of pending) {
        const at = this.listRowTarget(
          "t2Path",
          lkHex,
          target.candidates[target.next],
          ctx,
          listRows,
        );
        if (at instanceof RavenError) throw at;
        const held = byBlock.get(at.block);
        if (held === undefined) {
          byBlock.set(at.block, { label: at.label, rows: at.rows, group: [{ target, at }] });
        } else {
          held.group.push({ target, at });
        }
      }

      for (const [block, { label: pathInstance, rows, group }] of byBlock) {
        const rootKey = `${lkHex}:${block}`;
        const chunkCount = Math.ceil(group.length / MAX_BATCH_SIZE);
        for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
          const chunk = group.slice(
            chunkIndex * MAX_BATCH_SIZE,
            (chunkIndex + 1) * MAX_BATCH_SIZE,
          );
          // The leaf index never crosses the wire, only encrypted row queries.
          const privateReply = await this.runClientPirQueryBatch(
            pathInstance,
            ctx,
            chunk.map(({ at }) => at.row),
            rows,
            160,
          );
          if (this.privateFreshnessAction(privateReply.freshness, "t2-auth-path") === "fallback") {
            // This deliberately reveals the exact BC/list to upstream. The alternative is to
            // return an auth path whose freshness is below the operator-selected confidence floor.
            // Matched by LEAF rather than by position: upstream's reply order is its own business,
            // and a silently transposed pair here would hand a wallet another note's auth path.
            // The anchor is taken first: a disclosure whose answer cannot be verified buys nothing.
            const label = `upstream fallback for ${pathInstance}`;
            const anchor = this.blockRootAnchor(lkHex, block, this.upstream, label);
            const fallback = await this.passthroughMerkleProofs(
              listKey,
              chunk.map(({ target }) => target.bc),
            );
            const byLeaf = new Map(fallback.map((proof) => [normalizeHex(proof.leaf), proof]));
            for (const { target: { bcHex, position } } of chunk) {
              const proof = byLeaf.get(bcHex);
              if (!proof) {
                throw RavenError.decodeError(
                  `upstream merkle-proofs omitted BC ${bcHex} on list ${lkHex}`,
                );
              }
              await anchor(foldForeignProof(proof, bcHex, label), bcHex, label);
              out[position] = proof;
            }
            continue;
          }
          for (let slot = 0; slot < chunk.length; slot += 1) {
            const { target, at } = chunk[slot];
            const { bcHex, position } = target;
            const localIndex = at.leaf;
            const row = privateReply.plaintexts[slot];
            const addendum = privateReply.addenda[slot];
            if (!row || row.length !== 512 || new TextDecoder().decode(row.slice(34, 38)) !== "RVP2") {
              throw RavenError.decodeError(`client-PIR ${pathInstance}: malformed PPOI v2 row`);
            }
            if (source.kind === "bound" && sharesOnlyPrefix(row.subarray(0, 32), hexToBytes(bcHex))) {
              target.next += 1;
              if (target.next === target.candidates.length) throw notPresent(bcHex, 1);
              collided.push(target);
              continue;
            }
            if (bytesToHex(row.slice(0, 32)) !== bcHex) {
              throw RavenError.decodeError(`client-PIR ${pathInstance}: row leaf does not match requested BC`);
            }
            if (!addendum || addendum.length !== 160) {
              throw RavenError.decodeError(`client-PIR ${pathInstance}: upper-sibling addendum must be 160 bytes`);
            }
            const nodes = Array.from({ length: 11 }, (_unused, level) =>
              row.slice(38 + level * 32, 38 + (level + 1) * 32),
            ).concat(
              Array.from({ length: 5 }, (_unused, level) =>
                addendum.slice(level * 32, (level + 1) * 32),
              ),
            );
            const proof = buildMerkleProof(localIndex, bcHex, nodes);
            // Resolved through the same chain-aware -> legacy ladder `instanceLabel` routes on:
            // a guard keyed on the chain-less form, or a `has()` gate, would skip the check for a
            // proof routed on the chain-aware form and return it unverified with `Ok`.
            const pinnedRoot = this.pinnedRootFor(rootKey);
            if (pinnedRoot !== undefined) {
              const normalizedPin = checkedPinnedRoot(
                pinnedRoot,
                rootKey,
                `client-PIR ${pathInstance}`,
              );
              if (normalizedPin !== proof.root) {
                throw RavenError.decodeError(
                  `client-PIR ${pathInstance}: folded root does not match pinned root`,
                );
              }
            } else {
              await this.verifyAgainstUpstreamPin(pathInstance, lkHex, block, rootKey, proof.root);
            }
            out[position] = proof;
          }
        }
      }
      pending = collided;
    }
    return out;
  }

  /** Second rung of the root ladder. A caller-supplied pin always wins; with none, the
   *  roots come from the upstream aggregator, never from the node that served the siblings. */
  private async verifyAgainstUpstreamPin(
    pathInstance: string,
    listKeyHex: string,
    block: number,
    rootKey: string,
    foldedRoot: string,
  ): Promise<void> {
    const preamble =
      `client-PIR ${pathInstance}: no pinned root for ${rootKey} on chain ${this.chainId} and `;
    const remedy =
      "; a server-supplied auth path cannot be verified without an independently obtained root";
    if (!this.pinResolver) {
      // `invalidQuery`, not `staleData`: nothing here is stale, and StaleDataContext demands
      // lag/confidence numbers a missing pin does not have -- inventing them would be the
      // fabricated-context version of the defect this guard closes.
      throw RavenError.invalidQuery(
        `${preamble}no usable upstream pin source is configured (set pinUpstream, or preload ` +
          `ppoiPinnedRoots)${remedy}`,
      );
    }
    let resolved: ResolvedPins;
    try {
      resolved = await this.pinResolver.resolve(listKeyHex, block);
    } catch (cause) {
      throw pinSourceFailure(preamble, remedy, cause);
    }
    if (!resolved.roots.has(foldedRoot)) {
      // A block that froze inside the tail TTL is still answered from the window it had while
      // filling, and its final root is not in that set. Re-ask before refusing, so an honest
      // caller is not charged a refusal for the privacy fix above.
      //
      // Its cost: THREE extra requests (point query, status, events), one of which names the
      // block, and it fires on every window miss, not only on a real freeze. A node lagging more
      // than a window behind therefore pays it on every proof while refusing every proof, [6, 3, 3]
      // requests over three folds. Bounding it per block is not a free win: the bound
      // that stops the leak also stops a block that freezes between two folds from verifying,
      // which `ppoi_pinned_root_mandatory.test.ts` pins deliberately. Which of the two a wallet
      // should get is a caller's decision, so neither is hardcoded here until one is asked for.
      this.pinResolver.forgetTail(listKeyHex, block);
      try {
        resolved = await this.pinResolver.resolve(listKeyHex, block);
      } catch (cause) {
        // Same wrapper as the first attempt, and for the same reason: without it an upstream
        // outage inside the retry window would surface as `DecodeError` -- the tampering kind --
        // with no instance, no rootKey and none of the remedy text.
        throw pinSourceFailure(preamble, remedy, cause);
      }
    }
    if (!resolved.roots.has(foldedRoot)) {
      // The window is named because it is what separates "this node is lagging past the
      // range upstream was asked about" from "this node forged the siblings".
      throw RavenError.decodeError(
        `client-PIR ${pathInstance}: folded root is not among the ${resolved.roots.size} root(s) ` +
          `upstream certifies for ${rootKey} over global leaf indices ` +
          `${resolved.window.startIndex}..${resolved.window.endIndex} ` +
          `(${resolved.window.frozen ? "frozen" : "filling"} block)`,
      );
    }
  }

  /**
   * The independent root for one block, for a proof whose root came from `proofSource`. A root
   * from the proof's own source would pass any forgery that source sends, so the resolver
   * answers only when it is known to be another party; unknown counts as the same, as the
   * disclosure guard counts it. Taken before this block group's proofs are fetched, so a group
   * that could only refuse discloses none of its commitments; an earlier group of the same call
   * has already been sent by then.
   */
  private blockRootAnchor(
    lkHex: string,
    block: number,
    proofSource: string | undefined,
    label: string,
  ): RootAnchor {
    const rootKey = `${lkHex}:${block}`;
    const pinnedRoot = this.pinnedRootFor(rootKey);
    if (pinnedRoot !== undefined) {
      const pin = checkedPinnedRoot(pinnedRoot, rootKey, label);
      return async (folded, _bcHex, at) => {
        if (folded !== pin) {
          throw RavenError.decodeError(`${at}: folded root does not match pinned root`);
        }
      };
    }
    if (
      this.pinResolver === undefined ||
      proofSource === undefined ||
      samePartyOrUnknown(this.pinResolverSource, proofSource) !== false
    ) {
      throw RavenError.invalidQuery(
        `${label}: no pinned root for ${rootKey} on chain ${this.chainId}, and no root from a ` +
          `party other than the one that would send the proof; set pinUpstream to an aggregator ` +
          "upstreamFallbackEndpoint does not operate, or preload ppoiPinnedRoots",
      );
    }
    return (folded, _bcHex, at) => this.verifyAgainstUpstreamPin(at, lkHex, block, rootKey, folded);
  }

  /** Every caller pin for one list on this chain, each block through the same chain-aware ->
   *  legacy ladder `pinnedRootFor` applies. A fold equal to any of them proves inclusion in that
   *  block's tree, whichever block the server meant. */
  private listPinAnchor(lkHex: string): RootAnchor {
    const label = `merkle proofs for list ${lkHex}`;
    const blocks = new Set<string>();
    for (const key of this.ppoiPinnedRoots.keys()) {
      const parts = key.split(":");
      const [chain, list, block] = parts.length === 3 ? parts : [undefined, ...parts];
      if (chain !== undefined && chain !== String(this.chainId)) continue;
      if (list === lkHex && block !== undefined && /^[0-9]+$/.test(block)) blocks.add(block);
    }
    const pinned = new Set<string>();
    for (const block of blocks) {
      const rootKey = `${lkHex}:${block}`;
      const pin = this.pinnedRootFor(rootKey);
      if (pin !== undefined) pinned.add(checkedPinnedRoot(pin, rootKey, label));
    }
    if (pinned.size === 0) {
      throw RavenError.invalidQuery(
        `${label}: no root pinned for the list on chain ${this.chainId}, and the plaintext route ` +
          "does not say which block a proof is in, so no root from a party other than its source " +
          "can be asked for; preload ppoiPinnedRoots for the list, or use client-PIR",
      );
    }
    return async (folded, bcHex, at) => {
      if (!pinned.has(folded)) {
        throw RavenError.decodeError(
          `${at}: proof for ${bcHex} folds to a root that is not among the ${pinned.size} ` +
            `root(s) pinned for list ${lkHex}; either its block is not pinned or the proof is forged`,
        );
      }
    };
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

    const queryLevels = authPathQueryLevels(stillMissing, indices.length);
    const foldsCachedLevels = queryLevels.length < indices.length;

    const geometry = decodeShardGeometry(ctx.shardConfigBincode);
    const plan = buildPaddedQueryPlan(
      queryLevels.map((level) => indices[level]),
      geometry.entriesPerShard,
      geometry.totalEntries,
    );
    const queryBundles = plan.wireTargets.map((target) =>
      decodeClientPirQueryBundle(
        ctx.wasm.build_seeded_query(ctx.session, ctx.shardConfigBincode, BigInt(target)),
      ),
    );
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
      const wireSlot = plan.realSlots[k];
      let plaintext: Uint8Array;
      try {
        plaintext = ctx.wasm.extract_response(
          ctx.session,
          ctx.crsBincode,
          queryBundles[wireSlot].clientStateBincode,
          responses[wireSlot],
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

  /** List-row paths: build, pad, and decrypt one `/batch` request. Covers address rows below
   *  `populatedRows`; an empty `targetIndices` sends a lone cover and returns no rows. */
  private async runClientPirQueryBatch(
    instanceLabel: string,
    ctx: ClientPirContext,
    targetIndices: readonly number[],
    populatedRows: number,
    addendumBytes = 0,
  ): Promise<PrivateQueryBatchResult> {
    return this.withClientPirSessionRetry(instanceLabel, ctx, async () => {
      const route = this.route();
      const { entriesPerShard } = decodeShardGeometry(ctx.shardConfigBincode);
      const plan = buildPaddedQueryPlan(targetIndices, entriesPerShard, populatedRows);
      const queryBundles = plan.wireTargets.map((targetIdx) =>
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
      const addenda = plan.realSlots.map((slot) =>
        responses[slot].slice(responses[slot].length - addendumBytes),
      );
      const plaintexts = plan.realSlots.map((slot) =>
        ctx.wasm.extract_response(
          ctx.session,
          ctx.crsBincode,
          queryBundles[slot].clientStateBincode,
          addendumBytes === 0 ? responses[slot] : responses[slot].slice(0, -addendumBytes),
          ctx.entrySize,
        ),
      );
      return { plaintexts, addenda, freshness };
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
    const credential = bearerHeaders(this.route().bearerToken);
    const clientId = this.clientPirClientId(instanceLabel);
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method: "POST",
        headers: {
          "content-type": "application/octet-stream",
          ...credential,
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
    const credential = bearerHeaders(route.bearerToken);
    const clientId = this.clientPirClientId(instanceLabel);
    const body = ctx.wasm.client_packing_keys_versioned(ctx.session);
    const url = `${route.endpoint}/v1/instance/${encodeURIComponent(instanceLabel)}/session`;
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method: "POST",
        headers: {
          "content-type": "application/octet-stream",
          ...credential,
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
    const credential = bearerHeaders(route.bearerToken);
    const bodyText = JSON.stringify(body);
    const url = `${route.endpoint}${path}`;
    this.captureRequest(url, "POST", new TextEncoder().encode(bodyText));
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...credential,
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
    const reply = await this.upstreamJsonRpc<unknown>("ppoi_pois_per_list", {
      chainType: String(this.chainType),
      chainID: String(this.chainId),
      txidVersion: this.txidVersion,
      listKeys,
      blindedCommitmentDatas,
    });
    return assertPoisPerListResponse(reply, blindedCommitmentDatas, "upstream ppoi_pois_per_list");
  }

  private async passthroughMerkleProofs(
    listKey: string,
    blindedCommitments: string[],
  ): Promise<MerkleProof[]> {
    if (!this.upstream) {
      throw RavenError.invalidQuery("upstream fallback not configured");
    }
    const reply = await this.upstreamJsonRpc<unknown>("ppoi_merkle_proofs", {
      chainType: String(this.chainType),
      chainID: String(this.chainId),
      txidVersion: this.txidVersion,
      listKey,
      blindedCommitments,
    });
    return assertMerkleProofArray(reply, "upstream ppoi_merkle_proofs");
  }

  private async upstreamJsonRpc<T>(
    method: UpstreamJsonRpcMethod,
    params: Readonly<Record<string, unknown>>,
    allowMissingResult = false,
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
    if ((hasResult && hasError) || (!hasResult && !hasError && !allowMissingResult)) {
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

/** A malformed pin can never equal a fold, so without these checks a caller's own typo would
 *  surface as `DecodeError`, the kind that blames the node for forging the path. */
function checkedPinnedRoot(pin: string, rootKey: string, label: string): string {
  const normalizedPin = normalizeHex(pin);
  if (normalizedPin.length !== ROOT_HEX_CHARS) {
    throw RavenError.invalidQuery(
      `${label}: pinned root for ${rootKey} is ${normalizedPin.length} hex chars, not ` +
        `${ROOT_HEX_CHARS}; pad it to 32 bytes`,
    );
  }
  if (!/^[0-9a-f]+$/.test(normalizedPin)) {
    throw RavenError.invalidQuery(`${label}: pinned root for ${rootKey} is not hexadecimal`);
  }
  return normalizedPin;
}

/** Callers match the proof to `bcHex` by leaf first. The fold reads only sixteen elements and
 *  sixteen index bits, so any other depth or position is refused rather than folded. */
function foldForeignProof(proof: MerkleProof, bcHex: string, label: string): string {
  if (proof.elements.length !== TREE_DEPTH) {
    throw RavenError.decodeError(
      `${label}: proof for ${bcHex} has ${proof.elements.length} elements, not ${TREE_DEPTH}`,
    );
  }
  const indices = normalizeHex(proof.indices);
  if (!/^[0-9a-f]{1,64}$/.test(indices) || BigInt(`0x${indices}`) >= 1n << BigInt(TREE_DEPTH)) {
    throw RavenError.decodeError(
      `${label}: proof for ${bcHex} has indices ${JSON.stringify(proof.indices)}, not a leaf ` +
        `position in a depth-${TREE_DEPTH} tree`,
    );
  }
  const folded = foldMerkleRoot(bcHex, proof.elements, BigInt(`0x${indices}`));
  if (folded !== normalizeHex(proof.root)) {
    throw RavenError.decodeError(`${label}: proof for ${bcHex} does not fold to the root it claims`);
  }
  return folded;
}

/**
 * One message for "there is no independent root", whatever stopped it arriving -- keeping the
 * CAUSE'S kind, because that is what a caller's retry policy reads. Flattening an upstream 500,
 * an RPC error, or a frozen block answered with two roots to `InvalidQuery` would tell the
 * operator to check their own config and a retry policy not to retry a transient fault.
 */
function pinSourceFailure(preamble: string, remedy: string, cause: unknown): RavenError {
  const message = `${preamble}the upstream pin source could not answer (${String(cause)})${remedy}`;
  if (!(cause instanceof RavenError)) return RavenError.invalidQuery(message);
  // Only the four kinds the resolver can raise. A default of `invalidQuery` is right for the
  // rest: they would mean the SDK asked for something it should not have, which IS the caller.
  switch (cause.kind) {
    case "Network":
      return RavenError.network(message, cause.context);
    case "ServerError":
      return RavenError.serverError(message, cause.context);
    case "DecodeError":
      return RavenError.decodeError(message, cause.context);
    default:
      return RavenError.invalidQuery(message);
  }
}

/** Keeps the cause's kind, which is what a caller's retry policy reads. */
function indexSyncFailure(lkHex: string, held: BcPrefixIndex, cause: unknown): RavenError {
  const message =
    `client-PIR: the index for list ${lkHex} holds ${held.total} rows and could not be brought ` +
    `up to the list the node serves (${String(cause)}), so an absence from it cannot be shown ` +
    `current; set indexStalenessPolicy to "answer-at-index-rows" to answer from the rows held`;
  if (!(cause instanceof RavenError)) return RavenError.invalidQuery(message);
  switch (cause.kind) {
    case "Network":
      return RavenError.network(message, cause.context);
    case "ServerError":
      return RavenError.serverError(message, cause.context);
    case "DecodeError":
      return RavenError.decodeError(message, cause.context);
    case "StaleAdapter":
      return RavenError.staleAdapter(message, cause.context);
    default:
      return RavenError.invalidQuery(message);
  }
}

/** The commitments whose every asked list carries an engine verdict. Any other is left out, since
 *  engine replaces a commitment's stored map with what it is given. */
function engineVerdicts(
  answered: PoisPerListResponse,
  listKeys: readonly string[],
  unestablished: ReadonlySet<string>,
): PoisPerListResponse {
  const wanted = listKeys.map((listKey) => normalizeHex(listKey));
  const out: PoisPerListResponse = {};
  for (const [bcKey, perList] of Object.entries(answered)) {
    if (unestablished.has(bcKey)) continue;
    const statuses = Object.values(perList) as string[];
    const held = new Set(Object.keys(perList).map((listKey) => normalizeHex(listKey)));
    if (
      statuses.every((status) => ENGINE_STATUSES.includes(status)) &&
      wanted.every((listKey) => held.has(listKey))
    ) {
      out[bcKey] = perList;
    }
  }
  return out;
}

/** Rows of the list a source covers; a bare map carries no count, so its highest index stands in. */
function rowsHeldBy(source: ListIndexSource): number {
  if (source.kind === "bound") return Math.max(1, source.index.total);
  let highest = 0;
  for (const idx of source.map.values()) highest = Math.max(highest, idx);
  return highest + 1;
}

/** Ascending candidate indices per commitment. A map yields at most one, the lowest occurrence
 *  `bcToIdxMapFrom` kept; an index yields every row sharing the prefix. */
function candidatesIn(source: ListIndexSource, bcHexes: readonly string[]): number[][] {
  if (source.kind === "bound") return indexCandidatesForEach(source.index, bcHexes);
  return bcHexes.map((bcHex) => {
    const idx = source.map.get(bcHex);
    return idx === undefined ? [] : [idx];
  });
}

/**
 * The body is the node's proven gap-free prefix in index order, so entry `i` must be row `i`. That
 * refuses a row omitted, repeated or moved while the labels still name the original rows; one hidden
 * by relabelling every later row, and a cut tail, are refused by the row-by-row comparison with the
 * prefix channel in `fetchBcToIdxMap`.
 */
function parseBcToIdxMap(body: unknown, listKeyHex: string, url: string): BcToIdxMapBody {
  if (!isPlainObject(body)) {
    throw RavenError.decodeError("bc-to-idx-map: body is not an object", { url });
  }
  const { epoch, listKey, entries } = body;
  if (typeof epoch !== "number" || !Number.isSafeInteger(epoch) || epoch < 0) {
    throw RavenError.decodeError("bc-to-idx-map: epoch is not a non-negative integer", { url });
  }
  if (typeof listKey !== "string" || !isHex64(listKey) || normalizeHex(listKey) !== listKeyHex) {
    throw RavenError.decodeError(
      `bc-to-idx-map: answered for list ${String(listKey)}, asked for ${listKeyHex}`,
      { url },
    );
  }
  if (!Array.isArray(entries)) {
    throw RavenError.decodeError("bc-to-idx-map: entries is not an array", { url });
  }
  const rows: BcIdxEntry[] = new Array(entries.length);
  entries.forEach((entry: unknown, row) => {
    if (!isPlainObject(entry) || typeof entry.bc !== "string" || !isHex64(entry.bc)) {
      throw RavenError.decodeError(`bc-to-idx-map: row ${row} carries no 32-byte commitment`, {
        url,
      });
    }
    if (entry.idx !== row) {
      throw RavenError.decodeError(
        `bc-to-idx-map: row ${row} is labelled idx ${String(entry.idx)}; a row is missing, ` +
          "repeated or out of place",
        { url },
      );
    }
    rows[row] = { bc: entry.bc, idx: row };
  });
  return { epoch, listKey: listKeyHex, rows: rows.length, entries: rows };
}

/** A base for endpoints written same-origin (`/raven`), which `fetch` accepts in a browser and
 *  which have no origin of their own. Never contacted: `.invalid` is reserved precisely so it
 *  cannot resolve. */
const RELATIVE_ENDPOINT_BASE = "http://same-origin.invalid/";

/**
 * Do two endpoints name the same operator? `false` when either is absent, since there is nothing
 * to compare; otherwise their origins decide, and `undefined` means one did not parse and the two
 * differ as strings, so the answer is "cannot tell".
 *
 * Origin, not string: a differing scheme case, a default port, a trailing slash or an extra path
 * segment all address one server, and a raw string compare would let a node verify its own forged
 * auth path. The tri-state is not decoration -- the callers have OPPOSITE safe defaults (a
 * disclosure guard treats unknown as same-party and refuses; the resolver treats it as different
 * and builds an anchor that may be vacuous), and one boolean would give both the disclosure
 * guard's answer, disabling verification for any deployment whose endpoint is same-origin relative.
 *
 * A MISCONFIGURATION guard, not a security boundary: `localhost` and `127.0.0.1` are distinct
 * origins that reach one process, and two DNS names can resolve to one host.
 */
function samePartyOrUnknown(a: string | undefined, b: string | undefined): boolean | undefined {
  if (a === undefined || b === undefined) return false;
  const base =
    typeof globalThis.location?.href === "string" ? globalThis.location.href : RELATIVE_ENDPOINT_BASE;
  try {
    return new URL(a, base).origin.toLowerCase() === new URL(b, base).origin.toLowerCase();
  } catch {
    return a === b ? true : undefined;
  }
}

/** An endpoint is an absolute URL or a same-origin path. Anything else is a typo, refused as
 *  malformed rather than left to fail to parse in `samePartyOrUnknown` and read as a circular
 *  configuration. */
function isUsableEndpoint(value: string): boolean {
  // `//host` is SCHEME-relative, not same-origin: it resolves to a different authority
  // entirely, and admitting it would let a pin source aimed at the served node slip past the
  // circularity guard on a scheme mismatch.
  if (value.startsWith("//")) return false;
  if (value.startsWith("/")) return value.length > 1;
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function normalizeHex(hex: string): string {
  return (hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex).toLowerCase();
}

const POI_STATUS_VALUES: readonly string[] = [
  "Valid",
  "ShieldBlocked",
  "ProofSubmitted",
  "Missing",
  "Unreachable",
];

function isHex64(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const stripped = value.startsWith("0x") || value.startsWith("0X") ? value.slice(2) : value;
  return stripped.length === 64 && /^[0-9a-fA-F]+$/.test(stripped);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * `as T` is erased at runtime, so a shim response is checked rather than cast.
 *
 * The outer-key rule is the load-bearing one and a shape check alone cannot replace it:
 * `{listKey: {bc: status}}` and `{bc: {listKey: status}}` are both `{hex64: {hex64: POIStatus}}`,
 * so an inverted body is structurally indistinguishable from a correct one.
 */
function assertPoisPerListResponse(
  value: unknown,
  requested: BlindedCommitmentData[],
  path: string,
): PoisPerListResponse {
  if (!isPlainObject(value)) {
    throw RavenError.decodeError(`${path}: expected a JSON object keyed by blinded commitment`);
  }
  const asked = new Set(requested.map(({ blindedCommitment }) => normalizeHex(blindedCommitment)));
  for (const [bcKey, perList] of Object.entries(value)) {
    if (!asked.has(normalizeHex(bcKey))) {
      throw RavenError.decodeError(
        `${path}: outer key ${bcKey} was not requested; ` +
          "the body is keyed by something other than the blinded commitments asked for",
      );
    }
    if (!isPlainObject(perList)) {
      throw RavenError.decodeError(`${path}: entry for ${bcKey} is not a per-list object`);
    }
    for (const [listKey, status] of Object.entries(perList)) {
      if (typeof status !== "string" || !POI_STATUS_VALUES.includes(status)) {
        throw RavenError.decodeError(
          `${path}: status ${JSON.stringify(status)} for ${bcKey}/${listKey} is not a POIStatus`,
        );
      }
    }
  }
  return value as PoisPerListResponse;
}

function assertMerkleProof(value: unknown, path: string): MerkleProof {
  if (!isPlainObject(value)) {
    throw RavenError.decodeError(`${path}: proof is not an object`);
  }
  if (!isHex64(value.leaf)) {
    throw RavenError.decodeError(`${path}: proof leaf is not 32 bytes of hex`);
  }
  if (!isHex64(value.root)) {
    throw RavenError.decodeError(`${path}: proof root is not 32 bytes of hex`);
  }
  if (typeof value.indices !== "string") {
    throw RavenError.decodeError(`${path}: proof indices is not a string`);
  }
  if (!Array.isArray(value.elements) || !value.elements.every(isHex64)) {
    throw RavenError.decodeError(`${path}: proof elements are not an array of 32-byte hex strings`);
  }
  return value as unknown as MerkleProof;
}

/** The plaintext route's path, kept only if it answers the leaf asked for; its position is then
 *  minted from the request, as the client-PIR route mints it. */
function servedCommitTreeAuthPath(
  value: unknown,
  leafIndex: number,
  path: string,
): CommitTreeProof {
  if (!isPlainObject(value)) {
    throw RavenError.decodeError(`${path}: proof is not an object`);
  }
  const { elements, indices } = value;
  if (!Array.isArray(elements) || elements.length !== TREE_DEPTH || !elements.every(isHex64)) {
    throw RavenError.decodeError(
      `${path}: proof elements are not ${TREE_DEPTH} 32-byte hex strings`,
    );
  }
  const served = typeof indices === "string" ? normalizeHex(indices) : "";
  if (!/^[0-9a-f]{1,64}$/.test(served) || BigInt(`0x${served}`) !== BigInt(leafIndex)) {
    throw RavenError.decodeError(
      `${path}: proof indices ${JSON.stringify(indices)} do not name leaf ${leafIndex}, ` +
        "the one asked for",
    );
  }
  return {
    kind: "authPath",
    elements: elements.map((element: string) => normalizeHex(element)),
    indices: leafIndexToIndicesHex(leafIndex),
  };
}

function assertMerkleProofArray(value: unknown, path: string): MerkleProof[] {
  if (!Array.isArray(value)) {
    throw RavenError.decodeError(`${path}: expected an array of merkle proofs`);
  }
  return value.map((proof) => assertMerkleProof(proof, path));
}

/**
 * Re-key a response to the exact strings the caller passed in. The engine indexes this object with
 * its own `0x`-prefixed string (`abstract-wallet.ts:1420`) and a miss is an unlogged `continue`, so
 * a normalized key is silently dropped on every refresh. Normalization is an internal lookup
 * detail and must not reach the response.
 */
function rekeyToCallerStrings(
  response: PoisPerListResponse,
  blindedCommitmentDatas: BlindedCommitmentData[],
): PoisPerListResponse {
  const out: PoisPerListResponse = {};
  for (const { blindedCommitment } of blindedCommitmentDatas) {
    const entry =
      response[blindedCommitment] ?? response[normalizeHex(blindedCommitment)];
    if (entry !== undefined) out[blindedCommitment] = entry;
  }
  return out;
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
