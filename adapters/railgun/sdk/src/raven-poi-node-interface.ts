import type { POIsPerList as EnginePOIsPerList } from "@railgun-community/engine";
import {
  type ClientPirContext,
  callWasm,
  decodeClientPirQueryBundle,
  decodeShardGeometry,
} from "./client-pir";
import {
  type POIStatus,
  bytesToHex,
  containsByteSequence,
  hexToBytes,
  canonicalCommitmentHex,
  validateListKeyHex,
  TREE_DEPTH,
} from "./poi-pir";
import { MAX_BATCH_SIZE } from "./batch-ladder";
import { buildPaddedQueryPlan } from "./batch-cover";
import {
  type BcPrefixIndex,
  assertBcPrefixIndex,
  fetchBcPrefixIndex,
  indexCandidatesForEach,
  resumeBcPrefixIndex,
  sharesOnlyPrefix,
} from "./bc-prefix-index";
import { bearerHeaders } from "./bearer-auth";
import { ChainRegistry, type ChainRegistryEntry } from "./chain-registry";
import { RavenError } from "./errors";
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
import {
  type SubmittedProofStore,
  SubmittedProofs,
  memorySubmittedProofStore,
} from "./submitted-proofs";

export type BlindedCommitmentType = "Shield" | "Transact" | "Unshield";

export interface MerkleProof {
  leaf: string;
  elements: string[];
  indices: string;
  root: string;
}

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

export interface RavenConfig {
  endpoint: string;
  /** Adapter credential; omit for a node that serves its routes without one.
   * Read from `chainRegistry` instead when one is supplied. */
  bearerToken?: string;
  /** EVM chain id this adapter serves; defaults to 1 (mainnet). */
  chainId?: number;
  /** Upstream `chainType` (0 = EVM), sent in upstream JSON-RPC params. */
  chainType?: number;
  /** Multi-chain routing table; when omitted an internal one-entry registry is built. */
  chainRegistry?: ChainRegistry;
  txidVersion?: string;
  fetchImpl?: typeof fetch;
  /** Deadline for each request, from sending it to its last body byte; defaults to 60 000 ms, as
   *  the stock wallet interface allows. A request past it fails as `Network`. */
  requestTimeoutMs?: number;
  freshnessConfidenceFloor?: number;
  /** Client-PIR contexts keyed `t2Path:<chainId>:<listKeyHex>`, one per list. The lists with one
   *  are the lists this interface serves on its chain; it answers no other. */
  clientPirContexts?: Map<string, ClientPirContext>;
  /** Path instance ids keyed `t2Path:<chainId>:<listKeyHex>:<block>`, one per 65,536-leaf PPOI
   *  block, each asked at the leaf's row in its block. An index past the rows an instance's shard
   *  config declares is refused by name. */
  clientPirInstanceLabels?: Map<string, string>;
  /** Pinned PPOI block roots keyed `<chainId>:<listKeyHex>:<block>`. A caller-supplied pin always
   *  wins. */
  ppoiPinnedRoots?: Map<string, string>;
  /** Upstream PPOI aggregator: the target of `submitPOI`, `submitLegacyTransactProofs` and
   *  `validatePOIMerkleroots`, and the default pin source. No call sends it a status or proof
   *  question. */
  upstreamFallbackEndpoint?: string;
  /** Upstream PPOI aggregator to read block roots from when no root is pinned. Defaults to
   * `upstreamFallbackEndpoint`; `false` disables the resolver and restores the bare refusal.
   *
   * The default introduces no new party and no new connection: the wallet already opens TLS
   * to that host for validation and submission. There is deliberately no fallback hostname --
   * an invented default would send every unconfigured wallet to a host nobody chose. */
  pinUpstream?: string | false;
  /** Upstream `NetworkName` under `forNetwork`; defaults from `chainType`/`chainId`. */
  pinUpstreamNetworkName?: string;
  /** In-memory TTL for the filling block's roots. Frozen blocks are cached forever. */
  pinTailTtlMs?: number;
  /** List indexes keyed `<chainId>:<listKeyHex>`; `syncPoiListIndex` builds one. Every call
   *  brings the index up to the node's list before using it, and the first one re-reads every
   *  row of an index given here, since this node did not produce it. */
  poiListIndexes?: Map<string, BcPrefixIndex>;
  /** Where list indexes persist between runs: IndexedDB where the runtime has it, which Node does
   *  not, so a Node caller passes its own. `false` keeps them in memory only. */
  poiListIndexStore?: PoiListIndexStore | false;
  /** Where the commitments this device submitted proofs for persist between runs; in memory by
   *  default. Without persistence a restart before a proof reaches the list can cost one
   *  resubmission. */
  submittedProofStore?: SubmittedProofStore;
  /** Keep the last 64 outbound requests, bodies included, for `lastWireRequests()`. Off by
   *  default: the bodies include proof submissions and encrypted queries. */
  captureWireRequests?: boolean;
}

/** How index-derived absences were answered. */
export interface PoiIndexCounters {
  /** `Missing` answers, and proofs refused for a commitment absent from an index brought up to
   *  the node's list in the same call. */
  readonly absent: number;
  /** Syncs that found the node's list longer than the index held. */
  readonly staleIndexesCaught: number;
}

export interface BlindedCommitmentData {
  blindedCommitment: string;
  type: BlindedCommitmentType;
}

/** Outer key blinded commitment, inner list key, each as the caller spelled it; mirrors upstream `POIsPerListMap`. */
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

/** The index an answer is read from. `failure` set means it could not be brought up to the
 *  node's list: its present candidates still resolve, since a row the list holds never moves,
 *  but its absences are stale. */
interface ListIndexSource {
  readonly index: BcPrefixIndex;
  readonly failure?: unknown;
}

/** Where one list index is asked, and where its leaf sits in its PPOI block's tree. */
interface ListRowTarget {
  readonly block: number;
  readonly leaf: number;
  readonly label: string;
  /** Rows of the block this instance holds, which bounds where a cover query may point. */
  readonly rows: number;
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

/** One outbound request kept under `captureWireRequests`. */
export interface CapturedWireRequest {
  url: string;
  method: string;
  /** Raw bytes of the request body. Empty Uint8Array if no body. */
  body: Uint8Array;
}

const X_RAVEN_FRESHNESS = "x-raven-freshness";
const X_RAVEN_SCHEMA_VERSION = "x-raven-schema-version";
const WIRE_SCHEMA_VERSION = 8;
const DEFAULT_TXID_VERSION = "V2_PoseidonMerkle";
const DEFAULT_CONFIDENCE_FLOOR = 0.5;
const DEFAULT_CHAIN_ID = 1;
const DEFAULT_CHAIN_TYPE = 0; // upstream `ChainType.EVM`
const NODE_HASH_BYTES = 32;
const ROOT_HEX_CHARS = 64;
const PATH_RECORD_BYTES = TREE_DEPTH * NODE_HASH_BYTES;
const PATH10_ROW_BYTES = 512;
const PATH10_ADDENDUM_BYTES = 160;
/** Proofs per request on the engine-shaped legacy-submit path, as the stock wallet interface
 *  batches them. */
const ENGINE_BATCH_SIZE = 20;
/** The verdicts engine's `TXOPOIListStatus` has. */
const ENGINE_STATUSES: readonly string[] = ["Valid", "ShieldBlocked", "ProofSubmitted", "Missing"];
const SESSION_QUERY_ATTEMPTS = 2;
const WIRE_CAPTURE_CAP = 64;

type UpstreamJsonRpcMethod =
  | "ppoi_validate_poi_merkleroots"
  | "ppoi_submit_transact_proof"
  | "ppoi_submit_legacy_transact_proofs";

export class RavenPOINodeInterface {
  private readonly chainId: number;
  private readonly chainType: number;
  private readonly registry: ChainRegistry;
  private readonly upstream: string | undefined;
  private readonly txidVersion: string;
  private readonly fetchImpl: typeof fetch;
  private readonly confidenceFloor: number;
  private readonly clientPirContexts: Map<string, ClientPirContext>;
  private readonly clientPirInstanceLabels: Map<string, string>;
  private readonly ppoiPinnedRoots: Map<string, string>;
  private readonly pinResolver: UpstreamPinResolver | undefined;
  private readonly poiListIndexes: Map<string, BcPrefixIndex>;
  private readonly indexStore: PoiListIndexStore | undefined;
  private readonly submitted: SubmittedProofs;
  private readonly heldIndexes = new Map<string, BcPrefixIndex>();
  // Keys whose held rows this node served or confirmed; any other index is re-read in full.
  private readonly confirmedIndexes = new Set<string>();
  // One sync or reset per key at a time, so a slower one cannot land an older list over a newer one.
  private readonly syncQueues = new Map<string, Promise<unknown>>();
  // Keys reset since construction: their `poiListIndexes` entry is no longer read.
  private readonly droppedPreloads = new Set<string>();
  // One store read per key, awaited by every caller: a caller arriving mid-read gets its result.
  private readonly storeLoads = new Map<string, Promise<void>>();
  private readonly counters = {
    absent: 0,
    staleIndexesCaught: 0,
  };

  // Undefined unless the caller opted in: nothing is retained by default.
  private readonly capturedRequests: CapturedWireRequest[] | undefined;
  private readonly sessionHandshakes = new Map<string, Promise<bigint>>();
  private readonly clientPirIds = new Map<string, string>();
  private nextUpstreamRequestId = 1;

  constructor(config: RavenConfig) {
    this.chainId = config.chainId ?? DEFAULT_CHAIN_ID;
    this.chainType = config.chainType ?? DEFAULT_CHAIN_TYPE;
    this.upstream = config.upstreamFallbackEndpoint?.replace(/\/$/, "");
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
    this.clientPirContexts = config.clientPirContexts ?? new Map();
    this.clientPirInstanceLabels = config.clientPirInstanceLabels ?? new Map();
    this.ppoiPinnedRoots = config.ppoiPinnedRoots ?? new Map();
    this.poiListIndexes = config.poiListIndexes ?? new Map();
    for (const [key, index] of this.poiListIndexes) {
      assertBcPrefixIndex(index, `poiListIndexes[${key}]`);
    }
    this.indexStore =
      config.poiListIndexStore === false
        ? undefined
        : (config.poiListIndexStore ?? indexedDbPoiListIndexStore());
    this.submitted = new SubmittedProofs(config.submittedProofStore ?? memorySubmittedProofStore());
    this.capturedRequests = config.captureWireRequests === true ? [] : undefined;

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

    // A root supplied by the node that served the siblings verifies nothing. An EXPLICIT
    // `pinUpstream` pointed at this node is a configuration error and throws; one merely
    // inherited from `upstreamFallbackEndpoint` cannot, because one process serving both roles
    // is a legitimate topology for submission. It goes inert instead, and the fold-time refusal
    // says so.
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
    // chain, and a wallet whose only relevant config is `upstreamFallbackEndpoint` would fail to
    // construct on any chain outside the network map, taking down the status and submission
    // paths, which use no pins. A caller who named `pinUpstream`, `pinUpstreamNetworkName` or
    // `pinTailTtlMs` asked for the resolver and still gets the throw, so a bad value is refused
    // by name rather than silently turning pin verification off.
    const pinRequestedByName =
      typeof config.pinUpstream === "string" ||
      config.pinUpstreamNetworkName !== undefined ||
      config.pinTailTtlMs !== undefined;
    if (pinSource === undefined || samePartyOrUnknown(pinSource, routeEndpoint) === true) {
      this.pinResolver = undefined;
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
    }
  }

  /** The one chain this interface answers for; `PerChainPOINodeInterface` routes by it. */
  servedChain(): Chain {
    return { type: this.chainType, id: this.chainId };
  }

  isActive(chain: Chain): boolean {
    return chain.type === this.chainType && chain.id === this.chainId;
  }

  /** Refuses a chain it does not serve rather than answer `false`, which engine reads as every
   *  balance bucket spendable there; whether that chain requires POI is the stock interface's
   *  answer, which `PerChainPOINodeInterface` routes to. */
  async isRequired(chain: Chain): Promise<boolean> {
    if (!this.isActive(chain)) {
      throw RavenError.invalidQuery(
        `isRequired: chain ${chain.type}:${chain.id} is not served by this interface; install it ` +
          "behind PerChainPOINodeInterface to answer other chains",
      );
    }
    return true;
  }

  /** The engine-shaped calls that never reject answer nothing for a call they do not serve. */
  private servesInvocation(txidVersion: string, chain: Chain): boolean {
    return (
      txidVersion === this.txidVersion &&
      typeof chain === "object" &&
      chain !== null &&
      this.isActive(chain)
    );
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

  /** The last 64 outbound requests in the order they were sent. Refused unless constructed with
   *  `captureWireRequests: true`. */
  lastWireRequests(): CapturedWireRequest[] {
    if (this.capturedRequests === undefined) {
      throw RavenError.invalidQuery(
        "lastWireRequests: wire capture is off; construct with captureWireRequests: true",
      );
    }
    return this.capturedRequests.map((r) => ({
      url: r.url,
      method: r.method,
      body: new Uint8Array(r.body),
    }));
  }

  /** Drop every captured request. */
  resetWireCapture(): void {
    if (this.capturedRequests !== undefined) this.capturedRequests.length = 0;
  }

  /**
   * Status is read from the list's prefix index on this device. The only requests are the index
   * sync, whose cursors depend only on how many rows the index holds and how long the list is, so
   * none names a commitment, a list index or a shard.
   *
   * Per commitment and served list: `Valid` when its 6-byte prefix is among the rows synced in
   * this call, `ProofSubmitted` when this device submitted a proof covering it for that list and
   * it is not yet there, `Missing` otherwise. A blocked shield also reads `Missing`: nothing here
   * says a shield is blocked, and `Missing` never makes a note spendable. A commitment spelled
   * without its leading zero digits, as upstream serves some, is read as the 32-byte value it
   * spells, and every answer is keyed by the caller's own string.
   *
   * Engine's status is a nominal string enum that no literal union is assignable to, so the
   * engine-shaped overload answers in engine's own type, and as the stock wallet interface does:
   * it never rejects. Engine calls it from a refresh it does not await, where a rejection goes
   * unhandled, so a txidVersion or chain other than the configured one gets an empty map. A list
   * this interface does not serve is left out of every commitment's map, as the stock node leaves
   * out a list it does not hold. Engine replaces a commitment's whole stored map with what it gets
   * back, so a commitment whose verdict on a served list could not be established is left out, and
   * engine keeps what it held. The two-argument overload raises the typed errors instead.
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
    if (typeof txidVersionOrListKeys === "string") {
      try {
        if (
          !this.servesInvocation(txidVersionOrListKeys, chainOrCommitments as Chain) ||
          !upstreamListKeys ||
          !upstreamCommitments
        ) {
          return {};
        }
        return await this.getPOIsPerListForEngine(upstreamListKeys, upstreamCommitments);
      } catch {
        return {};
      }
    }
    const listKeys = txidVersionOrListKeys;
    const blindedCommitmentDatas = chainOrCommitments as BlindedCommitmentData[];
    if (!listKeys || !blindedCommitmentDatas) {
      throw RavenError.invalidQuery("getPOIsPerList: missing list keys or commitments");
    }
    for (const lk of listKeys) {
      validateListKeyHex(lk);
    }
    for (const { blindedCommitment } of blindedCommitmentDatas) {
      canonicalCommitmentHex(blindedCommitment);
    }
    for (const lk of listKeys) {
      if (!this.servesList(normalizeHex(lk))) {
        throw RavenError.invalidQuery(
          `getPOIsPerList: list ${normalizeHex(lk)} has no t2Path context on chain ` +
            `${this.chainId}, so this interface does not serve it; preload one via ` +
            "loadClientPirContext",
        );
      }
    }
    return this.statusFromIndex(listKeys, blindedCommitmentDatas);
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
      valid(() => canonicalCommitmentHex(blindedCommitment)),
    );
    const served = listKeys.filter((lk) => this.servesList(normalizeHex(lk)));
    if (served.length === 0) return {};
    const unestablished = new Set<string>();
    let answered: PoisPerListResponse;
    try {
      answered = await this.statusFromIndex(served, asked, unestablished);
    } catch {
      return {};
    }
    return engineVerdicts(answered, served, unestablished);
  }

  /** With `unestablished`, a list whose index cannot be synced adds every commitment to it and
   *  nothing is thrown; without, its failure is thrown with the cause's kind. */
  private async statusFromIndex(
    listKeys: string[],
    blindedCommitmentDatas: BlindedCommitmentData[],
    unestablished?: Set<string>,
  ): Promise<PoisPerListResponse> {
    const out: PoisPerListResponse = {};
    for (const { blindedCommitment } of blindedCommitmentDatas) {
      out[blindedCommitment] ??= {};
    }
    const bcHexes = blindedCommitmentDatas.map(({ blindedCommitment }) =>
      canonicalCommitmentHex(blindedCommitment),
    );
    for (const listKey of listKeys) {
      const lkHex = normalizeHex(listKey);
      let index: BcPrefixIndex;
      let pending: ReadonlySet<string> | undefined;
      try {
        index = await this.syncIndex(lkHex);
      } catch (cause) {
        if (unestablished === undefined) throw indexSyncFailure(lkHex, cause);
        for (const { blindedCommitment } of blindedCommitmentDatas) {
          unestablished.add(blindedCommitment);
        }
        continue;
      }
      try {
        pending = await this.submitted.pendingAfter(this.chainType, this.chainId, lkHex, index);
      } catch (cause) {
        // Unread, the set cannot tell ProofSubmitted from Missing, and a wrong Missing makes the
        // engine submit the same proof again; present commitments do not need it.
        if (unestablished === undefined) {
          throw RavenError.storage(
            `getPOIsPerList: the submitted-proof store could not be read for list ${lkHex} ` +
              `(${String(cause)}), so an absent commitment cannot be told from a submitted one`,
            { cause: String(cause) },
          );
        }
        pending = undefined;
      }
      const candidates = indexCandidatesForEach(index, bcHexes);
      blindedCommitmentDatas.forEach(({ blindedCommitment }, position) => {
        if (candidates[position].length > 0) {
          out[blindedCommitment][listKey] = "Valid";
        } else if (pending === undefined) {
          unestablished?.add(blindedCommitment);
        } else if (pending.has(bcHexes[position])) {
          out[blindedCommitment][listKey] = "ProofSubmitted";
        } else {
          this.counters.absent += 1;
          out[blindedCommitment][listKey] = "Missing";
        }
      });
    }
    return out;
  }

  /** A commitment spelled without its leading zero digits is proved as the 32-byte value it
   *  spells, and its proof's `leaf` carries all 64 digits. */
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
      canonicalCommitmentHex(bc);
    }
    return this.getPOIMerkleProofsClientPir(listKey, blindedCommitments);
  }

  /** Mirrors upstream `POINodeInterface.validatePOIMerkleroots`; `poiMerkleroots` is upstream's
   *  `ValidatePOIMerklerootsParams` field name. */
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

  /** Mirrors upstream's 9-arg `POINodeInterface.submitPOI`. Once upstream accepts the proof, its
   *  output commitments, and the unshield's when there is one, read `ProofSubmitted` for the list
   *  until they reach its index. */
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
    await this.submitted.record(chain.type, chain.id, listKey, [
      ...blindedCommitmentsOut,
      railgunTxidIfHasUnshield,
    ]);
  }

  /** Mirrors upstream `POINodeInterface.submitLegacyTransactProofs`. The engine-shaped overload
   *  submits in batches and, as the stock wallet interface does, never rejects: a failed batch,
   *  no upstream to send to, or a txidVersion or chain other than the configured one leaves the
   *  proofs for engine's next refresh. The two-argument overload sends one request and throws.
   *  Commitments in an accepted batch read `ProofSubmitted` until they reach the list's index. */
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
    if (typeof txidVersionOrListKeys === "string") {
      if (
        !this.upstream ||
        !upstreamListKeys ||
        !upstreamProofs ||
        !this.servesInvocation(txidVersionOrListKeys, chainOrProofs as Chain)
      ) {
        return;
      }
      for (let start = 0; start < upstreamProofs.length; start += ENGINE_BATCH_SIZE) {
        try {
          await this.submitLegacyBatch(
            upstreamListKeys,
            upstreamProofs.slice(start, start + ENGINE_BATCH_SIZE),
          );
        } catch {
          // Contained to this batch; engine resubmits what is still unproven on its next refresh.
        }
      }
      return;
    }
    const listKeys = txidVersionOrListKeys;
    const legacyTransactProofDatas = chainOrProofs as LegacyTransactProofData[];
    if (!listKeys || !legacyTransactProofDatas) {
      throw RavenError.invalidQuery(
        "submitLegacyTransactProofs: missing list keys or legacy proof data",
      );
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
    const commitments = legacyTransactProofDatas.map(({ blindedCommitment }) => blindedCommitment);
    for (const listKey of listKeys) {
      await this.submitted.record(this.chainType, this.chainId, listKey, commitments);
    }
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
    const bcHex = canonicalCommitmentHex(blindedCommitment);
    const lkHex = normalizeHex(listKey);
    const held = await this.heldIndex(lkHex);
    if (held === undefined) {
      throw RavenError.invalidQuery(
        `no index is held for list ${lkHex} on this node; call syncPoiListIndex first`,
      );
    }
    return {
      rows: held.total,
      candidates: indexCandidatesForEach(held, [bcHex])[0],
    };
  }

  /** Forget the index held for a list, in memory and in the store, so the next call reads the
   *  whole list from the node again. Waits for a sync of that list already running. */
  async resetPoiListIndex(listKey: string): Promise<void> {
    validateListKeyHex(listKey);
    const lkHex = normalizeHex(listKey);
    const key = this.indexKey(lkHex);
    await this.serialized(key, async () => {
      // A restore still reading the store would otherwise land its record after the reset.
      await this.storeLoads.get(key);
      this.heldIndexes.delete(key);
      this.confirmedIndexes.delete(key);
      this.droppedPreloads.add(key);
      this.storeLoads.set(key, Promise.resolve());
      if (this.indexStore === undefined) return;
      try {
        // A zero-length record decodes as no index, so any store clears without a delete.
        await this.indexStore.save(key, new Uint8Array(0));
      } catch (cause) {
        throw RavenError.storage(
          `resetPoiListIndex: the index store could not clear list ${lkHex} (${String(cause)}); ` +
            "the next run may resume the old index",
          { cause: String(cause) },
        );
      }
    });
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
    const preloaded = this.droppedPreloads.has(key)
      ? undefined
      : this.poiListIndexes.get(`${this.chainId}:${lkHex}`);
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
    return this.serialized(key, () => this.syncIndexNow(lkHex, key));
  }

  private serialized<T>(key: string, task: () => Promise<T>): Promise<T> {
    const prior = this.syncQueues.get(key);
    const run = prior === undefined ? task() : prior.then(task, task);
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

  /** The index a proof call resolves from, synced first. A failed sync is carried when an index
   *  is held, since it decides only what the call's absences may say. */
  private async listSource(lkHex: string): Promise<ListIndexSource> {
    try {
      return { index: await this.syncIndex(lkHex) };
    } catch (failure) {
      const held = await this.heldIndex(lkHex);
      if (held === undefined) throw indexSyncFailure(lkHex, failure);
      return { index: held, failure };
    }
  }

  private lookupContext(lkHex: string): ClientPirContext | undefined {
    return this.clientPirContexts.get(`t2Path:${this.chainId}:${lkHex}`);
  }

  private servesList(lkHex: string): boolean {
    return this.lookupContext(lkHex) !== undefined;
  }

  /**
   * Where a list index is asked: the instance holding its PPOI block, at the leaf's row in that
   * block. There is no whole-list path instance, so a block with no label is refused, as is an
   * index past the instance's rows, whose row was never written.
   */
  private listRowTarget(
    lkHex: string,
    idx: number,
    ctx: ClientPirContext,
    listRows: number,
  ): ListRowTarget {
    const block = Math.floor(idx / LEAVES_PER_PPOI_BLOCK);
    const leaf = idx - block * LEAVES_PER_PPOI_BLOCK;
    const labelKey = `t2Path:${this.chainId}:${lkHex}:${block}`;
    const label = this.clientPirInstanceLabels.get(labelKey);
    if (label === undefined) {
      throw RavenError.invalidQuery(
        `client-PIR: list ${lkHex} index ${idx} is in PPOI block ${block}, which has no path ` +
          `instance label; set clientPirInstanceLabels "${labelKey}"`,
      );
    }
    let capacity: number;
    try {
      capacity = decodeShardGeometry(ctx.shardConfigBincode).totalEntries;
    } catch (cause) {
      throw RavenError.invalidQuery(
        `client-PIR ${label}: the context's shard config gives no row count, so no index can be ` +
          `shown to be held (${cause instanceof Error ? cause.message : String(cause)})`,
      );
    }
    if (leaf >= capacity) {
      throw RavenError.invalidQuery(
        `client-PIR ${label}: list index ${idx} (row ${leaf} of block ${block}) is past the ` +
          `instance's capacity of ${capacity} rows, so no row there was ever written; refused ` +
          "rather than answered",
      );
    }
    const rowsBelow = listRows - block * LEAVES_PER_PPOI_BLOCK;
    return { block, leaf, label, rows: Math.max(leaf + 1, Math.min(capacity, rowsBelow)) };
  }

  private async getPOIMerkleProofsClientPir(
    listKey: string,
    blindedCommitments: string[],
  ): Promise<MerkleProof[]> {
    const lkHex = normalizeHex(listKey);
    const ctx = this.lookupContext(lkHex);
    if (!ctx) {
      throw RavenError.invalidQuery(
        `client-PIR: no t2Path context for list ${lkHex} on chain ${this.chainId}; preload one ` +
          "via loadClientPirContext before calling getPOIMerkleProofs",
      );
    }
    const source = await this.listSource(lkHex);
    // No proof exists for an absence, and its refusal says whether it could be shown current.
    const notPresent = (bcHex: string, absences: number): RavenError => {
      if (source.failure !== undefined) return indexSyncFailure(lkHex, source.failure);
      this.counters.absent += absences;
      return RavenError.invalidQuery(
        `client-PIR: blinded commitment ${bcHex} not present in list ${lkHex} (the index holds ` +
          `the ${source.index.total} rows the node serves)`,
      );
    };
    // Resolve every commitment before any row query goes out: an unknown blinded commitment
    // refuses without having disclosed the others, and the grouping below needs the whole set.
    const bcHexes = blindedCommitments.map((bc) => canonicalCommitmentHex(bc));
    const candidateSets = indexCandidatesForEach(source.index, bcHexes);
    const listRows = Math.max(1, source.index.total);
    const firstAbsent = candidateSets.findIndex((candidates) => candidates.length === 0);
    if (firstAbsent !== -1) {
      throw notPresent(
        bcHexes[firstAbsent],
        candidateSets.filter((candidates) => candidates.length === 0).length,
      );
    }
    let pending = blindedCommitments.map((_bc, position) => ({
      bcHex: bcHexes[position],
      position,
      candidates: candidateSets[position],
      next: 0,
    }));

    // Group by block (each block is its own instance), then pad each group on the ladder so the
    // server learns only that a chunk holds k real targets with k in (P/2, P]; at P = 1 and
    // P = 2 that bucket is exact. A later round exists only for a prefix collision.
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
        const at = this.listRowTarget(lkHex, target.candidates[target.next], ctx, listRows);
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
          // Encrypted row queries only: the block and each query's shard travel in the clear, the row does not.
          const privateReply = await this.runClientPirQueryBatch(
            pathInstance,
            ctx,
            chunk.map(({ at }) => at.leaf),
            rows,
          );
          this.privateFreshnessAction(privateReply.freshness);
          for (let slot = 0; slot < chunk.length; slot += 1) {
            const { target, at } = chunk[slot];
            const { bcHex, position } = target;
            const localIndex = at.leaf;
            const row = privateReply.plaintexts[slot];
            const addendum = privateReply.addenda[slot];
            if (
              !row ||
              row.length !== PATH10_ROW_BYTES ||
              new TextDecoder().decode(row.slice(34, 38)) !== "RVP2"
            ) {
              throw RavenError.decodeError(`client-PIR ${pathInstance}: malformed PPOI v2 row`);
            }
            if (sharesOnlyPrefix(row.subarray(0, 32), hexToBytes(bcHex))) {
              target.next += 1;
              if (target.next === target.candidates.length) throw notPresent(bcHex, 1);
              collided.push(target);
              continue;
            }
            if (bytesToHex(row.slice(0, 32)) !== bcHex) {
              throw RavenError.decodeError(
                `client-PIR ${pathInstance}: row leaf does not match the requested blinded commitment`,
              );
            }
            if (!addendum || addendum.length !== PATH10_ADDENDUM_BYTES) {
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
      // `invalidQuery`, not `staleData`: StaleData needs lag and confidence figures a missing
      // pin does not have.
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
      // A block that froze inside the tail TTL is still answered from its filling window, which
      // lacks the final root, so re-ask before refusing. The re-ask costs three requests, one
      // naming the block, on every window miss.
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

  private pinnedRootFor(rootKey: string): string | undefined {
    return this.ppoiPinnedRoots.get(`${this.chainId}:${rootKey}`);
  }

  /** Build, pad, and decrypt one `/batch` request, splitting each slot's upper-sibling addendum
   *  off its tail. Covers address rows below `populatedRows`. */
  private async runClientPirQueryBatch(
    instanceLabel: string,
    ctx: ClientPirContext,
    targetIndices: readonly number[],
    populatedRows: number,
  ): Promise<PrivateQueryBatchResult> {
    return this.withClientPirSessionRetry(instanceLabel, ctx, async () => {
      const route = this.route();
      const { entriesPerShard } = decodeShardGeometry(ctx.shardConfigBincode);
      const plan = buildPaddedQueryPlan(targetIndices, entriesPerShard, populatedRows);
      const queryBundles = plan.wireTargets.map((targetIdx) =>
        decodeClientPirQueryBundle(
          callWasm("client-PIR query", () =>
            ctx.wasm.build_seeded_query(ctx.session, ctx.shardConfigBincode, BigInt(targetIdx)),
          ),
        ),
      );
      const batchBody = encodeBatchBody(queryBundles.map(({ queryBytes }) => queryBytes));
      const url = `${route.endpoint}/v1/instance/${encodeURIComponent(instanceLabel)}/batch`;
      this.captureRequest(url, "POST", batchBody);
      const res = await this.postClientPirRequest(instanceLabel, url, batchBody);
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
        responses[slot].slice(responses[slot].length - PATH10_ADDENDUM_BYTES),
      );
      const plaintexts = plan.realSlots.map((slot) =>
        callWasm(`client-PIR batch ${instanceLabel}`, () =>
          ctx.wasm.extract_response(
            ctx.session,
            ctx.crsBincode,
            queryBundles[slot].clientStateBincode,
            responses[slot].slice(0, -PATH10_ADDENDUM_BYTES),
            ctx.entrySize,
          ),
        ),
      );
      return { plaintexts, addenda, freshness };
    });
  }

  private async withClientPirSessionRetry<T>(
    instanceLabel: string,
    ctx: ClientPirContext,
    query: () => Promise<T>,
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
            `client-PIR batch ${instanceLabel}: replacement session handle was refused`,
            { url: cause.url, status: 409 },
          );
        }
      }
    }
    throw RavenError.serverError(
      `client-PIR batch ${instanceLabel}: session retry exhausted`,
      { status: 409 },
    );
  }

  private async postClientPirRequest(
    instanceLabel: string,
    url: string,
    requestBody: Uint8Array,
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
      throw RavenError.network(`client-PIR batch ${instanceLabel}`, {
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
        throw RavenError.staleAdapter(`client-PIR batch ${instanceLabel}: schema mismatch`, {
          url,
          status: 400,
          serverWireSchemaVersion: serverVersion ?? undefined,
          clientWireSchemaVersion: WIRE_SCHEMA_VERSION,
        });
      }
    }
    if (!response.ok) {
      throw RavenError.serverError(`client-PIR batch ${instanceLabel}: ${response.status}`, {
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
      callWasm(`client-PIR session ${instanceLabel}`, () =>
        ctx.wasm.install_server_session_handle(ctx.session, handle),
      );
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
        `client-PIR ${instanceLabel}: WASM lacks the remote-session exports; install the ` +
          "@hisoka-io/raven-inspire-client-wasm this SDK names as a peer",
      );
    }
    const route = this.route();
    const credential = bearerHeaders(route.bearerToken);
    const clientId = this.clientPirClientId(instanceLabel);
    const body = callWasm(`client-PIR session ${instanceLabel}`, () =>
      ctx.wasm.client_packing_keys_versioned(ctx.session),
    );
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

  /** Accepts a fresh reply and refuses anything else: there is no private way to re-ask. */
  private privateFreshnessAction(privateFreshness: PrivateFreshness): void {
    const operation = "t2-auth-path";
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
    if (freshness.confidence >= this.confidenceFloor) return;
    throw RavenError.staleData(
      `private ${operation} response is stale: confidence ${freshness.confidence} < floor ` +
        `${this.confidenceFloor} (lag_blocks=${freshness.lagBlocks}, ` +
        `applied_height=${freshness.appliedHeight}, epoch=${freshness.epoch})`,
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

  private async upstreamJsonRpc<T>(
    method: UpstreamJsonRpcMethod,
    params: Readonly<Record<string, unknown>>,
    allowMissingResult = false,
  ): Promise<T> {
    if (!this.upstream) {
      throw RavenError.invalidQuery("upstreamFallbackEndpoint is not configured");
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
      if (!response.ok) {
        throw RavenError.serverError(`upstream ${method}: HTTP ${response.status}`, {
          url,
          status: response.status,
          cause: String(cause),
        });
      }
      throw RavenError.decodeError(`upstream ${method}: response is not valid JSON`, {
        url,
        status: response.status,
        cause: String(cause),
      });
    }
    // A non-2xx is the status talking unless it carries this call's JSON-RPC error.
    if (!response.ok && !isRpcErrorEnvelope(decoded, id)) {
      throw RavenError.serverError(`upstream ${method}: HTTP ${response.status}`, {
        url,
        status: response.status,
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
    return envelope.result as T;
  }

  private captureRequest(url: string, method: string, body: Uint8Array): void {
    const ring = this.capturedRequests;
    if (ring === undefined) return;
    if (ring.length >= WIRE_CAPTURE_CAP) ring.shift();
    ring.push({ url, method, body });
  }
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

/** A JSON-RPC 2.0 error answer to request `id`, and nothing else. */
function isRpcErrorEnvelope(decoded: unknown, id: number): boolean {
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) return false;
  const envelope = decoded as Record<string, unknown>;
  const error = envelope.error;
  return (
    envelope.jsonrpc === "2.0" &&
    envelope.id === id &&
    !Object.prototype.hasOwnProperty.call(envelope, "result") &&
    typeof error === "object" &&
    error !== null &&
    !Array.isArray(error) &&
    Number.isInteger((error as Record<string, unknown>).code) &&
    typeof (error as Record<string, unknown>).message === "string"
  );
}

/** A malformed pin can never equal a fold, so without these checks a caller's own typo would
 *  surface as `DecodeError`, the kind that blames the node for forging the path. */
function checkedPinnedRoot(pin: unknown, rootKey: string, label: string): string {
  if (typeof pin !== "string") {
    throw RavenError.invalidQuery(`${label}: pinned root for ${rootKey} is a ${typeof pin}, not a hex string`);
  }
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
function indexSyncFailure(lkHex: string, cause: unknown): RavenError {
  const message =
    `the index for list ${lkHex} could not be brought up to the list the node serves ` +
    `(${String(cause)}), so an absence from it cannot be shown current`;
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

/** The commitments whose every served list carries an engine verdict, under the caller's own
 *  list key. Any other is left out, since engine replaces a commitment's stored map with what it
 *  is given. */
function engineVerdicts(
  answered: PoisPerListResponse,
  listKeys: readonly string[],
  unestablished: ReadonlySet<string>,
): PoisPerListResponse {
  const out: PoisPerListResponse = {};
  for (const [bcKey, perList] of Object.entries(answered)) {
    if (unestablished.has(bcKey)) continue;
    const statuses = Object.values(perList) as string[];
    if (
      statuses.every((status) => ENGINE_STATUSES.includes(status)) &&
      listKeys.every((listKey) => Object.prototype.hasOwnProperty.call(perList, listKey))
    ) {
      out[bcKey] = perList;
    }
  }
  return out;
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
 * auth path. The callers have opposite safe defaults (the disclosure guard treats unknown as
 * same-party and refuses; the resolver treats it as different and builds an anchor that may be
 * vacuous), and one boolean would give both the disclosure guard's answer, disabling verification
 * for any deployment whose endpoint is same-origin relative.
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
  TREE_DEPTH,
  PATH_RECORD_BYTES,
  WIRE_SCHEMA_VERSION,
};
export type {
  ClientPirContext,
  RavenInspireWasm,
  RavenInspireClientSession,
  ClientPirQueryBundle,
} from "./client-pir";
export type { POIStatus } from "./poi-pir";
