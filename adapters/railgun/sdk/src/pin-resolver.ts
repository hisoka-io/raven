/**
 * Independent PPOI block roots, read from the upstream Railgun aggregator.
 *
 * A root fetched from the node that served the auth path proves nothing, so the pin comes from
 * elsewhere. Both requests are a function of public state only: a list key, a block number and
 * upstream's own tip. No blinded commitment is sent.
 *
 * The note is hidden and its block is not: `block` is `floor(noteLeafIndex / 65_536)`. Requests
 * for one block are identical between wallets apart from the JSON-RPC `id`, and the tail cache
 * makes a burst of proofs against one Raven snapshot cost one block-naming request. A fold whose
 * root moved off the cached window re-resolves from the point query, so a filling block that
 * takes a leaf between two proofs costs one such request per proof. A caller who needs the block
 * hidden preloads `ppoiPinnedRoots` and never reaches this module.
 */

import { RavenError } from "./errors";

/** Leaves per PPOI block; upstream calls the same span a "tree" and indexes it identically. */
export const LEAVES_PER_PPOI_BLOCK = 65_536;

/** Leaves read back from the tip when the block is still filling. Upstream refuses a range
 *  wider than 500 leaves, so this has room to grow if a node's lag ever needs it. */
export const PIN_TAIL_WINDOW = 64;

/** Default deadline for one pin request. */
const DEFAULT_PIN_REQUEST_TIMEOUT_MS = 10_000;

const DEFAULT_TAIL_TTL_MS = 15_000;
const ROOT_HEX_CHARS = 64;

/** Global leaf-index range actually queried; named in the refusal so an operator can tell
 *  "this node is lagging past the window" from "this node forged siblings". */
export interface PinWindow {
  readonly startIndex: number;
  readonly endIndex: number;
  /** True when the block is full, and its root therefore immutable forever. */
  readonly frozen: boolean;
}

export interface ResolvedPins {
  readonly roots: ReadonlySet<string>;
  readonly window: PinWindow;
}

/** Observer for outbound pin requests, so the SDK's privacy harness sees this path too. */
export type PinRequestObserver = (url: string, method: string, body: Uint8Array) => void;

export interface UpstreamPinResolverConfig {
  /** Upstream PPOI aggregator JSON-RPC endpoint. Never the Raven node being verified. */
  readonly endpoint: string;
  readonly fetchImpl: typeof fetch;
  readonly chainType: number;
  readonly chainId: number;
  readonly txidVersion: string;
  /** Upstream `NetworkName` for the status lookup; defaults from chainType/chainId. */
  readonly networkName?: string;
  readonly tailTtlMs?: number;
  /** Deadline for one pin request. A wallet is blocked on this, so it must not be unbounded. */
  readonly requestTimeoutMs?: number;
  readonly onRequest?: PinRequestObserver;
}

// Upstream keys node status by its own network name, not by chain id, and a wrong name
// silently reads another chain's tip. Derived from NETWORK_CONFIG entries that carry a
// `poi` section; anything else must be named explicitly.
const PPOI_NETWORK_NAMES: ReadonlyMap<string, string> = new Map([
  ["0:1", "Ethereum"],
  ["0:56", "BNB_Chain"],
  ["0:137", "Polygon"],
  ["0:42161", "Arbitrum"],
  ["0:11155111", "Ethereum_Sepolia"],
  ["0:80002", "Polygon_Amoy"],
]);

/** Upstream `NetworkName` for an EVM chain, or `undefined` when the pair is not known here. */
export function ppoiNetworkName(chainType: number, chainId: number): string | undefined {
  return PPOI_NETWORK_NAMES.get(`${chainType}:${chainId}`);
}

/** Strip `0x` and lowercase, exactly as the fold's own comparison does. No padding: a root
 *  of the wrong width is a malformed answer, not a mismatch. */
function normalizeRootHex(hex: string): string {
  return (hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex).toLowerCase();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export class UpstreamPinResolver {
  private readonly endpoint: string;
  private readonly fetchImpl: typeof fetch;
  private readonly chainType: number;
  private readonly chainId: number;
  private readonly txidVersion: string;
  private readonly networkName: string;
  private readonly tailTtlMs: number;
  private readonly onRequest: PinRequestObserver | undefined;
  private readonly requestTimeoutMs: number;

  // A full block's root can never change, so this entry is correct for the process lifetime.
  private readonly frozenRoots = new Map<string, ReadonlySet<string>>();
  // The tail moves. In memory only, never persisted: a stale pin on disk outlives the
  // reason it was believed.
  private readonly tailPins = new Map<string, { expiresAt: number; value: ResolvedPins }>();
  private nextRequestId = 1;

  constructor(config: UpstreamPinResolverConfig) {
    this.endpoint = config.endpoint.replace(/\/$/, "");
    if (this.endpoint.length === 0) {
      throw RavenError.invalidQuery("pin resolver: upstream endpoint must be non-empty");
    }
    this.fetchImpl = config.fetchImpl;
    this.chainType = config.chainType;
    this.chainId = config.chainId;
    this.txidVersion = config.txidVersion;
    const networkName = config.networkName ?? ppoiNetworkName(config.chainType, config.chainId);
    if (networkName === undefined || networkName.length === 0) {
      throw RavenError.invalidQuery(
        `pin resolver: no upstream network name known for chain ${config.chainType}:${config.chainId}; ` +
          "set pinUpstreamNetworkName to the name upstream reports under forNetwork",
      );
    }
    this.networkName = networkName;
    this.tailTtlMs = config.tailTtlMs ?? DEFAULT_TAIL_TTL_MS;
    if (!Number.isFinite(this.tailTtlMs) || this.tailTtlMs < 0) {
      throw RavenError.invalidQuery(
        `pin resolver: tail TTL must be finite and non-negative, got ${this.tailTtlMs}`,
      );
    }
    this.onRequest = config.onRequest;
    this.requestTimeoutMs = config.requestTimeoutMs ?? DEFAULT_PIN_REQUEST_TIMEOUT_MS;
  }

  /**
   * Drop the cached tail answer for one block, so the next `resolve` re-asks upstream.
   *
   * A block that freezes inside the TTL is still answered from its filling window, which lacks
   * the final root; forgetting once and re-resolving turns that refusal into a correct answer.
   * The frozen cache is never dropped: a full tree's root is immutable, so a miss against it is
   * a real mismatch.
   */
  forgetTail(listKeyHex: string, block: number): void {
    this.tailPins.delete(`${normalizeRootHex(listKeyHex)}:${block}`);
  }

  /** Every root upstream is willing to certify for this block. */
  async rootsFor(listKeyHex: string, block: number): Promise<Set<string>> {
    return new Set((await this.resolve(listKeyHex, block)).roots);
  }

  /** As `rootsFor`, plus the window that produced them. */
  async resolve(listKeyHex: string, block: number): Promise<ResolvedPins> {
    const listKey = normalizeRootHex(listKeyHex);
    if (listKey.length !== ROOT_HEX_CHARS || !/^[0-9a-f]+$/.test(listKey)) {
      throw RavenError.invalidQuery(
        `pin resolver: list key must be 64 hex chars, got ${listKey.length}`,
      );
    }
    if (!Number.isInteger(block) || block < 0) {
      throw RavenError.invalidQuery(`pin resolver: block must be a non-negative integer, got ${block}`);
    }
    const cacheKey = `${listKey}:${block}`;

    const lastIndex = block * LEAVES_PER_PPOI_BLOCK + (LEAVES_PER_PPOI_BLOCK - 1);
    const cachedFrozen = this.frozenRoots.get(cacheKey);
    if (cachedFrozen) {
      return { roots: cachedFrozen, window: { startIndex: lastIndex, endIndex: lastIndex, frozen: true } };
    }

    // One point query classifies the block AND answers it: a row at the block's last leaf
    // means the tree is full, so that row's root is the full tree's root and is immutable.
    // No row means the block is still filling (or is past the tip), which needs the window.
    // The tail cache is checked before the point query: `startIndex` names the note's block,
    // and a cached tail answer saves one block-naming request per proof.
    const now = Date.now();
    const cachedTail = this.tailPins.get(cacheKey);
    if (cachedTail && cachedTail.expiresAt > now) {
      return cachedTail.value;
    }

    const frozen = await this.pointQuery(listKey, lastIndex);
    if (frozen) {
      this.frozenRoots.set(cacheKey, frozen);
      return { roots: frozen, window: { startIndex: lastIndex, endIndex: lastIndex, frozen: true } };
    }

    const resolved = await this.tailWindow(listKey, block);
    this.tailPins.set(cacheKey, { expiresAt: now + this.tailTtlMs, value: resolved });
    return resolved;
  }

  /** The block's last leaf, as a zero-width range. Upstream rejects only `> 500` and `< 0`,
   *  and filters inclusively at both ends, so this returns at most one row. */
  private async pointQuery(
    listKey: string,
    lastIndex: number,
  ): Promise<ReadonlySet<string> | undefined> {
    const rows = this.decodeEvents(
      await this.jsonRpc("ppoi_poi_events", {
        chainType: String(this.chainType),
        chainID: String(this.chainId),
        txidVersion: this.txidVersion,
        listKey,
        startIndex: lastIndex,
        endIndex: lastIndex,
      }),
      lastIndex,
      lastIndex,
    );
    // Filtering by block here would accept any row that floor-divides to it, so an upstream
    // answering the zero-width query with an intermediate row would have that partial-tree
    // root cached as the block's immutable root for the process lifetime. The query names one
    // index; only that index may answer it.
    // At most one row, by the cap in `decodeEvents`, so a frozen block caches exactly one root.
    const roots = new Set<string>();
    for (const row of rows) {
      if (row.index !== lastIndex) continue;
      roots.add(row.root);
    }
    return roots.size === 0 ? undefined : roots;
  }

  private async tailWindow(listKey: string, block: number): Promise<ResolvedPins> {
    const latestIndex = (await this.historicalMerklerootsLength(listKey)) - 1;
    if (latestIndex < 0) {
      return { roots: new Set(), window: { startIndex: 0, endIndex: 0, frozen: false } };
    }
    const tailBlock = Math.floor(latestIndex / LEAVES_PER_PPOI_BLOCK);
    const startIndex = Math.max(tailBlock * LEAVES_PER_PPOI_BLOCK, latestIndex - (PIN_TAIL_WINDOW - 1));
    const rows = this.decodeEvents(
      await this.jsonRpc("ppoi_poi_events", {
        chainType: String(this.chainType),
        chainID: String(this.chainId),
        txidVersion: this.txidVersion,
        listKey,
        startIndex,
        endIndex: latestIndex,
      }),
      startIndex,
      latestIndex,
    );
    return {
      roots: this.rootsInBlock(rows, block, startIndex, latestIndex),
      window: { startIndex, endIndex: latestIndex, frozen: false },
    };
  }

  /** Two filters, both load-bearing. Block: a window that began in block B-1 would otherwise hand
   *  back B-1's root, which folds against a different tree. Range: the refusal quotes this window
   *  as what was checked, so a row upstream volunteered from outside it -- the block's first leaf,
   *  say -- must not be counted as a candidate the wallet's fold was measured against. `pointQuery`
   *  filters the same way. */
  private rootsInBlock(
    rows: readonly { index: number; root: string }[],
    block: number,
    startIndex: number,
    endIndex: number,
  ): ReadonlySet<string> {
    const out = new Set<string>();
    for (const row of rows) {
      if (row.index < startIndex || row.index > endIndex) continue;
      if (Math.floor(row.index / LEAVES_PER_PPOI_BLOCK) !== block) continue;
      out.add(row.root);
    }
    return out;
  }

  private async historicalMerklerootsLength(listKey: string): Promise<number> {
    const status = await this.jsonRpc("ppoi_node_status", {});
    if (!isRecord(status) || !isRecord(status.forNetwork)) {
      throw RavenError.decodeError("pin resolver: ppoi_node_status has no forNetwork object", {
        url: this.endpoint,
      });
    }
    const network = status.forNetwork[this.networkName];
    if (!isRecord(network) || !isRecord(network.listStatuses)) {
      throw RavenError.decodeError(
        `pin resolver: ppoi_node_status has no listStatuses for network ${this.networkName}`,
        { url: this.endpoint },
      );
    }
    // Upstream list keys are lowercase hex; the case-insensitive scan is the cheap
    // insurance against a node that echoes them back in another case.
    const statuses = network.listStatuses;
    const key =
      Object.prototype.hasOwnProperty.call(statuses, listKey)
        ? listKey
        : Object.keys(statuses).find((k) => k.toLowerCase() === listKey);
    const listStatus = key === undefined ? undefined : statuses[key];
    if (!isRecord(listStatus)) {
      throw RavenError.decodeError(
        `pin resolver: upstream does not serve list ${listKey} on network ${this.networkName}`,
        { url: this.endpoint },
      );
    }
    const length = listStatus.historicalMerklerootsLength;
    if (typeof length !== "number" || !Number.isInteger(length) || length < 0) {
      throw RavenError.decodeError(
        `pin resolver: historicalMerklerootsLength is ${String(length)}, not a non-negative integer`,
        { url: this.endpoint },
      );
    }
    return length;
  }

  /** Each row is one leaf's insert and the tree root written immediately after it. A list holds
   *  one row per index, so an answer longer than the range asked is refused before any is read. */
  private decodeEvents(
    result: unknown,
    startIndex: number,
    endIndex: number,
  ): { index: number; root: string }[] {
    if (!Array.isArray(result)) {
      throw RavenError.decodeError("pin resolver: ppoi_poi_events result is not an array", {
        url: this.endpoint,
      });
    }
    const width = endIndex - startIndex + 1;
    if (result.length > width) {
      throw RavenError.decodeError(
        `pin resolver: ppoi_poi_events answered leaves ${startIndex}..${endIndex} with ` +
          `${result.length} rows; the range holds at most ${width}`,
        { url: this.endpoint },
      );
    }
    return result.map((entry, position) => {
      if (!isRecord(entry) || !isRecord(entry.signedPOIEvent)) {
        throw RavenError.decodeError(
          `pin resolver: ppoi_poi_events row ${position} has no signedPOIEvent`,
          { url: this.endpoint },
        );
      }
      const index = entry.signedPOIEvent.index;
      if (typeof index !== "number" || !Number.isInteger(index) || index < 0) {
        throw RavenError.decodeError(
          `pin resolver: ppoi_poi_events row ${position} has index ${String(index)}, not a non-negative integer`,
          { url: this.endpoint },
        );
      }
      if (typeof entry.validatedMerkleroot !== "string") {
        throw RavenError.decodeError(
          `pin resolver: ppoi_poi_events row ${position} has no validatedMerkleroot string`,
          { url: this.endpoint },
        );
      }
      // Width is checked here rather than at the comparison for the same reason the
      // caller-supplied pin checks it: an unpadded 32-byte root can never equal a fold,
      // so it would surface as tampering by an honest node.
      const root = normalizeRootHex(entry.validatedMerkleroot);
      if (root.length !== ROOT_HEX_CHARS || !/^[0-9a-f]+$/.test(root)) {
        throw RavenError.decodeError(
          `pin resolver: ppoi_poi_events row ${position} root is ${root.length} hex chars, not ${ROOT_HEX_CHARS}`,
          { url: this.endpoint },
        );
      }
      return { index, root };
    });
  }

  private async jsonRpc(method: string, params: Readonly<Record<string, unknown>>): Promise<unknown> {
    const id = this.nextRequestId;
    this.nextRequestId = id === Number.MAX_SAFE_INTEGER ? 1 : id + 1;
    const body = JSON.stringify({ jsonrpc: "2.0", method, params, id });
    const encoded = new TextEncoder().encode(body);
    this.onRequest?.(this.endpoint, "POST", encoded);

    let response: Response;
    try {
      response = await this.fetchImpl(this.endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
        // A pin fetch blocks a proof the wallet is waiting on, and the endpoint is a third
        // party: without a deadline a silent upstream leaves that proof pending forever.
        // `AbortSignal.timeout` is the platform's own, so nothing leaks
        // when the fetch settles first.
        signal: AbortSignal.timeout(this.requestTimeoutMs),
      });
    } catch (cause) {
      throw RavenError.network(`pin resolver ${method}`, {
        url: this.endpoint,
        cause: String(cause),
      });
    }

    let decoded: unknown;
    try {
      decoded = await response.json();
    } catch (cause) {
      if (!response.ok) {
        throw RavenError.serverError(`pin resolver ${method}: HTTP ${response.status}`, {
          url: this.endpoint,
          status: response.status,
          cause: String(cause),
        });
      }
      throw RavenError.decodeError(`pin resolver ${method}: response is not valid JSON`, {
        url: this.endpoint,
        status: response.status,
        cause: String(cause),
      });
    }
    // A non-2xx is the status talking unless it carries this call's JSON-RPC error: a proxy's
    // 503 body, JSON or not, is not a malformed answer, and reading it as one makes it permanent.
    const carriesRpcError =
      isRecord(decoded) &&
      decoded.jsonrpc === "2.0" &&
      decoded.id === id &&
      decoded.error !== undefined &&
      decoded.error !== null;
    if (!response.ok && !carriesRpcError) {
      throw RavenError.serverError(`pin resolver ${method}: HTTP ${response.status}`, {
        url: this.endpoint,
        status: response.status,
      });
    }
    if (!isRecord(decoded)) {
      throw RavenError.decodeError(`pin resolver ${method}: JSON-RPC response is not an object`, {
        url: this.endpoint,
        status: response.status,
      });
    }
    if (decoded.jsonrpc !== "2.0" || decoded.id !== id) {
      throw RavenError.decodeError(
        `pin resolver ${method}: JSON-RPC envelope mismatch: version ${String(decoded.jsonrpc)}, ` +
          `id ${String(decoded.id)}, expected 2.0/${id}`,
        { url: this.endpoint, status: response.status },
      );
    }
    // Content, not presence: a proxy that spells success `"error": null` would otherwise turn
    // every pin fetch, and therefore every unpinned proof, into a refusal. JSON-RPC 2.0 says the
    // member is absent on success; tolerating the null spelling costs nothing.
    if (decoded.error !== undefined && decoded.error !== null) {
      const rpcError = decoded.error;
      const detail = isRecord(rpcError)
        ? `${String(rpcError.code)}: ${String(rpcError.message)}`
        : String(rpcError);
      throw RavenError.serverError(`pin resolver ${method} JSON-RPC error ${detail}`, {
        url: this.endpoint,
        status: response.status,
      });
    }
    if (!Object.prototype.hasOwnProperty.call(decoded, "result")) {
      throw RavenError.decodeError(
        `pin resolver ${method}: JSON-RPC response carries neither result nor error`,
        { url: this.endpoint, status: response.status },
      );
    }
    return decoded.result;
  }
}
