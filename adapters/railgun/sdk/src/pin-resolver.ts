/**
 * Independent PPOI block roots, read from the upstream Railgun aggregator.
 *
 * A root fetched from the node that served the auth path proves nothing, so the pin has to
 * come from somewhere else. Every byte of both requests below is a function of public state
 * only -- a list key, a block number, and upstream's own tip -- so the request is
 * byte-identical for every wallet asking about the same block and carries no
 * note-identifying information.
 */

import { RavenError } from "./errors";

/** Leaves per PPOI block; upstream calls the same span a "tree" and indexes it identically. */
export const LEAVES_PER_PPOI_BLOCK = 65_536;

/** Leaves read back from the tip when the block is still filling. Upstream refuses a range
 *  wider than 500 leaves, so this has room to grow if a node's lag ever needs it. */
export const PIN_TAIL_WINDOW = 64;

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
  readonly onRequest?: PinRequestObserver;
}

// Upstream keys node status by its own network NAME, not by chain id, and a wrong name
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
    const frozen = await this.pointQuery(listKey, block, lastIndex);
    if (frozen) {
      this.frozenRoots.set(cacheKey, frozen);
      return { roots: frozen, window: { startIndex: lastIndex, endIndex: lastIndex, frozen: true } };
    }

    const now = Date.now();
    const cachedTail = this.tailPins.get(cacheKey);
    if (cachedTail && cachedTail.expiresAt > now) {
      return cachedTail.value;
    }
    const resolved = await this.tailWindow(listKey, block);
    this.tailPins.set(cacheKey, { expiresAt: now + this.tailTtlMs, value: resolved });
    return resolved;
  }

  /** The block's last leaf, as a zero-width range. Upstream rejects only `> 500` and `< 0`,
   *  and filters inclusively at both ends, so this returns at most one row. */
  private async pointQuery(
    listKey: string,
    block: number,
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
    );
    const roots = this.rootsInBlock(rows, block);
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
    );
    return {
      roots: this.rootsInBlock(rows, block),
      window: { startIndex, endIndex: latestIndex, frozen: false },
    };
  }

  /** The index filter is not decoration: clamping to the tail block still lets a window
   *  that began in block B-1 hand back B-1's root, which folds against a different tree. */
  private rootsInBlock(
    rows: readonly { index: number; root: string }[],
    block: number,
  ): ReadonlySet<string> {
    const out = new Set<string>();
    for (const row of rows) {
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

  /** Each row is one leaf's insert and the tree root written immediately after it. */
  private decodeEvents(result: unknown): { index: number; root: string }[] {
    if (!Array.isArray(result)) {
      throw RavenError.decodeError("pin resolver: ppoi_poi_events result is not an array", {
        url: this.endpoint,
      });
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
      throw RavenError.decodeError(`pin resolver ${method}: response is not valid JSON`, {
        url: this.endpoint,
        status: response.status,
        cause: String(cause),
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
    if (Object.prototype.hasOwnProperty.call(decoded, "error")) {
      const rpcError = decoded.error;
      const detail = isRecord(rpcError)
        ? `${String(rpcError.code)}: ${String(rpcError.message)}`
        : String(rpcError);
      throw RavenError.serverError(`pin resolver ${method} JSON-RPC error ${detail}`, {
        url: this.endpoint,
        status: response.status,
      });
    }
    if (!response.ok) {
      throw RavenError.serverError(`pin resolver ${method}: HTTP ${response.status}`, {
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
