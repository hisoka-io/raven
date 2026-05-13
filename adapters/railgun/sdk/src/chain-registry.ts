/**
 * Multi-chain raven-railgun adapter routing registry.
 *
 * Wallet integrators run one raven-railgun deployment per chain;
 * `ChainRegistry` is the table the SDK consults to map a `chainId`
 * to the right adapter URL + bearer token. The table is initially
 * seeded by the wallet (per-chain config) and refreshed from the
 * server's `/v1/status` route on bootstrap or on observed epoch
 * advance.
 */

import { RavenError } from "./errors";

export interface ChainRegistryEntry {
  /** EVM chain id this adapter serves (1 = mainnet, 11155111 = Sepolia, ...). */
  readonly chainId: number;
  /** Base URL of the raven-railgun deployment, no trailing slash. */
  readonly endpoint: string;
  /** Bearer token used for `Authorization: Bearer <token>` headers. */
  readonly bearerToken: string;
  /** Last observed epoch (server-supplied; opaque). 0 if unknown. */
  readonly epoch?: number;
  /** Last observed schema version (server-supplied). 0 if unknown. */
  readonly schemaVersion?: number;
}

/**
 * Routing table the SDK consults per request. Uses a `Map<chainId,
 * Entry>` so lookups are O(1) and multi-chain wallets can register
 * one entry per chain.
 */
export class ChainRegistry {
  private readonly entries: Map<number, ChainRegistryEntry> = new Map();
  private fetchImpl: typeof fetch;

  constructor(seed: ChainRegistryEntry[] = [], fetchImpl: typeof fetch = fetch) {
    this.fetchImpl = fetchImpl;
    for (const e of seed) {
      this.upsert(e);
    }
  }

  /** Insert / overwrite the entry for `e.chainId`. */
  upsert(e: ChainRegistryEntry): void {
    if (!Number.isInteger(e.chainId) || e.chainId <= 0) {
      throw RavenError.invalidQuery(`ChainRegistry: chainId ${e.chainId} must be a positive integer`);
    }
    if (e.endpoint.length === 0) {
      throw RavenError.invalidQuery("ChainRegistry: endpoint must be non-empty");
    }
    this.entries.set(e.chainId, {
      chainId: e.chainId,
      endpoint: e.endpoint.replace(/\/$/, ""),
      bearerToken: e.bearerToken,
      epoch: e.epoch ?? 0,
      schemaVersion: e.schemaVersion ?? 0,
    });
  }

  /** Look up the entry for `chainId`; throws an `InvalidQuery` if missing. */
  resolve(chainId: number): ChainRegistryEntry {
    const e = this.entries.get(chainId);
    if (!e) {
      throw RavenError.invalidQuery(
        `ChainRegistry: no adapter registered for chain ${chainId}; ` +
          `register via ChainRegistry.upsert before issuing PIR queries`,
      );
    }
    return e;
  }

  /** All currently-registered chain ids. */
  knownChainIds(): number[] {
    return Array.from(this.entries.keys()).sort((a, b) => a - b);
  }

  /**
   * Re-fetch `/v1/status` for the named chain and update the cached
   * `epoch` + `schemaVersion`. The /v1/status route returns a JSON
   * body with `epoch` and `wire_schema_version` fields; on a 4xx /
   * 5xx the registry entry is left unchanged but the call surfaces
   * a typed error.
   */
  async refresh(chainId: number): Promise<ChainRegistryEntry> {
    const e = this.resolve(chainId);
    const url = `${e.endpoint}/v1/status`;
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        headers: { authorization: `Bearer ${e.bearerToken}` },
      });
    } catch (cause) {
      throw RavenError.network(`ChainRegistry.refresh: network error for chain ${chainId}`, {
        url,
        cause: String(cause),
      });
    }
    if (!res.ok) {
      throw RavenError.serverError(
        `ChainRegistry.refresh: server returned ${res.status} for chain ${chainId}`,
        { url, status: res.status },
      );
    }
    let body: unknown;
    try {
      body = await res.json();
    } catch (cause) {
      throw RavenError.decodeError(`ChainRegistry.refresh: malformed JSON for chain ${chainId}`, {
        url,
        cause: String(cause),
      });
    }
    const status = body as { epoch?: unknown; wire_schema_version?: unknown };
    const epoch = typeof status.epoch === "number" ? status.epoch : e.epoch ?? 0;
    const schemaVersion =
      typeof status.wire_schema_version === "number"
        ? status.wire_schema_version
        : e.schemaVersion ?? 0;
    const next: ChainRegistryEntry = {
      chainId: e.chainId,
      endpoint: e.endpoint,
      bearerToken: e.bearerToken,
      epoch,
      schemaVersion,
    };
    this.entries.set(chainId, next);
    return next;
  }

  /** Override the fetch impl (test hook). */
  setFetchImpl(fetchImpl: typeof fetch): void {
    this.fetchImpl = fetchImpl;
  }
}
