/** Per-chain routing table mapping `chainId` to adapter URL + bearer token. */

import { RavenError } from "./errors";
import type { StatusBody } from "./events-stream";

export interface ChainRegistryEntry {
  /** EVM chain id this adapter serves (1 = mainnet, 11155111 = Sepolia, ...). */
  readonly chainId: number;
  /** Base URL of the raven-railgun deployment, no trailing slash. */
  readonly endpoint: string;
  /** Bearer token used for `Authorization: Bearer <token>` headers. */
  readonly bearerToken: string;
  /** Oldest epoch across this chain's instances; 0 if unknown. A newest-wins summary would
   * report an instance as current while an older one still serves a superseded snapshot. */
  readonly epoch?: number;
  /** Snapshot epoch per instance id - the grain `X-Raven-Epoch` is served at. */
  readonly instanceEpochs?: ReadonlyMap<string, number>;
  /** Wire schema version; caller-supplied, since `/v1/status` does not report one. 0 if unknown. */
  readonly schemaVersion?: number;
}

/** Per-request routing table; one entry per chain. */
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
      instanceEpochs: new Map(e.instanceEpochs ?? []),
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

  /** Re-fetch `/v1/status` and update the per-instance epochs; entry unchanged on error. */
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
    const instances = statusInstancesIn(body, chainId, url);
    const instanceEpochs = new Map(instances.map((i) => [i.id, i.epoch]));
    const next: ChainRegistryEntry = {
      chainId: e.chainId,
      endpoint: e.endpoint,
      bearerToken: e.bearerToken,
      epoch: instances.length === 0 ? 0 : Math.min(...instanceEpochs.values()),
      instanceEpochs,
      schemaVersion: e.schemaVersion ?? 0,
    };
    this.entries.set(chainId, next);
    return next;
  }

  /** Override the fetch impl (test hook). */
  setFetchImpl(fetchImpl: typeof fetch): void {
    this.fetchImpl = fetchImpl;
  }
}

function statusInstancesIn(
  body: unknown,
  chainId: number,
  url: string,
): StatusBody["instances"] {
  const instances = typeof body === "object" && body !== null
    ? (body as { instances?: unknown }).instances
    : undefined;
  if (!Array.isArray(instances)) {
    throw RavenError.decodeError(
      `ChainRegistry.refresh: /v1/status for chain ${chainId} carries no "instances" array ` +
        `(got ${describeJson(body)}); the {epoch, wire_schema_version} shape is /v1/instance/{id}/params`,
      { url },
    );
  }
  return instances.map((row, at) => parseInstanceStatus(row, at, chainId, url));
}

function parseInstanceStatus(
  row: unknown,
  at: number,
  chainId: number,
  url: string,
): StatusBody["instances"][number] {
  const reject = (why: string): never => {
    throw RavenError.decodeError(
      `ChainRegistry.refresh: /v1/status for chain ${chainId} instance[${at}] ${why}`,
      { url },
    );
  };
  if (typeof row !== "object" || row === null) {
    return reject(`is ${describeJson(row)}, not an object`);
  }
  const fields = row as Record<string, unknown>;
  const text = (name: string): string =>
    typeof fields[name] === "string" ? (fields[name] as string) : reject(`has no string "${name}"`);
  const count = (name: string): number =>
    typeof fields[name] === "number" &&
    Number.isInteger(fields[name]) &&
    (fields[name] as number) >= 0
      ? (fields[name] as number)
      : reject(`has no non-negative integer "${name}" (got ${describeJson(fields[name])})`);
  return {
    id: text("id"),
    epoch: count("epoch"),
    role: text("role"),
    drain_state: text("drain_state"),
    in_flight: count("in_flight"),
    active_k_concurrency: count("active_k_concurrency"),
  };
}

function describeJson(value: unknown): string {
  if (value === undefined) return "undefined";
  if (value === null) return "null";
  if (Array.isArray(value)) return `array(${value.length})`;
  if (typeof value === "object") return `object{${Object.keys(value).join(",")}}`;
  return JSON.stringify(value);
}
