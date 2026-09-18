import { describe, expect, it } from "vitest";

import {
  RavenPOINodeInterface,
  type ClientPirContext,
  type RavenInspireWasm,
} from "../src/index";
import {
  encodeBatchResponseNodes,
  encodedBatchCount,
  NODE_BYTES,
  stubWasm,
  TOKEN,
} from "./helpers/auth_path_stub";
import { STUB_QUERY_BYTES, stubQueryBundle } from "./helpers/private_wire";

const TRANSACTION_COUNT = 20_000;
const INPUTS_PER_TRANSACTION = 2;
const SPENDS_PER_MONTH = 8;
const SESSION_TTL_MS = 3_600_000;
const MONTH_MS = 30 * 24 * 60 * 60 * 1_000;
const TRACE_SEED = 0x5_04_cade;

interface CadenceDistribution {
  readonly handshakesByMonth: readonly number[];
  readonly handshakes: number;
  readonly queries: number;
  readonly refusals: number;
  readonly batchAttempts: number;
}

interface ReplayServerState {
  now: number;
  activeHandle: bigint | undefined;
  expiresAt: number;
  nextHandle: bigint;
  handshakes: number;
  refusals: number;
  batchAttempts: number;
  readonly handshakesByMonth: number[];
}

function seededUniform(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 0x1_0000_0000;
  };
}

function transactionTrace(): readonly number[] {
  const uniform = seededUniform(TRACE_SEED);
  const meanGapMs = MONTH_MS / SPENDS_PER_MONTH;
  const timestamps: number[] = [];
  let timestamp = 0;
  for (let index = 0; index < TRANSACTION_COUNT; index += 1) {
    const sample = Math.max(uniform(), Number.EPSILON);
    timestamp += -Math.log(sample) * meanGapMs;
    timestamps.push(Math.floor(timestamp));
  }
  return timestamps;
}

function oracleCadence(timestamps: readonly number[]): CadenceDistribution {
  const lastMonth = Math.floor((timestamps.at(-1) ?? 0) / MONTH_MS);
  const handshakesByMonth = Array.from({ length: lastMonth + 1 }, () => 0);
  let expiresAt = Number.NEGATIVE_INFINITY;
  let handshakes = 0;
  for (const timestamp of timestamps) {
    if (timestamp >= expiresAt) {
      handshakes += 1;
      handshakesByMonth[Math.floor(timestamp / MONTH_MS)] += 1;
      expiresAt = timestamp + SESSION_TTL_MS;
    }
  }
  return {
    handshakesByMonth,
    handshakes,
    queries: timestamps.length * INPUTS_PER_TRANSACTION,
    refusals: Math.max(0, handshakes - 1),
    batchAttempts: timestamps.length * INPUTS_PER_TRANSACTION + Math.max(0, handshakes - 1),
  };
}

async function replayActualSdk(_timestamps: readonly number[]): Promise<CadenceDistribution> {
  const timestamps = _timestamps;
  const lastMonth = Math.floor((timestamps.at(-1) ?? 0) / MONTH_MS);
  const server: ReplayServerState = {
    now: 0,
    activeHandle: undefined,
    expiresAt: Number.NEGATIVE_INFINITY,
    nextHandle: 1n,
    handshakes: 0,
    refusals: 0,
    batchAttempts: 0,
    handshakesByMonth: Array.from({ length: lastMonth + 1 }, () => 0),
  };
  let installedHandle: bigint | undefined;
  const baseWasm = stubWasm();
  const wasm: RavenInspireWasm = {
    ...baseWasm,
    client_packing_keys_versioned: () => new Uint8Array([0, 6, 5, 0, 4]),
    install_server_session_handle: (_session, handle) => {
      installedHandle = handle;
    },
    build_seeded_query: () => {
      if (installedHandle === undefined) {
        throw new Error("cadence replay built a query before installing a server handle");
      }
      const query = new Uint8Array(STUB_QUERY_BYTES);
      new DataView(query.buffer).setBigUint64(0, installedHandle, true);
      return stubQueryBundle(query);
    },
  };
  const context: ClientPirContext = {
    wasm,
    session: { free: () => undefined },
    crsBincode: new Uint8Array(0),
    shardConfigBincode: new Uint8Array(0),
    entrySize: NODE_BYTES,
  };
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = requestUrl(input);
    if (url.endsWith("/session")) {
      const handle = server.nextHandle;
      server.nextHandle += 1n;
      server.activeHandle = handle;
      server.expiresAt = server.now + SESSION_TTL_MS;
      server.handshakes += 1;
      server.handshakesByMonth[Math.floor(server.now / MONTH_MS)] += 1;
      return new Response(JSON.stringify({ handle: Number(handle), expires_at_unix_secs: 0 }), {
        status: 200,
        headers: {
          "content-type": "application/json",
          "x-raven-session": handle.toString(),
        },
      });
    }
    if (!url.endsWith("/batch")) {
      return new Response("not found", { status: 404 });
    }
    server.batchAttempts += 1;
    const body = await requestBody(init?.body);
    const handle = new DataView(body.buffer, body.byteOffset, body.byteLength).getBigUint64(10, true);
    if (handle !== server.activeHandle || server.now >= server.expiresAt) {
      server.refusals += 1;
      return new Response(null, {
        status: 409,
        headers: { "x-raven-schema-version": "6" },
      });
    }
    const count = encodedBatchCount(body);
    const nodes = Array.from({ length: count }, () => new Uint8Array(NODE_BYTES));
    return new Response(ownedBuffer(encodeBatchResponseNodes(nodes)), {
      status: 200,
      headers: {
        "content-type": "application/octet-stream",
        "x-raven-epoch": "1",
        "x-raven-schema-version": "6",
        "x-raven-freshness": "lag_blocks=0 applied_height=1 epoch=1 confidence=1.000",
      },
    });
  };
  const sdk = new RavenPOINodeInterface({
    endpoint: "https://cadence.invalid",
    bearerToken: TOKEN,
    useClientPir: true,
    fetchImpl,
    clientPirContexts: new Map([["t3CommitTree:0", context]]),
  });

  let queries = 0;
  for (let transaction = 0; transaction < timestamps.length; transaction += 1) {
    server.now = timestamps[transaction];
    const firstLeaf = (transaction * INPUTS_PER_TRANSACTION) % 65_536;
    for (let input = 0; input < INPUTS_PER_TRANSACTION; input += 1) {
      await sdk.getMerkleProof(0, firstLeaf + input);
      queries += 1;
    }
  }
  return {
    handshakesByMonth: server.handshakesByMonth,
    handshakes: server.handshakes,
    queries,
    refusals: server.refusals,
    batchAttempts: server.batchAttempts,
  };
}

function ownedBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

async function requestBody(body: BodyInit | null | undefined): Promise<Uint8Array> {
  if (body instanceof Uint8Array) return body;
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (ArrayBuffer.isView(body)) {
    return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  }
  if (body instanceof Blob) return new Uint8Array(await body.arrayBuffer());
  throw new Error(`cadence replay expected a binary request body, got ${typeof body}`);
}

function percentile(sorted: readonly number[], fraction: number): number {
  const index = Math.floor((sorted.length - 1) * fraction);
  return sorted[index] ?? 0;
}

function summarize(distribution: CadenceDistribution): Record<string, unknown> {
  const sorted = [...distribution.handshakesByMonth].sort((left, right) => left - right);
  const mean = sorted.reduce((sum, count) => sum + count, 0) / sorted.length;
  const variance =
    sorted.reduce((sum, count) => sum + (count - mean) ** 2, 0) / sorted.length;
  const histogram: Record<string, number> = {};
  for (const count of sorted) {
    const bucket = String(count);
    histogram[bucket] = (histogram[bucket] ?? 0) + 1;
  }
  return {
    months: sorted.length,
    transactions: TRANSACTION_COUNT,
    queries: distribution.queries,
    handshakes: distribution.handshakes,
    refusals: distribution.refusals,
    batchAttempts: distribution.batchAttempts,
    min: sorted[0] ?? 0,
    p05: percentile(sorted, 0.05),
    p25: percentile(sorted, 0.25),
    median: percentile(sorted, 0.5),
    p75: percentile(sorted, 0.75),
    p95: percentile(sorted, 0.95),
    max: sorted.at(-1) ?? 0,
    mean,
    standardDeviation: Math.sqrt(variance),
    histogram,
  };
}

describe("MODELLED session cadence over 20,000 transactions", () => {
  it("matches the fixed-TTL oracle through the SDK handshake and replacement path", async () => {
    const timestamps = transactionTrace();
    const expected = oracleCadence(timestamps);

    const actual = await replayActualSdk(timestamps);

    expect(timestamps).toHaveLength(TRANSACTION_COUNT);
    expect(actual).toEqual(expected);
    expect(actual.handshakes).toBeGreaterThan(1);
    expect(actual.handshakes).toBeLessThan(TRANSACTION_COUNT);
    expect(actual.refusals).toBe(actual.handshakes - 1);
    console.info(`W5-04_MODELLED ${JSON.stringify(summarize(actual))}`);
  }, 120_000);
});
