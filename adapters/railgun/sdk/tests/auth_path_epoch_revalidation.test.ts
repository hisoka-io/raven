// Locks the auth-path freshness contract: a fully-cached path is revalidated against the
// server's snapshot epoch, and siblings drawn from two epochs are never folded into one proof.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  ImtCache,
  RavenError,
  RavenPOINodeInterface,
  TREE_DEPTH,
  type ClientPirContext,
  type RavenInspireWasm,
} from "../src/index";

import { startMockServer, writeJson, type MockServer } from "./helpers/mock_server";

const TOKEN = "test-token-padded-long-enough-1234";
const TREE_NUMBER = 0;
const INSTANCE_ID = `commit-tree-${TREE_NUMBER}`;
const SCHEMA_VERSION = 1;
const NODE_BYTES = 32;

function stubWasm(): RavenInspireWasm {
  function flatIndex(level: number, idxAtLevel: number): number {
    const total = 1 << (TREE_DEPTH + 1);
    return total - (1 << (TREE_DEPTH + 1 - level)) + idxAtLevel;
  }
  function siblingPath(leafIdx: number): Uint32Array {
    const out = new Uint32Array(TREE_DEPTH);
    let walk = leafIdx;
    for (let i = 0; i < TREE_DEPTH; i += 1) {
      out[i] = flatIndex(i, walk ^ 1);
      walk = walk >>> 1;
    }
    return out;
  }
  return {
    build_client_session: () => ({ free: () => undefined }),
    build_seeded_query: () => new Uint8Array(16),
    extract_response: (_session, _crs, _state, response, _entry) => new Uint8Array(response),
    build_instance_params_blob: () => new Uint8Array(0),
    register_client_session: () => {},
    path_indices_for_leaf: (_tree: number, leafIdx: number): Uint32Array => siblingPath(leafIdx),
    path_indices_for_per_list_leaf: (_listKey: Uint8Array, idx: number): Uint32Array =>
      siblingPath(idx),
  };
}

function stubCtx(): ClientPirContext {
  return {
    wasm: stubWasm(),
    session: { free: () => undefined },
    crsBincode: new Uint8Array(0),
    shardConfigBincode: new Uint8Array(0),
    entrySize: NODE_BYTES,
  };
}

interface AdapterState {
  epoch: number;
  batchHits: number;
  statusHits: number;
  statusStatus: number;
}

// Every node byte 0 carries the serving epoch, so a mixed-epoch fold is visible in `elements`.
function encodeBatchResponse(epoch: number, slots: number): Uint8Array {
  const out = new Uint8Array(2 + 8 + slots * (8 + NODE_BYTES));
  out[1] = 1;
  const dv = new DataView(out.buffer);
  dv.setUint32(2, slots, true);
  let off = 10;
  for (let level = 0; level < slots; level += 1) {
    dv.setUint32(off, NODE_BYTES, true);
    off += 8;
    out[off] = epoch;
    out[off + NODE_BYTES - 1] = level;
    off += NODE_BYTES;
  }
  return out;
}

function requestedSlots(body: Uint8Array): number {
  const dv = new DataView(body.buffer, body.byteOffset, body.byteLength);
  return dv.getUint32(2, true);
}

function mountAdapter(server: MockServer, state: AdapterState): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, body, res) => {
      state.batchHits += 1;
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "x-raven-epoch": String(state.epoch),
        "x-raven-schema-version": String(SCHEMA_VERSION),
      });
      res.end(Buffer.from(encodeBatchResponse(state.epoch, requestedSlots(body))));
      return true;
    },
  );
  server.route(
    (req) => req.url === "/v1/status",
    (_req, _body, res) => {
      state.statusHits += 1;
      if (state.statusStatus !== 200) {
        res.writeHead(state.statusStatus);
        res.end();
        return true;
      }
      writeJson(res, {
        scheme: "inspire",
        instances: [
          {
            id: INSTANCE_ID,
            epoch: state.epoch,
            role: "live",
            drain_state: "active",
            in_flight: 0,
            active_k_concurrency: 4,
          },
        ],
        consumer: null,
      });
      return true;
    },
  );
}

function newSdk(server: MockServer): RavenPOINodeInterface {
  return new RavenPOINodeInterface({
    endpoint: server.url,
    bearerToken: TOKEN,
    useClientPir: true,
    clientPirContexts: new Map([[`t3CommitTree:${TREE_NUMBER}`, stubCtx()]]),
    imtCache: new ImtCache({ disableIndexedDb: true }),
  });
}

function epochMarkers(elements: string[]): string[] {
  return Array.from(new Set(elements.map((e) => e.slice(0, 2)))).sort();
}

describe("auth-path epoch revalidation", () => {
  let server: MockServer;
  let state: AdapterState;

  beforeAll(async () => {
    server = await startMockServer();
  });
  afterAll(async () => {
    await server.close();
  });
  afterEach(() => {
    server.reset();
  });

  function freshAdapter(): AdapterState {
    state = { epoch: 7, batchHits: 0, statusHits: 0, statusStatus: 200 };
    mountAdapter(server, state);
    return state;
  }

  it("refetches a fully-cached path once the server snapshot epoch advances", async () => {
    freshAdapter();
    const sdk = newSdk(server);

    const cold = await sdk.getMerkleProof(TREE_NUMBER, 1234);
    expect(state.batchHits).toBe(1);
    expect(state.statusHits).toBe(0);
    expect(epochMarkers(cold.elements)).toEqual(["07"]);

    const warm = await sdk.getMerkleProof(TREE_NUMBER, 1234);
    expect(state.batchHits).toBe(1);
    expect(epochMarkers(warm.elements)).toEqual(["07"]);

    state.epoch = 8;
    const afterAdvance = await sdk.getMerkleProof(TREE_NUMBER, 1234);
    expect(state.batchHits).toBe(2);
    expect(epochMarkers(afterAdvance.elements)).toEqual(["08"]);
  });

  it("never folds siblings from two epochs into one proof on a partial cache hit", async () => {
    freshAdapter();
    const sdk = newSdk(server);

    await sdk.getMerkleProof(TREE_NUMBER, 1234);
    state.epoch = 8;

    // 1234 ^ 0b111 shares every sibling above level 2, so 13 levels come from the epoch-7 cache.
    const mixed = await sdk.getMerkleProof(TREE_NUMBER, 1234 ^ 0b111);
    expect(epochMarkers(mixed.elements)).toEqual(["08"]);
  });

  it("fails closed when the epoch probe is unreachable instead of serving the cached path", async () => {
    freshAdapter();
    const sdk = newSdk(server);

    await sdk.getMerkleProof(TREE_NUMBER, 1234);
    state.statusStatus = 503;

    let thrown: unknown;
    let returned = false;
    try {
      await sdk.getMerkleProof(TREE_NUMBER, 1234);
      returned = true;
    } catch (e) {
      thrown = e;
    }
    expect(returned).toBe(false);
    expect(RavenError.is(thrown, "ServerError")).toBe(true);
  });
});
