// Locks the auth-path freshness contract: every path is revalidated against the epoch its
// batch reply reports, and siblings drawn from two epochs are never folded into one proof.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { ImtCache, RavenError, RavenPOINodeInterface } from "../src/index";

import { startMockServer, writeJson, type MockServer } from "./helpers/mock_server";
import {
  authPathOf,
  encodeBatchResponse,
  encodedBatchCount,
  epochMarkers,
  stubCtx,
} from "./helpers/auth_path_stub";

const TOKEN = "test-token-padded-long-enough-1234";
const TREE_NUMBER = 0;
const INSTANCE_ID = `commit-tree-${TREE_NUMBER}`;
const SCHEMA_VERSION = 7;


interface AdapterState {
  epoch: number;
  batchHits: number;
  batchStatus: number;
  statusHits: number;
}


function mountAdapter(server: MockServer, state: AdapterState): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, body, res) => {
      state.batchHits += 1;
      if (state.batchStatus !== 200) {
        res.writeHead(state.batchStatus);
        res.end();
        return true;
      }
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "x-raven-epoch": String(state.epoch),
        "x-raven-schema-version": String(SCHEMA_VERSION),
      });
      res.end(Buffer.from(encodeBatchResponse(state.epoch, encodedBatchCount(body))));
      return true;
    },
  );
  server.route(
    (req) => req.url === "/v1/status",
    (_req, _body, res) => {
      state.statusHits += 1;
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
    state = { epoch: 7, batchHits: 0, batchStatus: 200, statusHits: 0 };
    mountAdapter(server, state);
    return state;
  }

  it("serves only the current snapshot's nodes once the server epoch advances", async () => {
    freshAdapter();
    const sdk = newSdk(server);

    const cold = await sdk.getMerkleProof(TREE_NUMBER, 1234);
    expect(state.batchHits).toBe(1);
    expect(epochMarkers(authPathOf(cold).elements)).toEqual(["07"]);

    const warm = await sdk.getMerkleProof(TREE_NUMBER, 1234);
    expect(state.batchHits).toBe(2);
    expect(epochMarkers(authPathOf(warm).elements)).toEqual(["07"]);

    state.epoch = 8;
    const afterAdvance = await sdk.getMerkleProof(TREE_NUMBER, 1234);
    expect(state.batchHits).toBe(3);
    expect(epochMarkers(authPathOf(afterAdvance).elements)).toEqual(["08"]);
    expect(state.statusHits).toBe(0);
  });

  it("never folds siblings from two epochs into one proof on a partial cache hit", async () => {
    freshAdapter();
    const sdk = newSdk(server);

    await sdk.getMerkleProof(TREE_NUMBER, 1234);
    state.epoch = 8;

    // 1234 ^ 0b111 shares every sibling above level 2, so 13 levels come from the epoch-7 cache.
    const mixed = await sdk.getMerkleProof(TREE_NUMBER, 1234 ^ 0b111);
    expect(epochMarkers(authPathOf(mixed).elements)).toEqual(["08"]);
  });

  it("fails closed when the revalidating batch is unreachable instead of serving the cached path", async () => {
    freshAdapter();
    const sdk = newSdk(server);

    await sdk.getMerkleProof(TREE_NUMBER, 1234);
    state.batchStatus = 503;

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
