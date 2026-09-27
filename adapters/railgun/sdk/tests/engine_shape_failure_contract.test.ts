// The engine runs receive-refresh, legacy submission, spent-refresh and spend-POI generation in
// one chain, and a rejection anywhere skips the rest and leaves the post-scan completion event
// unfired. The stock wallet interface therefore swallows each failed batch and answers only what
// it established. Engine also replaces a commitment's whole stored verdict map with the one it is
// handed, so an SDK-local verdict such as `Unreachable` would overwrite a stored `ProofSubmitted`.
// These pin the engine-shaped overloads to that contract; the two-argument overloads keep their
// typed errors.

import { POI, POIListType, type POIsPerList } from "@railgun-community/engine";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenError, RavenPOINodeInterface, type BlindedCommitmentData } from "../src/index";
import { encodeBatchResponseNodes } from "./helpers/auth_path_stub";
import {
  readJsonRpcRequest,
  startMockServer,
  writeJson,
  writeJsonRpcResult,
  type MockServer,
} from "./helpers/mock_server";
import { batchTargets, commitmentAt, statusRow, targetNamingCtx } from "./helpers/prefix_channel";

const TOKEN = "test-token-padded-long-enough-1234";
const TXID = "V2_PoseidonMerkle";
const CHAIN = { type: 0, id: 1 };
const LIST_A = "ab".repeat(32);
const LIST_B = "cd".repeat(32);
const ROWS = 70;
const COMMITMENTS = Array.from({ length: ROWS }, (_unused, row) => commitmentAt(row));
const PROOF_SUBMITTED = 2;
const FRESH = "lag_blocks=0 applied_height=0 epoch=1 confidence=1";
const STALE = "lag_blocks=900 applied_height=0 epoch=1 confidence=0.01";

type Reply = "ok" | "503" | "stale" | "drop";

function datas(commitments: readonly string[]): BlindedCommitmentData[] {
  return commitments.map((blindedCommitment) => ({ blindedCommitment, type: "Shield" }));
}

/** Answers the status batches in arrival order with `plan`, then "ok". */
function mountStatusPlan(server: MockServer, plan: Reply[]): void {
  let request = 0;
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, body, res) => {
      const reply = plan[request] ?? "ok";
      request += 1;
      if (reply === "503") {
        res.writeHead(503);
        res.end("overloaded");
        return true;
      }
      if (reply === "drop") {
        res.socket?.destroy();
        return true;
      }
      const rows = batchTargets(body).map((row) =>
        row < ROWS ? statusRow(PROOF_SUBMITTED, COMMITMENTS[row]) : new Uint8Array(32),
      );
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "x-raven-freshness": reply === "stale" ? STALE : FRESH,
      });
      res.end(Buffer.from(encodeBatchResponseNodes(rows)));
      return true;
    },
  );
}

function clientPirSdk(
  server: MockServer,
  lists: readonly string[] = [LIST_A],
  map: Map<string, number> = new Map(COMMITMENTS.map((bc, row) => [bc, row])),
): RavenPOINodeInterface {
  return new RavenPOINodeInterface({
    endpoint: server.url,
    bearerToken: TOKEN,
    useClientPir: true,
    clientPirContexts: new Map(lists.map((lk) => [`t1Status:${lk}`, targetNamingCtx()])),
    bcToIdxMaps: new Map(lists.map((lk) => [lk, map])),
  });
}

function everyStatus(got: Record<string, Record<string, string>>): string[] {
  return Object.values(got).flatMap((perList) => Object.values(perList));
}

describe("engine-shaped getPOIsPerList over client-PIR", () => {
  let server: MockServer;
  beforeAll(async () => {
    server = await startMockServer();
  });
  afterAll(async () => {
    await server.close();
  });
  afterEach(() => {
    server.reset();
  });

  it("resolves past a 503 chunk and a stale chunk, omitting exactly their commitments", async () => {
    // 70 commitments go out as chunks of 32, 32 and 6, in caller order.
    mountStatusPlan(server, ["503", "stale", "ok"]);
    const got = await clientPirSdk(server).getPOIsPerList(TXID, CHAIN, [LIST_A], datas(COMMITMENTS));

    expect(Object.keys(got).sort()).toEqual(COMMITMENTS.slice(64).sort());
    for (const bc of COMMITMENTS.slice(64)) expect(got[bc]).toEqual({ [LIST_A]: "ProofSubmitted" });
    expect(everyStatus(got)).not.toContain("Unreachable");
  });

  it("omits a commitment whose query never got an answer, where two arguments say Unreachable", async () => {
    const bc = [COMMITMENTS[3]];
    mountStatusPlan(server, ["drop"]);
    const engine = await clientPirSdk(server).getPOIsPerList(TXID, CHAIN, [LIST_A], datas(bc));
    expect(engine).toEqual({});

    server.reset();
    mountStatusPlan(server, ["drop"]);
    const own = await clientPirSdk(server).getPOIsPerList([LIST_A], datas(bc));
    expect(own[bc[0]][LIST_A]).toBe("Unreachable");
  });

  it("omits every commitment when one asked list has no context, and resolves", async () => {
    mountStatusPlan(server, []);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_A}`, targetNamingCtx()]]),
      bcToIdxMaps: new Map([[LIST_A, new Map(COMMITMENTS.map((bc, row) => [bc, row]))]]),
    });
    const bcs = COMMITMENTS.slice(0, 2);

    // A verdict for list A alone would replace a stored {A, B} map and drop B's verdict.
    await expect(sdk.getPOIsPerList(TXID, CHAIN, [LIST_A, LIST_B], datas(bcs))).resolves.toEqual({});
    await expect(sdk.getPOIsPerList([LIST_A, LIST_B], datas(bcs))).rejects.toSatisfy((e) =>
      RavenError.is(e, "InvalidQuery"),
    );
  });

  it("omits an absence it cannot show current instead of refusing the call", async () => {
    mountStatusPlan(server, []);
    const stranger = "77".repeat(32);
    const asked = datas([COMMITMENTS[1], stranger]);

    const got = await clientPirSdk(server).getPOIsPerList(TXID, CHAIN, [LIST_A], asked);
    expect(got).toEqual({ [COMMITMENTS[1]]: { [LIST_A]: "ProofSubmitted" } });
    await expect(clientPirSdk(server).getPOIsPerList([LIST_A], asked)).rejects.toThrow(
      /cannot be shown current/,
    );
  });

  it("omits a commitment the engine handed malformed rather than rejecting the refresh", async () => {
    mountStatusPlan(server, []);
    const got = await clientPirSdk(server).getPOIsPerList(
      TXID,
      CHAIN,
      [LIST_A],
      datas([COMMITMENTS[4], "not-hex"]),
    );
    expect(got).toEqual({ [COMMITMENTS[4]]: { [LIST_A]: "ProofSubmitted" } });
  });
});

describe("engine-shaped getPOIsPerList over plaintext", () => {
  let server: MockServer;
  beforeAll(async () => {
    server = await startMockServer();
  });
  afterAll(async () => {
    await server.close();
  });
  afterEach(() => {
    server.reset();
  });

  it("batches by twenty and contains a failed batch to its own commitments", async () => {
    let request = 0;
    server.route(
      (req) => req.url === "/v1/poi/pois-per-list",
      (_req, body, res) => {
        request += 1;
        if (request === 2) {
          res.writeHead(503);
          res.end();
          return true;
        }
        const asked = JSON.parse(new TextDecoder().decode(body)) as {
          blindedCommitmentDatas: BlindedCommitmentData[];
        };
        writeJson(
          res,
          Object.fromEntries(
            asked.blindedCommitmentDatas.map(({ blindedCommitment }, position) => [
              blindedCommitment,
              // A node's own SDK-local verdict must not reach the engine either.
              { [LIST_A]: position === 0 ? "Unreachable" : "Valid" },
            ]),
          ),
          { "x-raven-freshness": FRESH },
        );
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: false,
    });
    const bcs = COMMITMENTS.slice(0, 45);

    const got = await sdk.getPOIsPerList(TXID, CHAIN, [LIST_A], datas(bcs));

    expect(request).toBe(3);
    const expected = [...bcs.slice(1, 20), ...bcs.slice(41, 45)];
    expect(Object.keys(got).sort()).toEqual(expected.sort());
    expect(everyStatus(got)).toEqual(expected.map(() => "Valid"));
  });
});

describe("engine-shaped submitLegacyTransactProofs", () => {
  let server: MockServer;
  beforeAll(async () => {
    server = await startMockServer();
  });
  afterAll(async () => {
    await server.close();
  });
  afterEach(() => {
    server.reset();
  });

  const proofs = Array.from({ length: 45 }, (_unused, i) => ({
    txidIndex: String(i),
    npk: "00".repeat(32),
    value: "1",
    tokenHash: "11".repeat(32),
    blindedCommitment: COMMITMENTS[i],
  }));

  it("submits in batches of twenty and resolves past a failed batch", async () => {
    const sizes: number[] = [];
    server.route(
      (req) => req.url === "/",
      (_req, body, res) => {
        const params = readJsonRpcRequest(body).params as { legacyTransactProofDatas: unknown[] };
        sizes.push(params.legacyTransactProofDatas.length);
        // The second engine batch fails, and so does the two-argument call's single request.
        if (sizes.length === 2 || sizes.length === 4) {
          res.writeHead(500);
          res.end();
          return true;
        }
        writeJsonRpcResult(body, res, null);
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: server.url,
    });

    await expect(
      sdk.submitLegacyTransactProofs(TXID, CHAIN, [LIST_A], proofs),
    ).resolves.toBeUndefined();
    expect(sizes).toEqual([20, 20, 5]);
    await expect(sdk.submitLegacyTransactProofs([LIST_A], proofs)).rejects.toThrow();
  });

  it("resolves without a request when no upstream is configured", async () => {
    const sdk = new RavenPOINodeInterface({ endpoint: server.url, bearerToken: TOKEN });
    await expect(
      sdk.submitLegacyTransactProofs(TXID, CHAIN, [LIST_A], proofs),
    ).resolves.toBeUndefined();
    expect(server.requests).toHaveLength(0);
    await expect(sdk.submitLegacyTransactProofs([LIST_A], proofs)).rejects.toThrow(
      /upstreamFallbackEndpoint/,
    );
  });
});

describe("through engine's own POI seam", () => {
  let server: MockServer;
  beforeAll(async () => {
    server = await startMockServer();
  });
  afterAll(async () => {
    await server.close();
  });

  it("a refresh keeps every verdict it could not re-establish", async () => {
    // Chunk one fails, chunk two answers; engine then writes back only what it was handed.
    mountStatusPlan(server, ["503"]);
    const raven = clientPirSdk(server);
    POI.init(
      [{ key: LIST_A, type: POIListType.Active, name: "list", description: "list" }],
      raven,
    );
    const stored = new Map<string, POIsPerList>(
      COMMITMENTS.slice(0, 40).map((bc) => [bc, { [LIST_A]: "Valid" } as POIsPerList]),
    );

    const fetched = await POI.retrievePOIsForBlindedCommitments(
      TXID as Parameters<typeof POI.retrievePOIsForBlindedCommitments>[0],
      CHAIN,
      datas(COMMITMENTS.slice(0, 40)) as Parameters<typeof POI.retrievePOIsForBlindedCommitments>[2],
    );
    for (const [bc, prior] of stored) {
      const next = fetched[bc];
      if (next !== undefined) stored.set(bc, next);
      else expect(stored.get(bc)).toBe(prior);
    }

    for (const bc of COMMITMENTS.slice(0, 32)) expect(stored.get(bc)).toEqual({ [LIST_A]: "Valid" });
    for (const bc of COMMITMENTS.slice(32, 40)) {
      expect(stored.get(bc)).toEqual({ [LIST_A]: "ProofSubmitted" });
    }
    await expect(
      POI.submitLegacyTransactProofs(
        TXID as Parameters<typeof POI.submitLegacyTransactProofs>[0],
        CHAIN,
        [LIST_A],
        [],
      ),
    ).resolves.toBeUndefined();
  });
});
