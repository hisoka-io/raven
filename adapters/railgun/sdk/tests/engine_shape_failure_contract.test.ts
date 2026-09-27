// The engine runs receive-refresh, legacy submission, spent-refresh and spend-POI generation in
// one chain, and a rejection anywhere skips the rest and leaves the post-scan completion event
// unfired. The stock wallet interface therefore swallows each failed batch and answers only what
// it established. Engine also replaces a commitment's whole stored verdict map with the one it is
// handed, so a guessed verdict would overwrite a stored one. These pin the engine-shaped overloads
// to that contract; the two-argument overloads keep their typed errors.

import { POI, POIListType, type POIsPerList } from "@railgun-community/engine";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenError, RavenPOINodeInterface, type BlindedCommitmentData } from "../src/index";
import { forestConfig } from "./helpers/forest";
import {
  readJsonRpcRequest,
  startMockServer,
  writeJsonRpcResult,
  type MockServer,
} from "./helpers/mock_server";
import {
  commitmentAt,
  mountPrefixChannel,
  targetNamingCtx,
  type MockList,
} from "./helpers/prefix_channel";

const TOKEN = "test-token-padded-long-enough-1234";
const TXID = "V2_PoseidonMerkle";
const CHAIN = { type: 0, id: 1 };
const LIST_A = "ab".repeat(32);
const ROWS = 70;
const COMMITMENTS = Array.from({ length: ROWS }, (_unused, row) => commitmentAt(row));

function datas(commitments: readonly string[]): BlindedCommitmentData[] {
  return commitments.map((blindedCommitment) => ({ blindedCommitment, type: "Shield" }));
}

/** A node serving `rows` of the list on the prefix channel, whose failures a test switches on. */
function serveList(server: MockServer, rows = ROWS): MockList {
  const list: MockList = { commitments: COMMITMENTS.slice(0, rows) };
  mountPrefixChannel(server, LIST_A, list);
  return list;
}

function deviceSdk(server: MockServer): RavenPOINodeInterface {
  return new RavenPOINodeInterface({
    ...forestConfig({ endpoint: server.url, listKeyHex: LIST_A, ctx: targetNamingCtx() }),
    bearerToken: TOKEN,
  });
}

describe("engine-shaped getPOIsPerList on the device", () => {
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

  it("resolves past a refused, rolled-back or dropped sync, leaving every commitment out", async () => {
    const list = serveList(server);
    const sdk = deviceSdk(server);
    await sdk.syncPoiListIndex(LIST_A);

    list.failStatus = 503;
    await expect(sdk.getPOIsPerList(TXID, CHAIN, [LIST_A], datas(COMMITMENTS))).resolves.toEqual({});

    // A node now serving fewer rows than the device holds.
    list.failStatus = undefined;
    list.commitments.length = 10;
    await expect(sdk.getPOIsPerList(TXID, CHAIN, [LIST_A], datas(COMMITMENTS))).resolves.toEqual({});

    server.reset();
    server.route(
      (req) => (req.url ?? "").includes("/bc-prefixes"),
      (_req, _body, res) => {
        res.socket?.destroy();
        return true;
      },
    );
    await expect(sdk.getPOIsPerList(TXID, CHAIN, [LIST_A], datas(COMMITMENTS))).resolves.toEqual({});
  });

  it("raises the failure's own kind on the two-argument call instead", async () => {
    const list = serveList(server);
    list.failStatus = 503;
    await expect(deviceSdk(server).getPOIsPerList([LIST_A], datas(COMMITMENTS))).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "ServerError"),
    );

    server.reset();
    server.route(
      (req) => (req.url ?? "").includes("/bc-prefixes"),
      (_req, _body, res) => {
        res.socket?.destroy();
        return true;
      },
    );
    await expect(deviceSdk(server).getPOIsPerList([LIST_A], datas(COMMITMENTS))).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "Network"),
    );
  });

  it("omits a commitment the engine handed malformed rather than rejecting the refresh", async () => {
    serveList(server);
    const got = await deviceSdk(server).getPOIsPerList(
      TXID,
      CHAIN,
      [LIST_A],
      datas([COMMITMENTS[4], "not-hex"]),
    );
    expect(got).toEqual({ [COMMITMENTS[4]]: { [LIST_A]: "Valid" } });
  });

  it("answers nothing for a list key the engine handed malformed", async () => {
    serveList(server);
    await expect(
      deviceSdk(server).getPOIsPerList(TXID, CHAIN, [LIST_A, "zz"], datas([COMMITMENTS[4]])),
    ).resolves.toEqual({});
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

  it("a refresh keeps every verdict it could not re-establish, then replaces them", async () => {
    const list = serveList(server, 32);
    const raven = deviceSdk(server);
    POI.init(
      [{ key: LIST_A, type: POIListType.Active, name: "list", description: "list" }],
      raven,
    );
    const stored = new Map<string, POIsPerList>(
      COMMITMENTS.slice(0, 40).map((bc) => [bc, { [LIST_A]: "ProofSubmitted" } as POIsPerList]),
    );
    const refresh = async (): Promise<void> => {
      const fetched = await POI.retrievePOIsForBlindedCommitments(
        TXID as Parameters<typeof POI.retrievePOIsForBlindedCommitments>[0],
        CHAIN,
        datas(COMMITMENTS.slice(0, 40)) as Parameters<
          typeof POI.retrievePOIsForBlindedCommitments
        >[2],
      );
      // What engine does with the reply: an omitted commitment keeps its stored map.
      for (const bc of stored.keys()) {
        const next = fetched[bc];
        if (next !== undefined) stored.set(bc, next);
      }
    };

    list.failStatus = 503;
    await refresh();
    for (const verdict of stored.values()) expect(verdict).toEqual({ [LIST_A]: "ProofSubmitted" });

    list.failStatus = undefined;
    await refresh();
    for (const bc of COMMITMENTS.slice(0, 32)) expect(stored.get(bc)).toEqual({ [LIST_A]: "Valid" });
    for (const bc of COMMITMENTS.slice(32, 40)) {
      expect(stored.get(bc)).toEqual({ [LIST_A]: "Missing" });
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
