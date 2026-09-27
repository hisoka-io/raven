/** Routing and pre-flight tests against a stub WASM (no real PIR). */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenError, RavenPOINodeInterface } from "../src/index";
import { forestConfig } from "./helpers/forest";
import { startMockServer, type MockServer } from "./helpers/mock_server";
import { PATH10_ROW_BYTES } from "./helpers/path10_row";
import { commitmentAt, mountPrefixChannel, targetNamingCtx } from "./helpers/prefix_channel";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";
const BC_HEX = commitmentAt(1);
const SHIELD = [{ blindedCommitment: BC_HEX, type: "Shield" as const }];

describe("client-PIR routing + pre-flight", () => {
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

  function servedSdk(endpoint = server.url, placed: [string, number][] = []): RavenPOINodeInterface {
    return new RavenPOINodeInterface({
      ...forestConfig({
        endpoint,
        listKeyHex: LIST_KEY_HEX,
        ctx: { ...targetNamingCtx(), entrySize: PATH10_ROW_BYTES },
        placed,
      }),
      bearerToken: TOKEN,
    });
  }

  it("getPOIsPerList refuses a list with no context before any request", async () => {
    const sdk = new RavenPOINodeInterface({ endpoint: server.url, bearerToken: TOKEN });
    await expect(sdk.getPOIsPerList([LIST_KEY_HEX], SHIELD)).rejects.toThrow(/does not serve it/);
    expect(sdk.lastWireRequests().length).toBe(0);
  });

  it("getPOIMerkleProofs refuses a list with no context before any request", async () => {
    const sdk = new RavenPOINodeInterface({ endpoint: server.url, bearerToken: TOKEN });
    await expect(sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX])).rejects.toThrow(
      /no t2Path context/,
    );
    expect(sdk.lastWireRequests().length).toBe(0);
  });

  it("getPOIMerkleProofs refuses a commitment the synced index lacks before any query", async () => {
    mountPrefixChannel(server, LIST_KEY_HEX, { commitments: [commitmentAt(0)] });
    const sdk = servedSdk();
    await expect(sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX])).rejects.toThrow(/idx unknown/);
    // A query for a BC the client cannot place in the list would publish the lookup to the
    // server the PIR path exists to blind; only the index sync went out.
    expect(sdk.lastWireRequests().map((request) => request.method)).toEqual(["GET"]);
    expect(server.requests.some((request) => request.method === "POST")).toBe(false);
  });

  it("getPOIsPerList surfaces every (BC, listKey) cell across multiple lists", async () => {
    // outer key BC, inner list-key: upstream POIsPerListMap shape (shared-models proof-of-innocence.ts)
    const lkA = "11".repeat(32);
    const lkB = "22".repeat(32);
    mountPrefixChannel(server, lkA, { commitments: [BC_HEX] });
    mountPrefixChannel(server, lkB, { commitments: [commitmentAt(0)] });
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      clientPirContexts: new Map([
        [`t2Path:1:${lkA}`, targetNamingCtx()],
        [`t2Path:1:${lkB}`, targetNamingCtx()],
      ]),
      poiListIndexStore: false,
    });
    const got = await sdk.getPOIsPerList([lkA, lkB], SHIELD);
    expect(got).toStrictEqual({ [BC_HEX]: { [lkA]: "Valid", [lkB]: "Missing" } });
  });

  it("getPOIsPerList propagates a 5xx index sync as ServerError, never a silent Missing", async () => {
    server.route(
      (req) => (req.url ?? "").includes("/bc-prefixes"),
      (_req, _body, res) => {
        res.writeHead(500, { "content-type": "text/plain" });
        res.end("server error");
        return true;
      },
    );
    await expect(servedSdk().getPOIsPerList([LIST_KEY_HEX], SHIELD)).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "ServerError"),
    );
  });

  it("getPOIsPerList raises Network when the node cannot be reached", async () => {
    await expect(
      servedSdk("http://127.0.0.1:1").getPOIsPerList([LIST_KEY_HEX], SHIELD),
    ).rejects.toSatisfy((e: unknown) => RavenError.is(e, "Network"));
  });

  it("a socket destroyed mid-sync raises Network", async () => {
    server.route(
      (req) => (req.url ?? "").includes("/bc-prefixes"),
      (_req, _body, res) => {
        res.socket?.destroy();
        return true;
      },
    );
    await expect(servedSdk().getPOIsPerList([LIST_KEY_HEX], SHIELD)).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "Network"),
    );
  });

  it("getPOIMerkleProofs propagates a 5xx batch as ServerError", async () => {
    server.route(
      (req) => req.url?.startsWith("/v1/instance/") ?? false,
      (_req, _body, res) => {
        res.writeHead(500, { "content-type": "text/plain" });
        res.end("server error");
        return true;
      },
    );
    await expect(
      servedSdk(server.url, [[BC_HEX, 3]]).getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]),
    ).rejects.toSatisfy((e: unknown) => RavenError.is(e, "ServerError"));
  });

  it("captured request ring is bounded at exactly the 64-entry cap", async () => {
    server.route(
      () => true,
      (_req, _body, res) => {
        res.writeHead(404);
        res.end();
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({ endpoint: server.url, bearerToken: TOKEN });
    // Mirrors the cap literal in captureRequest (src/raven-poi-node-interface.ts); the ring
    // retains a request body per slot, so its size is a security-relevant quantity.
    const WIRE_RING_CAP = 64;
    // each fetch 404s but records into the ring first; 70 > the 64 cap
    for (let i = 0; i < WIRE_RING_CAP + 6; i += 1) {
      try {
        await sdk.syncPoiListIndex(LIST_KEY_HEX);
      } catch {
      }
    }
    // toBe, not toBeLessThanOrEqual: zero satisfied the old bound, so the test stayed
    // green with capture deleted outright. Equality both catches unbounded growth AND
    // proves capture still happens.
    expect(sdk.lastWireRequests().length).toBe(WIRE_RING_CAP);
  });

  it("resetWireCapture clears the ring", async () => {
    const sdk = new RavenPOINodeInterface({ endpoint: server.url, bearerToken: TOKEN });
    await sdk.syncPoiListIndex(LIST_KEY_HEX).catch(() => undefined);
    expect(sdk.lastWireRequests().length).toBe(1);
    sdk.resetWireCapture();
    expect(sdk.lastWireRequests().length).toBe(0);
  });

  it("lastWireRequests returns a fresh array (pushes cannot grow the ring)", async () => {
    const sdk = new RavenPOINodeInterface({ endpoint: server.url, bearerToken: TOKEN });
    await sdk.syncPoiListIndex(LIST_KEY_HEX).catch(() => undefined);
    const ring1 = sdk.lastWireRequests();
    const len1 = ring1.length;
    expect(len1).toBeGreaterThan(0);
    ring1.push({ url: "evil", method: "POST", body: new Uint8Array(0) });
    expect(sdk.lastWireRequests().length).toBe(len1);
  });

  it("lastWireRequests deep-clones retained request bodies", async () => {
    // The held index lets the proof reach the batch POST, whose body is not empty.
    const sdk = servedSdk(server.url, [[BC_HEX, 3]]);
    await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]).catch(() => undefined);
    const posted = sdk.lastWireRequests().findIndex((request) => request.method === "POST");
    expect(posted).toBeGreaterThanOrEqual(0);
    const ring1 = sdk.lastWireRequests();
    expect(ring1[posted].body.length).toBeGreaterThan(0);
    const before = sdk.lastWireRequests()[posted].body[0];
    ring1[posted].body[0] = before ^ 0xff;
    expect(sdk.lastWireRequests()[posted].body[0]).toBe(before);
  });
});
