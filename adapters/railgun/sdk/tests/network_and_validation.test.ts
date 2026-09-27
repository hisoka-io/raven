// Locks the SDK as chain-agnostic: chain ids are not baked in, the wallet wires `endpoint` and
// its context keys per chain. Chain list per shared-models/src/models/network-config.ts.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenPOINodeInterface } from "../src/index";
import { forestConfig } from "./helpers/forest";
import {
  readJsonRpcRequest,
  startMockServer,
  writeJsonRpcResult,
  type MockServer,
} from "./helpers/mock_server";
import { commitmentAt, mountPrefixChannel, targetNamingCtx } from "./helpers/prefix_channel";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";
const BC_HEX = commitmentAt(1);
const SHIELD = [{ blindedCommitment: BC_HEX, type: "Shield" as const }];

const NETWORKS = [
  { name: "Ethereum mainnet", chainId: 1 },
  { name: "Sepolia", chainId: 11155111 },
  { name: "BSC", chainId: 56 },
  { name: "Polygon", chainId: 137 },
  { name: "Arbitrum", chainId: 42161 },
];

describe("per-network deployments + validation", () => {
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

  for (const net of NETWORKS) {
    it(`SDK works against a ${net.name} (chain ${net.chainId}) operator`, async () => {
      mountPrefixChannel(server, LIST_KEY_HEX, { commitments: [BC_HEX] });
      const sdk = new RavenPOINodeInterface({
        ...forestConfig({
          endpoint: server.url,
          listKeyHex: LIST_KEY_HEX,
          ctx: targetNamingCtx(),
          chainId: net.chainId,
        }),
        bearerToken: TOKEN,
      });
      const got = await sdk.getPOIsPerList(
        "V2_PoseidonMerkle",
        { type: 0, id: net.chainId },
        [LIST_KEY_HEX],
        SHIELD,
      );
      expect(got[BC_HEX][LIST_KEY_HEX]).toBe("Valid");
    });
  }

  it("does not serve a list whose context is keyed for another chain", async () => {
    mountPrefixChannel(server, LIST_KEY_HEX, { commitments: [BC_HEX] });
    const sdk = new RavenPOINodeInterface({
      ...forestConfig({ endpoint: server.url, listKeyHex: LIST_KEY_HEX, ctx: targetNamingCtx() }),
      chainId: 137,
      bearerToken: TOKEN,
    });
    await expect(sdk.getPOIsPerList([LIST_KEY_HEX], SHIELD)).rejects.toThrow(/does not serve it/);
    expect(server.requests).toHaveLength(0);
  });

  it("constructor strips a trailing slash before the endpoint reaches a URL", async () => {
    // `expect(() => sdk).not.toThrow()` used to stand here and could not fail: the strip was
    // removable with the whole suite green. Assert the observable consequence instead.
    mountPrefixChannel(server, LIST_KEY_HEX, { commitments: [] });
    const sdk = new RavenPOINodeInterface({
      endpoint: `${server.url}/`,
      bearerToken: TOKEN,
      poiListIndexStore: false,
    });
    await sdk.syncPoiListIndex(LIST_KEY_HEX);
    const wires = sdk.lastWireRequests();
    expect(wires.length).toBe(1);
    expect(wires[0].url).toBe(`${server.url}/v1/poi/${LIST_KEY_HEX}/bc-prefixes?since=0`);
    expect(wires[0].url).not.toContain("//v1/");
  });

  it("answers an empty map per commitment for empty list keys, and nothing to the engine", async () => {
    const sdk = new RavenPOINodeInterface({ endpoint: server.url, bearerToken: TOKEN });
    await expect(sdk.getPOIsPerList([], SHIELD)).resolves.toEqual({ [BC_HEX]: {} });
    await expect(
      sdk.getPOIsPerList("V2_PoseidonMerkle", { type: 0, id: 1 }, [], SHIELD),
    ).resolves.toEqual({});
    expect(server.requests).toHaveLength(0);
  });

  it("accepts empty blinded commitments", async () => {
    mountPrefixChannel(server, LIST_KEY_HEX, { commitments: [BC_HEX] });
    const sdk = new RavenPOINodeInterface({
      ...forestConfig({ endpoint: server.url, listKeyHex: LIST_KEY_HEX, ctx: targetNamingCtx() }),
      bearerToken: TOKEN,
    });
    await expect(sdk.getPOIsPerList([LIST_KEY_HEX], [])).resolves.toEqual({});
  });

  for (const [label, txidVersion, expected] of [
    ["passes the configured txid version upstream", "V3_PoseidonMerkle", "V3_PoseidonMerkle"],
    ["defaults the txid version to V2_PoseidonMerkle", undefined, "V2_PoseidonMerkle"],
  ] as const) {
    it(label, async () => {
      let sent: unknown;
      server.route(
        (req) => req.url === "/",
        (_req, body, res) => {
          sent = readJsonRpcRequest(body).params.txidVersion;
          writeJsonRpcResult(body, res, true);
          return true;
        },
      );
      const sdk = new RavenPOINodeInterface({
        endpoint: server.url,
        bearerToken: TOKEN,
        upstreamFallbackEndpoint: `${server.url}/`,
        ...(txidVersion === undefined ? {} : { txidVersion }),
      });
      await sdk.validatePOIMerkleroots(LIST_KEY_HEX, ["00".repeat(32)]);
      expect(sent).toBe(expected);
    });
  }

  it("custom fetchImpl is used when supplied", async () => {
    let callCount = 0;
    const customFetch: typeof fetch = async (url, init) => {
      callCount += 1;
      return fetch(url, init);
    };
    mountPrefixChannel(server, LIST_KEY_HEX, { commitments: [] });
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      fetchImpl: customFetch,
      poiListIndexStore: false,
    });
    await sdk.syncPoiListIndex(LIST_KEY_HEX);
    expect(callCount).toBe(1);
  });

  it("the index channel carries the bearer token", async () => {
    mountPrefixChannel(server, LIST_KEY_HEX, { commitments: [] });
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      poiListIndexStore: false,
    });
    await sdk.syncPoiListIndex(LIST_KEY_HEX);
    const prefixReads = server.requests.filter((r) => r.url.includes("/bc-prefixes"));
    expect(prefixReads.map((r) => r.headers.authorization)).toStrictEqual([`Bearer ${TOKEN}`]);
  });
});
