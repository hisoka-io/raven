// A node that has not bootstrapped a list has no rows to show, and the shim answers its index
// channel 503. "Missing" is a verdict a wallet acts on, and it may only come from an index brought
// up to the rows the node serves in the same call, so such a node yields no status at all.

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { RavenError, RavenPOINodeInterface } from "../src/index";
import { forestConfig } from "./helpers/forest";
import { startMockServer, type MockServer } from "./helpers/mock_server";
import { targetNamingCtx } from "./helpers/prefix_channel";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";
const BC_HEX = "0c00112233445566778899aabbccddeeff00112233445566778899aabbccdd01";
const ASKED = [{ blindedCommitment: BC_HEX, type: "Shield" as const }];

describe("an unbootstrapped node is not a list state", () => {
  let server: MockServer;
  beforeAll(async () => {
    server = await startMockServer();
    // What the shim answers for a list it holds no rows of.
    server.route(
      (req) => (req.url ?? "").startsWith(`/v1/poi/${LIST_KEY_HEX}/bc-prefixes`),
      (_req, _body, res) => {
        res.writeHead(503, { "content-type": "text/plain" });
        res.end("no wired store covers the list");
        return true;
      },
    );
  });
  afterAll(async () => {
    await server.close();
  });

  function sdk(preloadEmpty: boolean): RavenPOINodeInterface {
    const config = forestConfig({ endpoint: server.url, listKeyHex: LIST_KEY_HEX, ctx: targetNamingCtx() });
    return new RavenPOINodeInterface({
      ...config,
      bearerToken: TOKEN,
      ...(preloadEmpty
        ? {
            poiListIndexes: new Map([
              [`1:${LIST_KEY_HEX}`, { epoch: 0, total: 0, prefixes: new Uint8Array(0) }],
            ]),
          }
        : {}),
    });
  }

  for (const preloadEmpty of [false, true]) {
    const held = preloadEmpty ? "an empty preloaded index" : "no index";
    it(`refuses on the two-argument call with ${held}, answering no Missing`, async () => {
      const client = sdk(preloadEmpty);
      await expect(client.getPOIsPerList([LIST_KEY_HEX], ASKED)).rejects.toSatisfy(
        (e: unknown) => RavenError.is(e, "ServerError"),
      );
      expect(client.indexCounters().absent).toBe(0);
    });

    it(`leaves the commitment out of the engine-shaped call with ${held}`, async () => {
      const client = sdk(preloadEmpty);
      await expect(
        client.getPOIsPerList("V2_PoseidonMerkle", { type: 0, id: 1 }, [LIST_KEY_HEX], ASKED),
      ).resolves.toEqual({});
      expect(client.indexCounters().absent).toBe(0);
    });
  }
});
