// `postJson` ended at `json = (await res.json()) as T`, so every shim response crossed into a typed
// result with no check at all. `as T` is a compile-time assertion and does nothing at runtime, so a
// node serving any JSON object at all was believed.
//
// A pure SHAPE check is not sufficient here and that is the point of the outer-key rule:
// `{listKey: {bc: status}}` and `{bc: {listKey: status}}` are structurally identical — both are
// `{hex64: {hex64: POIStatus}}`. Two tests in this suite carried the inverted shape and passed for
// years against a path that returned the body uncast. Only "the outer keys are the commitments I
// asked about" separates a correct body from an inverted one.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenPOINodeInterface } from "../src/index";
import { startMockServer, type MockServer } from "./helpers/mock_server";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";
const BC_HEX = "bc00112233445566778899aabbccddeeff00112233445566778899aabbccdd01";
const OTHER_BC = "dd00112233445566778899aabbccddeeff00112233445566778899aabbccdd02";

function mountJson(server: MockServer, path: string, payload: unknown): void {
  server.route(
    (req) => req.url === path,
    (_req, _body, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(payload));
      return true;
    },
  );
}

describe("JSON from the shim is validated before it is returned as a typed result", () => {
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

  function sdk(): RavenPOINodeInterface {
    return new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: false,
    });
  }

  const askStatus = () =>
    sdk().getPOIsPerList([LIST_KEY_HEX], [{ blindedCommitment: BC_HEX, type: "Shield" }]);
  const askProofs = () => sdk().getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);

  it("refuses a pois-per-list body that is an array", async () => {
    mountJson(server, "/v1/poi/pois-per-list", [{ [BC_HEX]: { [LIST_KEY_HEX]: "Valid" } }]);
    await expect(askStatus()).rejects.toThrow(/pois-per-list/i);
  });

  it("refuses a per-BC entry that is not an object", async () => {
    mountJson(server, "/v1/poi/pois-per-list", { [BC_HEX]: "Valid" });
    await expect(askStatus()).rejects.toThrow(/pois-per-list/i);
  });

  it("refuses a status that is not a POIStatus", async () => {
    mountJson(server, "/v1/poi/pois-per-list", { [BC_HEX]: { [LIST_KEY_HEX]: "Excellent" } });
    await expect(askStatus()).rejects.toThrow(/Excellent|status/i);
  });

  // Structurally valid, semantically inverted: only the outer-key rule can reject this.
  it("refuses an inverted body whose outer keys are list keys, not commitments", async () => {
    mountJson(server, "/v1/poi/pois-per-list", { [LIST_KEY_HEX]: { [BC_HEX]: "Valid" } });
    await expect(askStatus()).rejects.toThrow(/not requested|outer key|unrequested/i);
  });

  it("refuses an outer key that was never asked about", async () => {
    mountJson(server, "/v1/poi/pois-per-list", { [OTHER_BC]: { [LIST_KEY_HEX]: "Valid" } });
    await expect(askStatus()).rejects.toThrow(/not requested|outer key|unrequested/i);
  });

  it("refuses a merkle-proofs body that is not an array", async () => {
    mountJson(server, "/v1/poi/merkle-proofs", { leaf: BC_HEX });
    await expect(askProofs()).rejects.toThrow(/merkle-proofs/i);
  });

  it("refuses a proof whose elements are not hex strings", async () => {
    mountJson(server, "/v1/poi/merkle-proofs", [
      { leaf: BC_HEX, elements: [1, 2, 3], indices: "0", root: BC_HEX },
    ]);
    await expect(askProofs()).rejects.toThrow(/elements/i);
  });

  it("refuses a proof missing a required field", async () => {
    mountJson(server, "/v1/poi/merkle-proofs", [{ leaf: BC_HEX, elements: [], indices: "0" }]);
    await expect(askProofs()).rejects.toThrow(/root|proof/i);
  });

  // The refusals must not swallow the good case.
  it("accepts a well-formed pois-per-list body unchanged", async () => {
    mountJson(server, "/v1/poi/pois-per-list", { [BC_HEX]: { [LIST_KEY_HEX]: "Valid" } });
    await expect(askStatus()).resolves.toEqual({ [BC_HEX]: { [LIST_KEY_HEX]: "Valid" } });
  });

  it("accepts a well-formed merkle-proofs body unchanged", async () => {
    const proof = { leaf: BC_HEX, elements: [LIST_KEY_HEX], indices: "0", root: BC_HEX };
    mountJson(server, "/v1/poi/merkle-proofs", [proof]);
    await expect(askProofs()).resolves.toEqual([proof]);
  });
});
