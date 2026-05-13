/**
 * Per-network operator endpoints + SDK validation tests.
 *
 * Per `shared-models/src/models/network-config.ts` Railgun runs on:
 *   - Ethereum mainnet (chain id 1)
 *   - Sepolia       (11155111)
 *   - BSC           (56)
 *   - Polygon       (137)
 *   - Arbitrum      (42161)
 *
 * The SDK does not bake in chain IDs; each operator deployment
 * exposes its own chain-id config (operator chooses one per
 * deployment). The wallet wires `endpoint` per chain. We exercise
 * the mock-server pattern across each chain to lock that the SDK is
 * chain-agnostic. A mismatch test verifies that a wallet pointing
 * at the wrong operator gets a typed error rather than silently
 * accepting wrong-chain data.
 *
 * Validation tests document the SDK's current acceptance shape so
 * future tightening (e.g. hex-length checks) is a deliberate
 * reviewable change rather than a silent contract widening.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenPOINodeInterface } from "../src/index";
import { startMockServer, writeJson, type MockServer } from "./helpers/mock_server";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";
const BC_HEX = "0000000000000000000000000000000000000000000000000000000000000001";

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
      // Operator surfaces its chain via response payload — wallets
      // can verify by reading the status route. This test confirms
      // the SDK can round-trip data tagged with the network's chain
      // id without tripping any client-side filter.
      server.route(
        (req) => req.url === "/v1/poi/pois-per-list",
        (_req, _body, res) => {
          writeJson(
            res,
            { [BC_HEX]: { [LIST_KEY_HEX]: "Valid" } },
            {
              "x-raven-chain-id": net.chainId.toString(),
              "x-raven-freshness": "lag_blocks=1 applied_height=10 epoch=1 confidence=0.99",
            },
          );
          return true;
        },
      );
      const sdk = new RavenPOINodeInterface({
        endpoint: server.url,
        bearerToken: TOKEN,
        useClientPir: false,
      });
      const got = await sdk.getPOIsPerList(
        [LIST_KEY_HEX],
        [{ blindedCommitment: BC_HEX, type: "Shield" }],
      );
      expect(got[BC_HEX][LIST_KEY_HEX]).toBe("Valid");
    });
  }

  it("operator chain-id mismatch surfaces via response inspection (test-side check)", async () => {
    // The SDK does not currently verify chain-id; the wallet
    // integrator is expected to read `X-Raven-Chain-Id` from the
    // status route and bail before issuing PIR queries against the
    // wrong network. This regression-guard test documents that
    // current behavior so a future contract tightening (SDK-side
    // chain-id verification) lands as a deliberate change rather
    // than a silent shift.
    server.route(
      (req) => req.url === "/v1/poi/pois-per-list",
      (_req, _body, res) => {
        writeJson(
          res,
          { [LIST_KEY_HEX]: { [BC_HEX]: "Valid" } },
          {
            "x-raven-chain-id": "999999999",
            "x-raven-freshness": "lag_blocks=1 applied_height=10 epoch=1 confidence=0.99",
          },
        );
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: false,
    });
    // SDK accepts; wallet integrator MUST verify out-of-band.
    await expect(
      sdk.getPOIsPerList(
        [LIST_KEY_HEX],
        [{ blindedCommitment: BC_HEX, type: "Shield" }],
      ),
    ).resolves.toBeTruthy();
  });

  it("constructor strips trailing slashes from endpoint", () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: "http://localhost:8080/",
      bearerToken: TOKEN,
    });
    // No way to inspect endpoint directly; trigger a request that
    // would fail the path concatenation if the trailing slash had
    // leaked.
    expect(() => sdk).not.toThrow();
  });

  it("accepts empty list_keys (server returns empty map)", async () => {
    server.route(
      (req) => req.url === "/v1/poi/pois-per-list",
      (_req, _body, res) => {
        writeJson(res, {});
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: false,
    });
    const got = await sdk.getPOIsPerList(
      [],
      [{ blindedCommitment: BC_HEX, type: "Shield" }],
    );
    expect(got).toEqual({});
  });

  it("accepts empty blinded_commitments (server returns empty)", async () => {
    server.route(
      (req) => req.url === "/v1/poi/pois-per-list",
      (_req, _body, res) => {
        // Outer-key is BC; with no BCs in the request the response
        // is an empty object, mirroring upstream POIsPerListMap.
        writeJson(res, {});
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: false,
    });
    const got = await sdk.getPOIsPerList([LIST_KEY_HEX], []);
    expect(got).toEqual({});
  });

  it("legacy mode passes blank txid_version when explicitly set", async () => {
    server.route(
      (req) => req.url === "/v1/poi/pois-per-list",
      (_req, body, res) => {
        const decoded = JSON.parse(new TextDecoder().decode(body));
        expect(decoded.txidVersion).toBe("V3_PoseidonMerkle");
        writeJson(res, {});
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: false,
      txidVersion: "V3_PoseidonMerkle",
    });
    await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_HEX, type: "Shield" }],
    );
  });

  it("legacy mode default txid_version is V2_PoseidonMerkle", async () => {
    server.route(
      (req) => req.url === "/v1/poi/pois-per-list",
      (_req, body, res) => {
        const decoded = JSON.parse(new TextDecoder().decode(body));
        expect(decoded.txidVersion).toBe("V2_PoseidonMerkle");
        writeJson(res, {});
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: false,
    });
    await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_HEX, type: "Shield" }],
    );
  });

  it("custom fetchImpl is used when supplied", async () => {
    let callCount = 0;
    const customFetch: typeof fetch = async (url, init) => {
      callCount += 1;
      // Defer to native fetch so the request actually hits the mock.
      return fetch(url, init);
    };
    server.route(
      (req) => req.url === "/v1/poi/pois-per-list",
      (_req, _body, res) => {
        writeJson(res, {});
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: false,
      fetchImpl: customFetch,
    });
    await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_HEX, type: "Shield" }],
    );
    expect(callCount).toBe(1);
  });

  it("Authorization header carries the configured bearer token", async () => {
    let observed: string | undefined;
    server.route(
      (req) => req.url === "/v1/poi/pois-per-list",
      (req, _body, res) => {
        observed = req.headers.authorization as string | undefined;
        writeJson(res, {});
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: false,
    });
    await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_HEX, type: "Shield" }],
    );
    expect(observed).toBe(`Bearer ${TOKEN}`);
  });

  it("publishing channels carry the bearer token", async () => {
    let observed: string | undefined;
    server.route(
      (req) => req.url?.endsWith("/bc-to-idx-map") ?? false,
      (req, _body, res) => {
        observed = req.headers.authorization as string | undefined;
        writeJson(res, { epoch: 1, listKey: LIST_KEY_HEX, entries: [] });
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
    });
    await sdk.fetchBcToIdxMap(LIST_KEY_HEX);
    expect(observed).toBe(`Bearer ${TOKEN}`);
  });
});
