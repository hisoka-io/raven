import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  RavenPOINodeInterface,
  RavenError,
  containsByteSequence,
  hexToBytes,
  type ClientPirContext,
  type RavenConfig,
  type RavenInspireWasm,
  type StaleDataContext,
} from "../src/index";
import {
  encodeBatchResponse,
  encodedBatchCount,
  stubCtx as authPathContext,
} from "./helpers/auth_path_stub";
import { makeRegisterSpy, stubRemoteSessionExports } from "./helpers/register_spy";
import { startMockServer, writeBinary, writeJson, type MockServer } from "./helpers/mock_server";
import {
  assertNoCommitmentsInPirRequests,
  STUB_QUERY_BYTES,
  stubQueryBundle,
} from "./helpers/private_wire";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "ab".repeat(32);
const BC_HEX = "00".repeat(31) + "01";
const STALE_FRESHNESS = "lag_blocks=999 applied_height=10 epoch=1 confidence=0.10";

// @ts-expect-error disclosure opt-in requires the upstream endpoint it will contact.
const INVALID_DISCLOSURE_CONFIG: RavenConfig = {
  endpoint: "http://127.0.0.1",
  bearerToken: TOKEN,
  privateStalePolicy: "allow-upstream-disclosure",
};
void INVALID_DISCLOSURE_CONFIG;

const POLICY_ROWS = [
  { label: "fresh without endpoint", confidence: 0.99, endpoint: false, policy: "refuse", verdict: "private" },
  { label: "floor equality with endpoint", confidence: 0.5, endpoint: true, policy: "refuse", verdict: "private" },
  { label: "stale without endpoint", confidence: 0.1, endpoint: false, policy: "refuse", verdict: "stale" },
  { label: "stale with endpoint by default", confidence: 0.1, endpoint: true, policy: "refuse", verdict: "stale" },
  { label: "stale with disclosure opt-in", confidence: 0.1, endpoint: true, policy: "allow", verdict: "fallback" },
  { label: "fresh with disclosure opt-in", confidence: 0.99, endpoint: true, policy: "allow", verdict: "private" },
] as const;

function statusContext(): ClientPirContext {
  const row = new Uint8Array(32);
  row[0] = 0;
  row.set(hexToBytes(BC_HEX).subarray(0, 31), 1);
  const wasm: RavenInspireWasm = {
    ...stubRemoteSessionExports(),
    build_client_session: () => ({ free: () => undefined }),
    build_seeded_query: () => stubQueryBundle(),
    extract_response: () => new Uint8Array(row),
    build_instance_params_blob: () => new Uint8Array(0),
    register_client_session: makeRegisterSpy(),
    path_indices_for_leaf: () => new Uint32Array(16),
    path_indices_for_per_list_leaf: () => new Uint32Array(16),
  };
  return {
    wasm,
    session: { free: () => undefined },
    crsBincode: new Uint8Array(0),
    shardConfigBincode: new Uint8Array(0),
    entrySize: 32,
  };
}

describe("private response freshness fallback", () => {
  let adapter: MockServer;
  let upstream: MockServer;

  beforeAll(async () => {
    adapter = await startMockServer();
    upstream = await startMockServer();
  });

  afterAll(async () => {
    await adapter.close();
    await upstream.close();
  });

  afterEach(() => {
    adapter.reset();
    upstream.reset();
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -0.01, 1.01])(
    "rejects invalid confidence floor %s before I/O",
    (floor) => {
      let thrown: unknown;
      try {
        new RavenPOINodeInterface({
          endpoint: adapter.url,
          bearerToken: TOKEN,
          freshnessConfidenceFloor: floor,
        });
      } catch (error) {
        thrown = error;
      }
      expect(RavenError.is(thrown, "InvalidQuery")).toBe(true);
      expect(String((thrown as Error).message)).toMatch(/freshnessConfidenceFloor.*finite.*\[0,1\]/);
      expect(adapter.requests).toHaveLength(0);
      expect(upstream.requests).toHaveLength(0);
    },
  );

  it("a negative confidence floor cannot turn confidence 0.10 into Valid", async () => {
    adapter.route(
      (req) => req.url?.endsWith("/batch") ?? false,
      (_req, body, res) => {
        writeBinary(res, encodeBatchResponse(1, encodedBatchCount(body)), {
          "x-raven-freshness": STALE_FRESHNESS,
        });
        return true;
      },
    );
    let returnedValid = false;
    let thrown: unknown;
    try {
      const sdk = new RavenPOINodeInterface({
        endpoint: adapter.url,
        bearerToken: TOKEN,
        freshnessConfidenceFloor: -1,
        useClientPir: true,
        clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, statusContext()]]),
        bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_HEX, 0]])]]),
      });
      const statuses = await sdk.getPOIsPerList(
        [LIST_KEY_HEX],
        [{ blindedCommitment: BC_HEX, type: "Shield" }],
      );
      returnedValid = statuses[BC_HEX][LIST_KEY_HEX] === "Valid";
    } catch (error) {
      thrown = error;
    }
    expect(returnedValid).toBe(false);
    expect(RavenError.is(thrown, "InvalidQuery")).toBe(true);
    expect(adapter.requests).toHaveLength(0);
  });

  it.each([
    { floor: 0, confidence: 0.1 },
    { floor: 1, confidence: 1 },
  ])("accepts boundary floor $floor and keeps equality private", async ({ floor, confidence }) => {
    adapter.route(
      (req) => req.url?.endsWith("/batch") ?? false,
      (_req, body, res) => {
        writeBinary(res, encodeBatchResponse(1, encodedBatchCount(body)), {
          "x-raven-freshness":
            `lag_blocks=0 applied_height=10 epoch=1 confidence=${confidence}`,
        });
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: adapter.url,
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: upstream.url,
      freshnessConfidenceFloor: floor,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, statusContext()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_HEX, 0]])]]),
    });
    const statuses = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_HEX, type: "Shield" }],
    );
    expect(statuses[BC_HEX][LIST_KEY_HEX]).toBe("Valid");
    expect(upstream.requests).toHaveLength(0);
  });

  it("refuses a stale spend-authorizing status by default without upstream traffic", async () => {
    adapter.route(
      (req) => req.url?.endsWith("/batch") ?? false,
      (_req, body, res) => {
        writeBinary(res, encodeBatchResponse(1, encodedBatchCount(body)), {
          "x-raven-freshness": STALE_FRESHNESS,
        });
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: adapter.url,
      bearerToken: TOKEN,
      useClientPir: true,
      freshnessConfidenceFloor: 0.5,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, statusContext()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_HEX, 0]])]]),
    });

    let returned = false;
    let thrown: unknown;
    try {
      const statuses = await sdk.getPOIsPerList(
        [LIST_KEY_HEX],
        [{ blindedCommitment: BC_HEX, type: "Shield" }],
      );
      returned = statuses[BC_HEX][LIST_KEY_HEX] === "Valid";
    } catch (error) {
      thrown = error;
    }

    expect(returned, "confidence 0.10 must never return spend-authorizing Valid").toBe(false);
    expect(thrown).toMatchObject({
      kind: "StaleData",
      context: {
        operation: "t1-status",
        lagBlocks: 999,
        appliedHeight: 10,
        epoch: 1,
        confidence: 0.1,
        confidenceFloor: 0.5,
      },
    });
    expect(upstream.requests).toHaveLength(0);
    expect(
      assertNoCommitmentsInPirRequests(adapter.requests, [BC_HEX], {
        expectedQueryCount: 1,
        expectedQueryBytes: STUB_QUERY_BYTES,
      }),
    ).toHaveLength(1);
  });

  it("explicitly falls back from a low-confidence private status", async () => {
    adapter.route(
      (req) => req.url?.endsWith("/batch") ?? false,
      (_req, body, res) => {
        writeBinary(res, encodeBatchResponse(1, encodedBatchCount(body)), {
          "x-raven-freshness": STALE_FRESHNESS,
        });
        return true;
      },
    );
    upstream.route(
      (req) => req.url === "/pois-per-list/0/1",
      (_req, _body, res) => {
        writeJson(res, { [BC_HEX]: { [LIST_KEY_HEX]: "ShieldBlocked" } });
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: adapter.url,
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: upstream.url,
      privateStalePolicy: "allow-upstream-disclosure",
      useClientPir: true,
      freshnessConfidenceFloor: 0.5,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, statusContext()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_HEX, 0]])]]),
    });

    const statuses = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_HEX, type: "Shield" }],
    );

    expect(statuses[BC_HEX][LIST_KEY_HEX]).toBe("ShieldBlocked");
    expect(upstream.requests).toHaveLength(1);
    expect(adapter.requests).toHaveLength(2);
    expect(
      assertNoCommitmentsInPirRequests(adapter.requests, [BC_HEX], {
        expectedQueryCount: 1,
        expectedQueryBytes: STUB_QUERY_BYTES,
      }),
    ).toHaveLength(1);
    expect(
      containsByteSequence(upstream.requests[0].body, new TextEncoder().encode(BC_HEX)),
    ).toBe(true);
  });

  it("explicitly falls back from a low-confidence private auth path", async () => {
    adapter.route(
      (req) => req.url?.endsWith("/batch") ?? false,
      (_req, body, res) => {
        writeBinary(res, encodeBatchResponse(1, encodedBatchCount(body)), {
          "x-raven-epoch": "1",
          "x-raven-schema-version": "3",
          "x-raven-freshness": STALE_FRESHNESS,
        });
        return true;
      },
    );
    const upstreamProof = {
      leaf: BC_HEX,
      elements: Array.from({ length: 16 }, () => "11".repeat(32)),
      indices: "0".repeat(64),
      root: "22".repeat(32),
    };
    upstream.route(
      (req) => req.url === "/merkle-proofs/0/1",
      (_req, _body, res) => {
        writeJson(res, [upstreamProof]);
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: adapter.url,
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: upstream.url,
      privateStalePolicy: "allow-upstream-disclosure",
      useClientPir: true,
      freshnessConfidenceFloor: 0.5,
      clientPirContexts: new Map([[`t2Path:${LIST_KEY_HEX}`, authPathContext()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_HEX, 0]])]]),
    });

    const proofs = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);

    expect(proofs).toEqual([upstreamProof]);
    expect(upstream.requests).toHaveLength(1);
    expect(adapter.requests).toHaveLength(2);
    expect(
      assertNoCommitmentsInPirRequests(adapter.requests, [BC_HEX], {
        expectedQueryCount: 16,
        expectedQueryBytes: STUB_QUERY_BYTES,
      }),
    ).toHaveLength(1);
    expect(
      containsByteSequence(upstream.requests[0].body, new TextEncoder().encode(BC_HEX)),
    ).toBe(true);
  });

  for (const operation of ["t1-status", "t2-auth-path"] as const) {
    it.each(POLICY_ROWS)(`${operation}: $label`, async (row) => {
      const freshness =
        `lag_blocks=999 applied_height=10 epoch=1 confidence=${row.confidence}`;
      adapter.route(
        (req) => req.url?.endsWith("/batch") ?? false,
        (_req, body, res) => {
          writeBinary(res, encodeBatchResponse(1, encodedBatchCount(body)), {
            "x-raven-epoch": "1",
            "x-raven-schema-version": "3",
            "x-raven-freshness": freshness,
          });
          return true;
        },
      );
      const upstreamProof = {
        leaf: BC_HEX,
        elements: Array.from({ length: 16 }, () => "11".repeat(32)),
        indices: "0".repeat(64),
        root: "22".repeat(32),
      };
      upstream.route(
        (req) => req.url === "/pois-per-list/0/1",
        (_req, _body, res) => {
          writeJson(res, { [BC_HEX]: { [LIST_KEY_HEX]: "ShieldBlocked" } });
          return true;
        },
      );
      upstream.route(
        (req) => req.url === "/merkle-proofs/0/1",
        (_req, _body, res) => {
          writeJson(res, [upstreamProof]);
          return true;
        },
      );

      const base = {
        endpoint: adapter.url,
        bearerToken: TOKEN,
        useClientPir: true,
        freshnessConfidenceFloor: 0.5,
        clientPirContexts: new Map([
          [`t1Status:${LIST_KEY_HEX}`, statusContext()],
          [`t2Path:${LIST_KEY_HEX}`, authPathContext()],
        ]),
        bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_HEX, 0]])]]),
      };
      const config: RavenConfig = row.policy === "allow"
        ? {
            ...base,
            upstreamFallbackEndpoint: upstream.url,
            privateStalePolicy: "allow-upstream-disclosure",
          }
        : row.endpoint
          ? { ...base, upstreamFallbackEndpoint: upstream.url }
          : base;
      const sdk = new RavenPOINodeInterface(config);

      let returned: unknown;
      let thrown: unknown;
      try {
        returned = operation === "t1-status"
          ? await sdk.getPOIsPerList(
              [LIST_KEY_HEX],
              [{ blindedCommitment: BC_HEX, type: "Shield" }],
            )
          : await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
      } catch (error) {
        thrown = error;
      }

      if (row.verdict === "stale") {
        expect(returned).toBeUndefined();
        expect(RavenError.is(thrown, "StaleData")).toBe(true);
        if (RavenError.is(thrown, "StaleData")) {
          const context: StaleDataContext = thrown.context;
          expect(context).toEqual({
            operation,
            lagBlocks: 999,
            appliedHeight: 10,
            epoch: 1,
            confidence: 0.1,
            confidenceFloor: 0.5,
          });
          expect(Object.keys(context).sort()).toEqual([
            "appliedHeight",
            "confidence",
            "confidenceFloor",
            "epoch",
            "lagBlocks",
            "operation",
          ]);
        }
      } else if (row.verdict === "fallback") {
        if (operation === "t1-status") {
          expect(returned).toEqual({ [BC_HEX]: { [LIST_KEY_HEX]: "ShieldBlocked" } });
        } else {
          expect(returned).toEqual([upstreamProof]);
        }
      } else if (operation === "t1-status") {
        expect(returned).toEqual({ [BC_HEX]: { [LIST_KEY_HEX]: "Valid" } });
      } else {
        expect(returned).toMatchObject([{ leaf: BC_HEX }]);
        expect(returned).not.toEqual([upstreamProof]);
      }

      const upstreamRequests = upstream.requests.filter((request) =>
        request.url === (operation === "t1-status" ? "/pois-per-list/0/1" : "/merkle-proofs/0/1")
      );
      expect(upstreamRequests).toHaveLength(row.verdict === "fallback" ? 1 : 0);
      if (row.verdict === "fallback") {
        const body = JSON.parse(new TextDecoder().decode(upstreamRequests[0].body));
        expect(body.listKeys ?? [body.listKey]).toEqual([LIST_KEY_HEX]);
        expect(
          body.blindedCommitmentDatas?.map(
            (commitment: { blindedCommitment: string }) => commitment.blindedCommitment,
          ) ?? body.blindedCommitments,
        ).toEqual([BC_HEX]);
      }
      expect(
        assertNoCommitmentsInPirRequests(adapter.requests, [BC_HEX], {
          expectedQueryCount: operation === "t1-status" ? 1 : 16,
          expectedQueryBytes: STUB_QUERY_BYTES,
        }),
      ).toHaveLength(1);
    });

    it(`${operation}: disclosure policy without endpoint is rejected before I/O`, () => {
      const invalid = {
        endpoint: adapter.url,
        bearerToken: TOKEN,
        privateStalePolicy: "allow-upstream-disclosure",
      } as RavenConfig;
      expect(() => new RavenPOINodeInterface(invalid)).toThrow(/requires upstreamFallbackEndpoint/);
      expect(adapter.requests).toHaveLength(0);
      expect(upstream.requests).toHaveLength(0);
    });

    it.each([
      { label: "absent", header: null, kind: "StaleAdapter" as const },
      { label: "malformed", header: "confidence=not-a-number", kind: "DecodeError" as const },
    ])(`${operation}: $label freshness fails closed`, async ({ header, kind }) => {
      adapter.route(
        (req) => req.url?.endsWith("/batch") ?? false,
        (_req, body, res) => {
          const headers: Record<string, string> = {
            "content-type": "application/octet-stream",
            "x-raven-epoch": "1",
            "x-raven-schema-version": "3",
          };
          if (header !== null) headers["x-raven-freshness"] = header;
          res.writeHead(200, headers);
          res.end(Buffer.from(encodeBatchResponse(1, encodedBatchCount(body))));
          return true;
        },
      );
      const sdk = new RavenPOINodeInterface({
        endpoint: adapter.url,
        bearerToken: TOKEN,
        upstreamFallbackEndpoint: upstream.url,
        useClientPir: true,
        clientPirContexts: new Map([
          [`t1Status:${LIST_KEY_HEX}`, statusContext()],
          [`t2Path:${LIST_KEY_HEX}`, authPathContext()],
        ]),
        bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_HEX, 0]])]]),
      });

      let returned: unknown;
      let thrown: unknown;
      try {
        returned = operation === "t1-status"
          ? await sdk.getPOIsPerList(
              [LIST_KEY_HEX],
              [{ blindedCommitment: BC_HEX, type: "Shield" }],
            )
          : await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
      } catch (error) {
        thrown = error;
      }
      expect(returned).toBeUndefined();
      expect(RavenError.is(thrown, kind)).toBe(true);
      expect(upstream.requests).toHaveLength(0);
      expect(
        assertNoCommitmentsInPirRequests(adapter.requests, [BC_HEX], {
          expectedQueryCount: operation === "t1-status" ? 1 : 16,
          expectedQueryBytes: STUB_QUERY_BYTES,
        }),
      ).toHaveLength(1);
    });
  }
});
