import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  RavenPOINodeInterface,
  RavenError,
  containsByteSequence,
  foldMerkleRoot,
  hexToBytes,
  type ClientPirContext,
  type RavenConfig,
  type RavenInspireWasm,
  type StaleDataContext,
} from "../src/index";
import {
  encodeBatchResponse,
  encodeBatchResponseNodes,
  stubCtx as nodeAuthPathContext,
} from "./helpers/auth_path_stub";
import {
  PATH10_ROW_BYTES,
  path10Root,
  path10Siblings,
  path10Slot,
} from "./helpers/path10_row";
import { makeRegisterSpy, stubRemoteSessionExports } from "./helpers/register_spy";
import {
  readJsonRpcRequest,
  startMockServer,
  writeBinary,
  writeJsonRpcResult,
  type MockServer,
} from "./helpers/mock_server";
import {
  assertNoCommitmentsInPirRequests,
  STUB_QUERY_BYTES,
  stubQueryBundle,
} from "./helpers/private_wire";
import { shardConfigBincode } from "./helpers/shard_config";

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
    shardConfigBincode: shardConfigBincode(),
    entrySize: 32,
  };
}

/** Siblings and the root the SDK must fold to for BC_HEX at local leaf 0. */
const PATH10_NODES = path10Siblings(0xab);
const PATH10_ROOT = path10Root(BC_HEX, PATH10_NODES, 0);
const PATH10_HEX = PATH10_NODES.map((node) => Buffer.from(node).toString("hex"));
const BLOCK0_LAST_INDEX = 65_535;
/** An honest upstream proof for BC_HEX at leaf 0, spelled as upstream spells it: `0x` on the
 *  leaf and on the first element only. */
const UPSTREAM_PROOF = {
  leaf: `0x${BC_HEX}`,
  elements: [`0x${PATH10_HEX[0]}`, ...PATH10_HEX.slice(1)],
  indices: "0".repeat(64),
  root: PATH10_ROOT,
};
/** Claims the honest root, but its elements are garbage and fold to something else. */
const FORGED_PROOF = {
  leaf: BC_HEX,
  elements: Array.from({ length: 16 }, () => "11".repeat(32)),
  indices: "0".repeat(64),
  root: PATH10_ROOT,
};
/** Folds to the root it claims, but over fifteen levels: an interior node posing as a leaf. */
const SHORT_PROOF = (() => {
  const elements = UPSTREAM_PROOF.elements.slice(0, 15);
  return { ...UPSTREAM_PROOF, elements, root: foldMerkleRoot(BC_HEX, elements, 0n) };
})();
/** Folds to the honest root, since the fold reads only sixteen index bits. */
const OUT_OF_RANGE_PROOF = {
  ...UPSTREAM_PROOF,
  indices: (1n << 16n).toString(16).padStart(64, "0"),
};

function authPathContext(): ClientPirContext {
  return { ...nodeAuthPathContext(), entrySize: PATH10_ROW_BYTES };
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

  // `allow-upstream-disclosure` means "re-ask a DIFFERENT party". Aimed back at this node
  // the caller consents to disclosure and gets the same stale answer from the same operator,
  // so the consent buys nothing and the policy name is false.
  it("refuses a disclosure fallback aimed at the endpoint it falls back from", () => {
    let thrown: unknown;
    try {
      new RavenPOINodeInterface({
        endpoint: adapter.url,
        bearerToken: TOKEN,
        privateStalePolicy: "allow-upstream-disclosure",
        upstreamFallbackEndpoint: `${adapter.url}/`,
      });
    } catch (error) {
      thrown = error;
    }
    expect(RavenError.is(thrown, "InvalidQuery")).toBe(true);
    expect(String((thrown as Error).message)).toMatch(/must not be the endpoint it falls back from/);
    expect(adapter.requests).toHaveLength(0);
    expect(upstream.requests).toHaveLength(0);
  });

  // The same policy against a genuinely separate party is accepted.
  it("accepts a disclosure fallback aimed at a separate party", () => {
    expect(
      () =>
        new RavenPOINodeInterface({
          endpoint: adapter.url,
          bearerToken: TOKEN,
          privateStalePolicy: "allow-upstream-disclosure",
          upstreamFallbackEndpoint: upstream.url,
        }),
    ).not.toThrow();
  });

  it("a negative confidence floor cannot turn confidence 0.10 into Valid", async () => {
    adapter.route(
      (req) => req.url?.endsWith("/batch") ?? false,
      (_req, body, res) => {
        writeBinary(res, encodeBatchResponse(1, body), {
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
        writeBinary(res, encodeBatchResponse(1, body), {
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
        writeBinary(res, encodeBatchResponse(1, body), {
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
        writeBinary(res, encodeBatchResponse(1, body), {
          "x-raven-freshness": STALE_FRESHNESS,
        });
        return true;
      },
    );
    upstream.route(
      (req) => req.url === "/",
      (_req, body, res) => {
        const request = writeJsonRpcResult(
          body,
          res,
          { [BC_HEX]: { [LIST_KEY_HEX]: "ShieldBlocked" } },
        );
        expect(request.method).toBe("ppoi_pois_per_list");
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

  // Low confidence is the server's own claim, so it must not buy the wallet an unverified proof.
  // The fallback proof is folded, and the fold must match a root from a party other than the
  // upstream that sent the proof: a root from the proof's own source verifies nothing.
  function staleAuthPathRoute(): void {
    adapter.route(
      (req) => req.url?.endsWith("/batch") ?? false,
      (_req, body, res) => {
        writeBinary(res, encodeBatchResponse(1, body), {
          "x-raven-epoch": "1",
          "x-raven-schema-version": "6",
          "x-raven-freshness": STALE_FRESHNESS,
        });
        return true;
      },
    );
  }

  function upstreamAnswers(proof: unknown): void {
    upstream.route(
      (req) => req.url === "/",
      (_req, body, res) => {
        const request = writeJsonRpcResult(body, res, [proof]);
        expect(request.method).toBe("ppoi_merkle_proofs");
        return true;
      },
    );
  }

  function fallbackSdk(extra: Partial<RavenConfig> = {}): RavenPOINodeInterface {
    return new RavenPOINodeInterface({
      endpoint: adapter.url,
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: upstream.url,
      privateStalePolicy: "allow-upstream-disclosure",
      useClientPir: true,
      freshnessConfidenceFloor: 0.5,
      clientPirContexts: new Map([[`t2Path:${LIST_KEY_HEX}`, authPathContext()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_HEX, 0]])]]),
      ...extra,
    } as RavenConfig);
  }

  async function fallbackOutcome(sdk: RavenPOINodeInterface): Promise<{
    returned: unknown;
    thrown: unknown;
  }> {
    try {
      return { returned: await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]), thrown: undefined };
    } catch (error) {
      return { returned: undefined, thrown: error };
    }
  }

  // The root a proof claims is only its sender's word, so each of these claims exactly the root the
  // caller pinned and is still refused.
  it.each([
    { label: "garbage elements", proof: FORGED_PROOF, reason: /does not fold to the root it claims/ },
    { label: "fifteen elements", proof: SHORT_PROOF, reason: /has 15 elements/ },
    { label: "indices past a depth-16 tree", proof: OUT_OF_RANGE_PROOF, reason: /has indices/ },
  ])("refuses a fallback proof with $label that claims the pinned root", async ({ proof, reason }) => {
    staleAuthPathRoute();
    upstreamAnswers(proof);
    const sdk = fallbackSdk({ ppoiPinnedRoots: new Map([[`${LIST_KEY_HEX}:0`, proof.root]]) });

    const { returned, thrown } = await fallbackOutcome(sdk);

    expect(returned).toBeUndefined();
    expect(RavenError.is(thrown, "DecodeError"), String(thrown)).toBe(true);
    expect(String((thrown as Error).message)).toMatch(reason);
    expect(upstream.requests).toHaveLength(1);
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

  // Upstream would be asked for the proof and for the root that checks it, which is circular,
  // so the call refuses before the commitment is disclosed at all.
  it("refuses before disclosing when upstream is the only root source", async () => {
    staleAuthPathRoute();
    upstreamAnswers(UPSTREAM_PROOF);
    const sdk = fallbackSdk();

    const { returned, thrown } = await fallbackOutcome(sdk);

    expect(returned).toBeUndefined();
    expect(RavenError.is(thrown, "InvalidQuery"), String(thrown)).toBe(true);
    expect(String((thrown as Error).message)).toMatch(/no root from a party other than/);
    expect(upstream.requests).toHaveLength(0);
  });

  it("refuses before disclosing under a pin source on upstream's own origin", async () => {
    staleAuthPathRoute();
    upstreamAnswers(UPSTREAM_PROOF);
    const sdk = fallbackSdk({ pinUpstream: `${upstream.url}/pins` });

    const { returned, thrown } = await fallbackOutcome(sdk);

    expect(returned).toBeUndefined();
    expect(RavenError.is(thrown, "InvalidQuery"), String(thrown)).toBe(true);
    expect(upstream.requests).toHaveLength(0);
  });

  // With no resolver at all, the fold-time check would refuse too, but only after the commitment
  // had reached upstream, and a disclosure cannot be taken back.
  it.each([
    { label: "pin verification is switched off", extra: { pinUpstream: false } },
    { label: "the chain has no upstream network name", extra: { chainId: 10 } },
  ] as const)("refuses before disclosing when $label", async ({ extra }) => {
    staleAuthPathRoute();
    upstreamAnswers(UPSTREAM_PROOF);
    const sdk = fallbackSdk(extra);

    const { returned, thrown } = await fallbackOutcome(sdk);

    expect(returned).toBeUndefined();
    expect(RavenError.is(thrown, "InvalidQuery"), String(thrown)).toBe(true);
    expect(String((thrown as Error).message)).toMatch(/no root from a party other than/);
    expect(upstream.requests).toHaveLength(0);
  });

  it("returns a fallback proof that folds to the caller's pinned root", async () => {
    staleAuthPathRoute();
    upstreamAnswers(UPSTREAM_PROOF);
    const sdk = fallbackSdk({ ppoiPinnedRoots: new Map([[`${LIST_KEY_HEX}:0`, PATH10_ROOT]]) });

    const proofs = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);

    expect(proofs).toEqual([UPSTREAM_PROOF]);
    expect(upstream.requests).toHaveLength(1);
    expect(adapter.requests).toHaveLength(2);
  });

  it("refuses a fallback proof whose fold is not the caller's pinned root", async () => {
    staleAuthPathRoute();
    upstreamAnswers(UPSTREAM_PROOF);
    const sdk = fallbackSdk({ ppoiPinnedRoots: new Map([[`${LIST_KEY_HEX}:0`, "33".repeat(32)]]) });

    const { returned, thrown } = await fallbackOutcome(sdk);

    expect(returned).toBeUndefined();
    expect(RavenError.is(thrown, "DecodeError"), String(thrown)).toBe(true);
  });

  // Block groups are fetched one after another, so the anchor guards each group's own commitments:
  // a later group that could only refuse is refused before it reaches upstream.
  it("refuses a later block group with no independent root before disclosing it", async () => {
    const secondBlockBc = "00".repeat(31) + "02";
    staleAuthPathRoute();
    upstreamAnswers(UPSTREAM_PROOF);
    const sdk = fallbackSdk({
      bcToIdxMaps: new Map([
        [LIST_KEY_HEX, new Map([[BC_HEX, 0], [secondBlockBc, BLOCK0_LAST_INDEX + 1]])],
      ]),
      clientPirInstanceLabels: new Map([[`t2Path:${LIST_KEY_HEX}:1`, "ppoi-paths-1"]]),
      ppoiPinnedRoots: new Map([[`${LIST_KEY_HEX}:0`, PATH10_ROOT]]),
    });

    let thrown: unknown;
    try {
      await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX, secondBlockBc]);
    } catch (error) {
      thrown = error;
    }

    expect(RavenError.is(thrown, "InvalidQuery"), String(thrown)).toBe(true);
    expect(String((thrown as Error).message)).toMatch(
      new RegExp(`no pinned root for ${LIST_KEY_HEX}:1 on chain`),
    );
    for (const request of upstream.requests) {
      expect(
        containsByteSequence(request.body, new TextEncoder().encode(secondBlockBc)),
      ).toBe(false);
    }
  });

  describe("with a pin source that is not upstream", () => {
    let pins: MockServer;

    beforeAll(async () => {
      pins = await startMockServer();
    });
    afterAll(async () => {
      await pins.close();
    });
    afterEach(() => {
      pins.reset();
    });

    function pinsCertify(root: string): void {
      pins.route(
        (req) => req.url === "/",
        (_req, body, res) => {
          const request = readJsonRpcRequest(body);
          expect(request.method).toBe("ppoi_poi_events");
          writeJsonRpcResult(body, res, [
            {
              signedPOIEvent: { index: BLOCK0_LAST_INDEX },
              validatedMerkleroot: root,
            },
          ]);
          return true;
        },
      );
    }

    it("verifies the fallback proof against the root that source certifies", async () => {
      staleAuthPathRoute();
      upstreamAnswers(UPSTREAM_PROOF);
      pinsCertify(PATH10_ROOT);
      const sdk = fallbackSdk({ pinUpstream: pins.url });

      const proofs = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);

      expect(proofs).toEqual([UPSTREAM_PROOF]);
      expect(upstream.requests).toHaveLength(1);
      expect(pins.requests).toHaveLength(1);
      expect(
        containsByteSequence(pins.requests[0].body, new TextEncoder().encode(BC_HEX)),
      ).toBe(false);
    });

    it("refuses a forged fallback proof that claims the root that source certifies", async () => {
      staleAuthPathRoute();
      upstreamAnswers(FORGED_PROOF);
      pinsCertify(FORGED_PROOF.root);
      const sdk = fallbackSdk({ pinUpstream: pins.url });

      const { returned, thrown } = await fallbackOutcome(sdk);

      expect(returned).toBeUndefined();
      expect(RavenError.is(thrown, "DecodeError"), String(thrown)).toBe(true);
      expect(String((thrown as Error).message)).toMatch(/does not fold to the root it claims/);
    });

    it("refuses the fallback proof when its fold misses that root", async () => {
      staleAuthPathRoute();
      upstreamAnswers(UPSTREAM_PROOF);
      pinsCertify("44".repeat(32));
      const sdk = fallbackSdk({ pinUpstream: pins.url });

      const { returned, thrown } = await fallbackOutcome(sdk);

      expect(returned).toBeUndefined();
      expect(RavenError.is(thrown, "DecodeError"), String(thrown)).toBe(true);
      expect(pins.requests.length).toBeGreaterThan(0);
    });
  });

  for (const operation of ["t1-status", "t2-auth-path"] as const) {
    it.each(POLICY_ROWS)(`${operation}: $label`, async (row) => {
      const freshness =
        `lag_blocks=999 applied_height=10 epoch=1 confidence=${row.confidence}`;
      adapter.route(
        (req) => req.url?.endsWith("/batch") ?? false,
        (reqInfo, body, res) => {
          const isPath = (reqInfo.url ?? "").includes("t2Path");
          const payload = isPath
            ? encodeBatchResponseNodes([
                path10Slot({ bcHex: BC_HEX, nodes: PATH10_NODES }),
              ])
            : encodeBatchResponse(1, body);
          writeBinary(res, payload, {
            "x-raven-epoch": "1",
            "x-raven-schema-version": "7",
            "x-raven-freshness": freshness,
          });
          return true;
        },
      );
      const upstreamProof = UPSTREAM_PROOF;
      upstream.route(
        (req) => req.url === "/",
        (_req, body, res) => {
          const request = readJsonRpcRequest(body);
          const result = request.method === "ppoi_pois_per_list"
            ? { [BC_HEX]: { [LIST_KEY_HEX]: "ShieldBlocked" } }
            : [upstreamProof];
          writeJsonRpcResult(body, res, result);
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
        // Every path-10 fold requires a pinned root.
        ppoiPinnedRoots: new Map([[`${LIST_KEY_HEX}:0`, PATH10_ROOT]]),
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
        request.url === "/"
      );
      expect(upstreamRequests).toHaveLength(row.verdict === "fallback" ? 1 : 0);
      if (row.verdict === "fallback") {
        const body = JSON.parse(new TextDecoder().decode(upstreamRequests[0].body));
        expect(body.params.listKeys ?? [body.params.listKey]).toEqual([LIST_KEY_HEX]);
        expect(
          body.params.blindedCommitmentDatas?.map(
            (commitment: { blindedCommitment: string }) => commitment.blindedCommitment,
          ) ?? body.params.blindedCommitments,
        ).toEqual([BC_HEX]);
      }
      expect(
        assertNoCommitmentsInPirRequests(adapter.requests, [BC_HEX], {
          expectedQueryCount: 1,
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
            "x-raven-schema-version": "6",
          };
          if (header !== null) headers["x-raven-freshness"] = header;
          res.writeHead(200, headers);
          res.end(Buffer.from(encodeBatchResponse(1, body)));
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
          expectedQueryCount: 1,
          expectedQueryBytes: STUB_QUERY_BYTES,
        }),
      ).toHaveLength(1);
    });
  }
});
