// No call path leaks plaintext BC bytes when useClientPir is true. Asserts only the
// OUTGOING direction; response decode is allowed to fail (tolerated via try/catch).

import { afterEach, beforeAll, describe, expect, it, afterAll } from "vitest";

import { RavenPOINodeInterface, containsByteSequence } from "../src/index";
import type { ClientPirContext } from "../src/index";

import { loadFixture, makeClientPirContext } from "./helpers/fixture";
import { encodeBatchResponseNodes, encodedBatchCount } from "./helpers/auth_path_stub";
import { startMockServer, writeBinary, writeJson, type MockServer } from "./helpers/mock_server";
import {
  assertNoCommitmentsInPirRequests,
  inspectPirDataPosts,
} from "./helpers/private_wire";

const TOKEN = "test-token-padded-long-enough-1234";

function makeMaps(fixture: ReturnType<typeof loadFixture>, ctx: ClientPirContext) {
  const lk = fixture.meta.list_key_hex;
  const ctxs = new Map<string, ClientPirContext>([
    [`t1Status:${lk}`, ctx],
    [`t2Path:${lk}`, ctx],
    [`t3CommitTree:0`, ctx],
    [`t3CommitTree:1`, ctx],
  ]);
  const bcMap = new Map<string, number>();
  for (const idx of fixture.meta.target_indices) {
    bcMap.set(fixture.meta.bcs_hex[idx], idx);
  }
  const bcMaps = new Map<string, Map<string, number>>([[lk, bcMap]]);
  return { ctxs, bcMaps };
}

describe("privacy across every SDK call path", () => {
  let fixture: ReturnType<typeof loadFixture>;
  let ctx: ClientPirContext;
  let server: MockServer;

  beforeAll(async () => {
    fixture = loadFixture();
    ctx = makeClientPirContext(fixture);
    server = await startMockServer();
  });

  afterAll(async () => {
    if (server) await server.close();
    if (ctx) ctx.session.free();
  });

  afterEach(() => {
    server.reset();
  });

  it("getPOIsPerList client-PIR path leaks no BC bytes", async () => {
    const responses = Array.from(fixture.responsesByIdx.values());
    let cursor = 0;
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/(query|batch)$/.test(req.url ?? ""),
      (req, _body, res) => {
        if ((req.url ?? "").endsWith("/batch")) {
          const r = responses[cursor % responses.length];
          cursor += 1;
          writeBinary(res, encodeBatchResponseNodes(new Array<Uint8Array>(16).fill(r)));
          return true;
        }
        const r = responses[cursor % responses.length];
        cursor += 1;
        writeBinary(res, r);
        return true;
      },
    );

    const { ctxs, bcMaps } = makeMaps(fixture, ctx);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: ctxs,
      bcToIdxMaps: bcMaps,
    });

    const queriedBcs = fixture.meta.target_indices.map((idx) => fixture.meta.bcs_hex[idx]);
    try {
      await sdk.getPOIsPerList(
        [fixture.meta.list_key_hex],
        queriedBcs.map((bc) => ({ blindedCommitment: bc, type: "Shield" as const })),
      );
    } catch {
    }
    expect(
      assertNoCommitmentsInPirRequests(sdk.lastWireRequests(), queriedBcs, {
        expectedQueryCount: 8,
      }),
    ).toHaveLength(1);
    expect(
      assertNoCommitmentsInPirRequests(server.requests, queriedBcs, {
        expectedQueryCount: 8,
      }),
    ).toHaveLength(1);
    const sessionOnly = server.requests.filter((request) => request.url.endsWith("/session"));
    expect(sessionOnly).toHaveLength(1);
    expect(() =>
      assertNoCommitmentsInPirRequests(sessionOnly, queriedBcs, {
        expectedQueryCount: 8,
      }),
    ).toThrow(/selected no POST query\/batch\/fanout requests/);
  });

  it("getPOIMerkleProofs client-PIR path leaks no BC bytes", async () => {
    const responses = Array.from(fixture.responsesByIdx.values());
    let cursor = 0;
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/(query|batch)$/.test(req.url ?? ""),
      (req, _body, res) => {
        if ((req.url ?? "").endsWith("/batch")) {
          const r = responses[cursor % responses.length];
          cursor += 1;
          writeBinary(res, encodeBatchResponseNodes(new Array<Uint8Array>(16).fill(r)));
          return true;
        }
        const r = responses[cursor % responses.length];
        cursor += 1;
        writeBinary(res, r);
        return true;
      },
    );

    const { ctxs, bcMaps } = makeMaps(fixture, ctx);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: ctxs,
      bcToIdxMaps: bcMaps,
    });

    const queriedBcs = fixture.meta.target_indices.map((idx) => fixture.meta.bcs_hex[idx]);
    try {
      await sdk.getPOIMerkleProofs(fixture.meta.list_key_hex, queriedBcs);
    } catch {
    }
    expect(
      assertNoCommitmentsInPirRequests(sdk.lastWireRequests(), queriedBcs, {
        expectedQueryCount: 16,
      }),
    ).toHaveLength(1);
    expect(
      assertNoCommitmentsInPirRequests(server.requests, queriedBcs, {
        expectedQueryCount: 16,
      }),
    ).toHaveLength(1);
  });

  it("getMerkleProof (T3 commit-tree) client-PIR path leaks no BC bytes", async () => {
    const responses = Array.from(fixture.responsesByIdx.values());
    let cursor = 0;
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/(query|batch)$/.test(req.url ?? ""),
      (req, _body, res) => {
        if ((req.url ?? "").endsWith("/batch")) {
          const r = responses[cursor % responses.length];
          cursor += 1;
          writeBinary(res, encodeBatchResponseNodes(new Array<Uint8Array>(16).fill(r)));
          return true;
        }
        const r = responses[cursor % responses.length];
        cursor += 1;
        writeBinary(res, r);
        return true;
      },
    );

    const { ctxs } = makeMaps(fixture, ctx);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: ctxs,
    });

    // T3 keys on (treeNumber, leafIndex); assert the leaf index never serializes into the wire body.
    try {
      await sdk.getMerkleProof(0, 1234);
    } catch {
    }

    const inspected = inspectPirDataPosts(sdk.lastWireRequests(), {
      expectedQueryCount: 16,
    });
    expect(inspected).toHaveLength(1);
    const ascii = new TextEncoder().encode("1234");
    const raw = new Uint8Array([0xd2, 0x04, 0x00, 0x00]); // 1234 LE u32
    for (const { request: w } of inspected) {
      expect(
        containsByteSequence(w.body, raw),
        `body for ${w.url} contains raw u32 LE leafIndex`,
      ).toBe(false);
      expect(
        containsByteSequence(w.body, ascii),
        `body for ${w.url} contains ASCII leafIndex`,
      ).toBe(false);
    }
  });

  // D4 / DH-L0-6: the number of request envelopes must not reveal how many supplied
  // commitments are members of the list.
  it(
    "T1 outbound request count is independent of list membership (D4 / DH-L0-6)",
    async () => {
      const lk = fixture.meta.list_key_hex;
      const memberBcs = fixture.meta.target_indices
        .slice(0, 3)
        .map((idx) => fixture.meta.bcs_hex[idx]);
      const nonMemberBcs = ["77".repeat(32), "88".repeat(32), "99".repeat(32)];
      const served = fixture.meta.target_indices.slice(0, 3);
      let batchNumber = 0;
      server.route(
        (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
        (_req, body, res) => {
          const count = encodedBatchCount(body);
          const real =
            batchNumber === 0
              ? [fixture.responsesByIdx.get(served[0])!]
              : served.map((idx) => fixture.responsesByIdx.get(idx)!);
          batchNumber += 1;
          const responses = Array.from({ length: count }, (_unused, slot) =>
            slot < real.length ? real[slot] : real[0],
          );
          writeBinary(res, encodeBatchResponseNodes(responses));
          return true;
        },
      );

      const countQueries = (sdk: RavenPOINodeInterface): number =>
        sdk.lastWireRequests().filter((r) => r.url.includes("/v1/instance/")).length;

      const { ctxs, bcMaps } = makeMaps(fixture, ctx);
      const sdk0 = new RavenPOINodeInterface({
        endpoint: server.url,
        bearerToken: TOKEN,
        useClientPir: true,
        clientPirContexts: ctxs,
        bcToIdxMaps: bcMaps,
      });
      await sdk0.getPOIsPerList(
        [lk],
        nonMemberBcs.map((bc) => ({ blindedCommitment: bc, type: "Shield" as const })),
      );
      const countZeroMembers = countQueries(sdk0);
      expect(encodedBatchCount(sdk0.lastWireRequests()[0].body)).toBe(1);

      const sdk3 = new RavenPOINodeInterface({
        endpoint: server.url,
        bearerToken: TOKEN,
        useClientPir: true,
        clientPirContexts: ctxs,
        bcToIdxMaps: bcMaps,
      });
      await sdk3.getPOIsPerList(
        [lk],
        [...memberBcs, ...nonMemberBcs].map((bc) => ({
          blindedCommitment: bc,
          type: "Shield" as const,
        })),
      );
      const countThreeMembers = countQueries(sdk3);
      expect(encodedBatchCount(sdk3.lastWireRequests()[0].body)).toBe(4);

      expect(
        countThreeMembers,
        "same N, different M must produce the same request count or the count is an oracle",
      ).toBe(countZeroMembers);
    },
  );

  it("privacy assertion refuses empty and malformed request sets", () => {
    expect(() =>
      assertNoCommitmentsInPirRequests([], ["11".repeat(32)], {
        expectedQueryCount: 1,
      }),
    ).toThrow(/selected no POST query\/batch\/fanout requests/);

    const shortBatch = new Uint8Array(9);
    shortBatch.set([0, 6]);
    expect(() =>
      assertNoCommitmentsInPirRequests(
        [{ url: "/v1/instance/test/batch", method: "POST", body: shortBatch }],
        ["11".repeat(32)],
        { expectedQueryCount: 1 },
      ),
    ).toThrow(/shorter than 10-byte header/);

    expect(() =>
      assertNoCommitmentsInPirRequests(
        [{ url: "/v1/instance/test/batch", method: "POST", body: new Uint8Array(10) }],
        ["11".repeat(32)],
        { expectedQueryCount: 1 },
      ),
    ).toThrow(/schema prefix.*expected \[0, 6\]/);

    const zeroCountBatch = new Uint8Array(10);
    zeroCountBatch.set([0, 6]);
    expect(() =>
      assertNoCommitmentsInPirRequests(
        [{ url: "/v1/instance/test/batch", method: "POST", body: zeroCountBatch }],
        ["11".repeat(32)],
        { expectedQueryCount: 1 },
      ),
    ).toThrow(/invalid batch query count 0/);

    const undersizedBatch = new Uint8Array(10 + 31);
    undersizedBatch.set([0, 6]);
    new DataView(undersizedBatch.buffer).setBigUint64(2, 1n, true);
    expect(() =>
      assertNoCommitmentsInPirRequests(
        [{ url: "/v1/instance/test/batch", method: "POST", body: undersizedBatch }],
        ["11".repeat(32)],
        { expectedQueryCount: 1 },
      ),
    ).toThrow(/query payload is 31 bytes/);

    const unevenBatch = new Uint8Array(10 + 65);
    unevenBatch.set([0, 6]);
    new DataView(unevenBatch.buffer).setBigUint64(2, 2n, true);
    expect(() =>
      assertNoCommitmentsInPirRequests(
        [{ url: "/v1/instance/test/batch", method: "POST", body: unevenBatch }],
        ["11".repeat(32)],
        { expectedQueryCount: 2 },
      ),
    ).toThrow(/payload bytes do not divide/);
  });

  it("bc-to-idx-map publishing channel emits a GET with no body", async () => {
    server.route(
      (req) => req.url?.endsWith("/bc-to-idx-map") ?? false,
      (_req, _body, res) => {
        writeJson(res, {
          epoch: 1,
          listKey: fixture.meta.list_key_hex,
          entries: [],
        });
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
    });
    await sdk.fetchBcToIdxMap(fixture.meta.list_key_hex);
    const wires = sdk.lastWireRequests();
    expect(wires.length).toBe(1);
    expect(wires[0].method).toBe("GET");
    expect(wires[0].body.length).toBe(0);
  });

  it("status-header publishing channel emits a GET with no body", async () => {
    server.route(
      (req) => req.url?.endsWith("/status-header") ?? false,
      (_req, _body, res) => {
        writeJson(res, {
          epoch: 1,
          listKey: fixture.meta.list_key_hex,
          blockedBcs: [],
          pendingBcs: [],
        });
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
    });
    const result = (await sdk.fetchStatusHeader(fixture.meta.list_key_hex)) as unknown as {
      epoch: number;
      listKey: string;
      blockedBcs: string[];
      pendingBcs: string[];
    };
    // SDK must return upstream camelCase keys verbatim, never translate to snake_case.
    expect(result.epoch).toBe(1);
    expect(result.listKey).toBe(fixture.meta.list_key_hex);
    expect(Array.isArray(result.blockedBcs)).toBe(true);
    expect(Array.isArray(result.pendingBcs)).toBe(true);
    const wires = sdk.lastWireRequests();
    expect(wires.length).toBe(1);
    expect(wires[0].method).toBe("GET");
  });
});
