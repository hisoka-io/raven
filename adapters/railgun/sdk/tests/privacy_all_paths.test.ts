// No call path leaks plaintext BC bytes when useClientPir is true. Asserts only the
// OUTGOING direction; response decode is allowed to fail (tolerated via try/catch).

import { afterEach, beforeAll, describe, expect, it, afterAll } from "vitest";

import { RavenPOINodeInterface, containsByteSequence, hexToBytes } from "../src/index";
import type { ClientPirContext } from "../src/index";

import { loadFixture, makeClientPirContext } from "./helpers/fixture";
import { encodeBatchResponseNodes } from "./helpers/auth_path_stub";
import { startMockServer, writeBinary, writeJson, type MockServer } from "./helpers/mock_server";

const TOKEN = "test-token-padded-long-enough-1234";

/** A leak check over zero bodies proves nothing, so the caller must say what it expects. */
function assertNoBcLeaked(
  bodies: { url: string; body: Uint8Array }[],
  bcsHex: string[],
  minQueryBodies: number,
): void {
  const queries = bodies.filter((b) => b.url.includes("/v1/instance/"));
  expect(
    queries.length,
    "no PIR request left the SDK, so the leak check below inspected nothing",
  ).toBeGreaterThanOrEqual(minQueryBodies);
  for (const bcHex of bcsHex) {
    const bcBytes = hexToBytes(bcHex);
    const bcAscii = new TextEncoder().encode(bcHex);
    const bcAscii0x = new TextEncoder().encode(`0x${bcHex}`);
    for (const b of bodies) {
      // bc-to-idx-map and status-header are public ordering oracles that publish BCs in plaintext by design.
      if (b.url.includes("bc-to-idx-map")) continue;
      if (b.url.includes("status-header")) continue;
      expect(
        containsByteSequence(b.body, bcBytes),
        `body for ${b.url} contains raw BC bytes ${bcHex}`,
      ).toBe(false);
      expect(
        containsByteSequence(b.body, bcAscii),
        `body for ${b.url} contains hex-ASCII BC ${bcHex}`,
      ).toBe(false);
      expect(
        containsByteSequence(b.body, bcAscii0x),
        `body for ${b.url} contains 0x-prefixed BC ${bcHex}`,
      ).toBe(false);
    }
  }
}

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
    assertNoBcLeaked(sdk.lastWireRequests(), queriedBcs, 1);
    assertNoBcLeaked(
      server.requests.map((r) => ({ url: r.url, body: r.body })),
      queriedBcs,
      1,
    );
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
    assertNoBcLeaked(sdk.lastWireRequests(), queriedBcs, 1);
    assertNoBcLeaked(
      server.requests.map((r) => ({ url: r.url, body: r.body })),
      queriedBcs,
      1,
    );
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

    const wires = sdk.lastWireRequests();
    expect(wires.length).toBeGreaterThan(0);
    const ascii = new TextEncoder().encode("1234");
    const raw = new Uint8Array([0xd2, 0x04, 0x00, 0x00]); // 1234 LE u32
    for (const w of wires) {
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

  // D4 / DH-L0-6: a non-member short-circuits to `Missing` with `continue` BEFORE any
  // query fires (src/raven-poi-node-interface.ts getPOIsPerListClientPir), so the
  // observable count of /v1/instance/ POSTs tracks list membership 1:1 — a
  // list-membership oracle for anyone who can count requests. drawPaddedSlots exists
  // and is applied to exactly ONE call site (assembleAuthPath); the T1 loop has no
  // padding. RED-by-design: un-mark when getPOIsPerListClientPir applies the batch
  // ladder (or equivalent padding) to the T1 path. Probe capture (as a plain `it`):
  // "expected 3 to be +0 // Object.is equality" at the count assertion below.
  it.fails(
    "T1 outbound request count is independent of list membership (D4 / DH-L0-6)",
    async () => {
      const lk = fixture.meta.list_key_hex;
      const memberBcs = fixture.meta.target_indices
        .slice(0, 3)
        .map((idx) => fixture.meta.bcs_hex[idx]);
      const nonMemberBcs = ["77".repeat(32), "88".repeat(32), "99".repeat(32)];
      const served = fixture.meta.target_indices.slice(0, 3);
      let cursor = 0;
      server.route(
        (req) => /^\/v1\/instance\/[^/]+\/query$/.test(req.url ?? ""),
        (_req, _body, res) => {
          const idx = served[cursor % served.length];
          cursor += 1;
          const body = fixture.responsesByIdx.get(idx)!;
          const out = new Uint8Array(2 + body.length);
          out[1] = 1;
          out.set(body, 2);
          writeBinary(res, out);
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

      expect(
        countThreeMembers,
        "same N, different M must produce the same request count or the count is an oracle",
      ).toBe(countZeroMembers);
    },
  );

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
