// No call path leaks plaintext BC bytes when useClientPir is true. Asserts only the
// OUTGOING direction; response decode is allowed to fail (tolerated via try/catch).

import { afterEach, beforeAll, describe, expect, it, afterAll } from "vitest";

import { RavenPOINodeInterface, containsByteSequence, hexToBytes } from "../src/index";
import type { ClientPirContext } from "../src/index";

import { loadFixture, makeClientPirContext } from "./helpers/fixture";
import { startMockServer, writeBinary, writeJson, type MockServer } from "./helpers/mock_server";

const TOKEN = "test-token-padded-long-enough-1234";

function assertNoBcLeaked(
  bodies: { url: string; body: Uint8Array }[],
  bcsHex: string[],
): void {
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
          // Synthetic batch reply: `[u16 schema][u64 LE count][per-elem u64 LE len + bytes]`, 16 slots per auth path.
          const elemCount = 16;
          const r = responses[cursor % responses.length];
          cursor += 1;
          const total = 2 + 8 + elemCount * (8 + r.length);
          const out = new Uint8Array(total);
          out[0] = 0;
          out[1] = 1;
          const dv = new DataView(out.buffer);
          dv.setUint32(2, elemCount, true);
          dv.setUint32(6, 0, true);
          let off = 10;
          for (let i = 0; i < elemCount; i += 1) {
            dv.setUint32(off, r.length, true);
            dv.setUint32(off + 4, 0, true);
            off += 8;
            out.set(r, off);
            off += r.length;
          }
          writeBinary(res, out);
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
      // Tolerated: only the captured wire requests matter here.
    }
    assertNoBcLeaked(sdk.lastWireRequests(), queriedBcs);
    assertNoBcLeaked(
      server.requests.map((r) => ({ url: r.url, body: r.body })),
      queriedBcs,
    );
  });

  it("getPOIMerkleProofs client-PIR path leaks no BC bytes", async () => {
    const responses = Array.from(fixture.responsesByIdx.values());
    let cursor = 0;
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/(query|batch)$/.test(req.url ?? ""),
      (req, _body, res) => {
        if ((req.url ?? "").endsWith("/batch")) {
          // Synthetic batch reply: `[u16 schema][u64 LE count][per-elem u64 LE len + bytes]`, 16 slots per auth path.
          const elemCount = 16;
          const r = responses[cursor % responses.length];
          cursor += 1;
          const total = 2 + 8 + elemCount * (8 + r.length);
          const out = new Uint8Array(total);
          out[0] = 0;
          out[1] = 1;
          const dv = new DataView(out.buffer);
          dv.setUint32(2, elemCount, true);
          dv.setUint32(6, 0, true);
          let off = 10;
          for (let i = 0; i < elemCount; i += 1) {
            dv.setUint32(off, r.length, true);
            dv.setUint32(off + 4, 0, true);
            off += 8;
            out.set(r, off);
            off += r.length;
          }
          writeBinary(res, out);
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
      // Tolerated: only the wire-out direction is asserted.
    }
    assertNoBcLeaked(sdk.lastWireRequests(), queriedBcs);
    assertNoBcLeaked(
      server.requests.map((r) => ({ url: r.url, body: r.body })),
      queriedBcs,
    );
  });

  it("getMerkleProof (T3 commit-tree) client-PIR path leaks no BC bytes", async () => {
    const responses = Array.from(fixture.responsesByIdx.values());
    let cursor = 0;
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/(query|batch)$/.test(req.url ?? ""),
      (req, _body, res) => {
        if ((req.url ?? "").endsWith("/batch")) {
          // Synthetic batch reply: `[u16 schema][u64 LE count][per-elem u64 LE len + bytes]`, 16 slots per auth path.
          const elemCount = 16;
          const r = responses[cursor % responses.length];
          cursor += 1;
          const total = 2 + 8 + elemCount * (8 + r.length);
          const out = new Uint8Array(total);
          out[0] = 0;
          out[1] = 1;
          const dv = new DataView(out.buffer);
          dv.setUint32(2, elemCount, true);
          dv.setUint32(6, 0, true);
          let off = 10;
          for (let i = 0; i < elemCount; i += 1) {
            dv.setUint32(off, r.length, true);
            dv.setUint32(off + 4, 0, true);
            off += 8;
            out.set(r, off);
            off += r.length;
          }
          writeBinary(res, out);
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
      // Tolerated: only the wire-out direction is asserted.
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
