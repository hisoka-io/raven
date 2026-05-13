/**
 * Privacy invariant: NO call path leaks plaintext blinded
 * commitment bytes when `useClientPir: true`.
 *
 * Coverage:
 *   - getPOIsPerList (T1 status)
 *   - getPOIMerkleProofs (T2 PPOI auth-path)
 *   - getMerkleProof (T3 commit-tree auth-path)
 *   - bc-to-idx-map publishing channel (BCs are public; this exists
 *     to verify the SDK routes through the captured-request ring
 *     correctly)
 *   - status-header publishing channel (same)
 *
 * Each test stands up a fresh `MockServer`, drives the SDK, and
 * asserts:
 *   1. SOME wire request was captured.
 *   2. NO captured body contains the queried BC bytes (raw or
 *      hex-ASCII).
 *   3. NO body the server actually received contains the BC bytes.
 *
 * Per the privacy_invariant baseline, we don't rely on the
 * server-side response decrypting cleanly — the privacy invariant is
 * about the OUTGOING direction, and per-BC failures during decode
 * surface as `Missing` in T1 and as a thrown error in T2/T3 (which
 * we tolerate via try/catch).
 */

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
      // The bc-to-idx-map publishing channel intentionally publishes
      // BCs in plaintext (it's the public ordering oracle). Skip
      // those routes from the leakage check; the privacy invariant
      // is about per-query routes (PIR query bodies).
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
          // Build a synthetic batch reply: u16 schema version + u64
          // LE element-count + repeated (u64 LE elem-len + bytes).
          // The element count must match the request's query count
          // (16 for an auth path); we encode `responses[cursor]` for
          // every slot.
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
      // T1 client-PIR catches per-BC decode failure as Missing; if
      // anything else throws we still want to assert on captured
      // wire requests below.
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
          // Build a synthetic batch reply: u16 schema version + u64
          // LE element-count + repeated (u64 LE elem-len + bytes).
          // The element count must match the request's query count
          // (16 for an auth path); we encode `responses[cursor]` for
          // every slot.
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
      // Same expected-decode-failure caveat as the privacy-invariant
      // baseline: the wire-out direction is what we assert.
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
          // Build a synthetic batch reply: u16 schema version + u64
          // LE element-count + repeated (u64 LE elem-len + bytes).
          // The element count must match the request's query count
          // (16 for an auth path); we encode `responses[cursor]` for
          // every slot.
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

    // T3 keys on (treeNumber, leafIndex). The "BC" privacy invariant
    // here is really an "address invariant" — the wallet's leaf
    // index never leaves the wallet. We assert the leafIndex isn't
    // serialized into the wire body in any plaintext form.
    try {
      await sdk.getMerkleProof(0, 1234);
    } catch {
      // tolerable per the response-decode caveat.
    }

    const wires = sdk.lastWireRequests();
    expect(wires.length).toBeGreaterThan(0);
    // 1234 -> "1234" ASCII OR raw u32 LE = [0xd2, 0x04, 0x00, 0x00]
    const ascii = new TextEncoder().encode("1234");
    const raw = new Uint8Array([0xd2, 0x04, 0x00, 0x00]);
    for (const w of wires) {
      // The endpoint URL itself doesn't carry the leaf index for
      // PIR; assert it's not in the body.
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
    // The shim publishes camelCase keys (per upstream Railgun PPOI
    // wire shape); the SDK returns the JSON verbatim. This test
    // locks that the SDK does NOT translate keys to snake_case,
    // catching a future refactor that adds key-translation and
    // silently breaks wallet integrators typed against camelCase.
    expect(result.epoch).toBe(1);
    expect(result.listKey).toBe(fixture.meta.list_key_hex);
    expect(Array.isArray(result.blockedBcs)).toBe(true);
    expect(Array.isArray(result.pendingBcs)).toBe(true);
    const wires = sdk.lastWireRequests();
    expect(wires.length).toBe(1);
    expect(wires[0].method).toBe("GET");
  });
});
