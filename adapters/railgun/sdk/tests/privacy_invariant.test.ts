// End-to-end privacy invariant against the real wasm + Rust-emitted fixture: when
// useClientPir is true, no plaintext BC bytes appear in any outbound body, and the
// encrypted query payload is non-trivial (>8 KB) to rule out a degenerate passthrough.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { RavenPOINodeInterface, containsByteSequence, hexToBytes } from "../src/index";
import type { ClientPirContext, RavenInspireWasm } from "../src/index";

import * as wasmPkg from "raven-inspire-client-wasm";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, "fixtures");

interface FixtureMeta {
  entry_size: number;
  list_key_hex: string;
  target_indices: number[];
  bcs_hex: string[];
}

function loadFixture(): {
  meta: FixtureMeta;
  paramsBundle: Uint8Array;
  crsBincode: Uint8Array;
  shardConfigBincode: Uint8Array;
  responsesByIdx: Map<number, Uint8Array>;
} {
  const meta = JSON.parse(readFileSync(join(FIXTURES_DIR, "fixture.json"), "utf-8")) as FixtureMeta;
  const paramsBundle = new Uint8Array(readFileSync(join(FIXTURES_DIR, "params_bundle.bin")));
  const crsBincode = new Uint8Array(readFileSync(join(FIXTURES_DIR, "crs.bin")));
  const shardConfigBincode = new Uint8Array(readFileSync(join(FIXTURES_DIR, "shard_config.bin")));
  const responsesByIdx = new Map<number, Uint8Array>();
  for (const idx of meta.target_indices) {
    responsesByIdx.set(
      idx,
      new Uint8Array(readFileSync(join(FIXTURES_DIR, `response_for_idx_${idx}.bin`))),
    );
  }
  return { meta, paramsBundle, crsBincode, shardConfigBincode, responsesByIdx };
}

interface MockServerHandle {
  server: Server;
  url: string;
  // Server-side view of every received body, cross-checked against the SDK-side capture.
  receivedBodies: { url: string; body: Uint8Array }[];
}

async function startMockServer(
  meta: FixtureMeta,
  responsesByIdx: Map<number, Uint8Array>,
): Promise<MockServerHandle> {
  const receivedBodies: { url: string; body: Uint8Array }[] = [];

  // SDK iterates BCs in supplied order, so the mock replies by request order.
  let responseCursor = 0;
  const responseSequence = meta.target_indices;

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      receivedBodies.push({ url: req.url ?? "", body: new Uint8Array(body) });

      const url = req.url ?? "";

      if (url.startsWith("/v1/poi/") && url.endsWith("/bc-to-idx-map")) {
        const entries = meta.target_indices.map((idx) => ({
          bc: meta.bcs_hex[idx],
          idx,
        }));
        const payload = JSON.stringify({
          epoch: 1,
          list_key: meta.list_key_hex,
          entries,
        });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(payload);
        return;
      }

      if (url.match(/^\/v1\/instance\/[^/]+\/query$/)) {
        const idx = responseSequence[responseCursor];
        responseCursor = (responseCursor + 1) % responseSequence.length;
        const respBytes = responsesByIdx.get(idx);
        if (!respBytes) {
          res.writeHead(500);
          res.end();
          return;
        }
        res.writeHead(200, {
          "content-type": "application/octet-stream",
          "x-raven-freshness": "lag_blocks=1 applied_height=100 epoch=1 confidence=0.99",
        });
        res.end(Buffer.from(respBytes));
        return;
      }

      res.writeHead(404);
      res.end();
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  if (typeof addr === "string" || addr === null) {
    throw new Error("mock server: unexpected address shape");
  }
  return { server, url: `http://127.0.0.1:${addr.port}`, receivedBodies };
}

async function stopMockServer(h: MockServerHandle): Promise<void> {
  await new Promise<void>((resolve, reject) =>
    h.server.close((err) => (err ? reject(err) : resolve())),
  );
}

function makeClientPirContext(
  fixture: ReturnType<typeof loadFixture>,
): ClientPirContext {
  const wasm = wasmPkg as unknown as RavenInspireWasm;
  const session = wasm.build_client_session(fixture.paramsBundle, fixture.crsBincode);
  return {
    wasm,
    session,
    crsBincode: fixture.crsBincode,
    shardConfigBincode: fixture.shardConfigBincode,
    entrySize: fixture.meta.entry_size,
  };
}

describe("RavenPOINodeInterface privacy invariant", () => {
  let fixture: ReturnType<typeof loadFixture>;
  let ctx: ClientPirContext;
  let mock: MockServerHandle;

  beforeAll(async () => {
    fixture = loadFixture();
    ctx = makeClientPirContext(fixture);
    mock = await startMockServer(fixture.meta, fixture.responsesByIdx);
  });

  afterAll(async () => {
    if (mock) await stopMockServer(mock);
    if (ctx) ctx.session.free();
  });

  it("getPOIsPerList (all-members fixture) does not leak BC bytes when useClientPir=true", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: mock.url,
      bearerToken: "test-token-must-be-at-least-16",
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${fixture.meta.list_key_hex}`, ctx]]),
      bcToIdxMaps: new Map([
        [
          fixture.meta.list_key_hex,
          new Map(fixture.meta.target_indices.map((idx) => [fixture.meta.bcs_hex[idx], idx])),
        ],
      ]),
    });

    const queriedBcs = fixture.meta.target_indices.map((idx) => fixture.meta.bcs_hex[idx]);
    // Each call throws on the RESPONSE, but not on the crypto: the session holds the
    // fixture's own key and decrypts it byte-exactly (wasm_extract_fixture_decode). It
    // throws because this mock omits the `[u16 BE schema]` envelope the server sends.
    // (The emitter's old `bc[1..32]` row-shape divergence from `PerListStatusEncoder` is
    // fixed; t1_end_to_end_real_decode covers the enveloped happy path.) The throw never
    // reaches what is asserted here, which is the OUTBOUND direction; one call per BC so
    // each query fires first.
    for (const bc of queriedBcs) {
      try {
        await sdk.getPOIsPerList(
          [fixture.meta.list_key_hex],
          [{ blindedCommitment: bc, type: "Shield" as const }],
        );
      } catch {
        }
    }

    const wireRequests = sdk.lastWireRequests();
    expect(wireRequests.length).toBeGreaterThanOrEqual(queriedBcs.length);

    // Encrypted query bodies are KB-scale; legacy plaintext bodies were ~80 B per BC.
    // SCOPE OF THE EQUALITY BELOW: the fixture supplies ONLY list-member BCs (every
    // queried BC is in the bc-to-idx map), so one query per BC is trivially true here.
    // It does NOT hold for mixed membership — a non-member produces ZERO queries, which
    // is the D4 request-count oracle pinned RED in privacy_all_paths.test.ts ("T1
    // outbound request count is independent of list membership"). When T1 padding lands,
    // THIS all-members equality may legitimately change (e.g. to a ladder step) — that
    // red is the fix arriving, not a regression.
    const queryRequests = wireRequests.filter((r) => r.url.includes("/v1/instance/"));
    expect(queryRequests.length).toBe(queriedBcs.length);
    for (const req of queryRequests) {
      expect(req.body.length).toBeGreaterThan(8 * 1024);
    }

    for (const bcHex of queriedBcs) {
      const bcBytes = hexToBytes(bcHex);
      const bcAsciiHex = new TextEncoder().encode(bcHex);
      const bcAsciiHex0x = new TextEncoder().encode(`0x${bcHex}`);
      for (const req of wireRequests) {
        expect(
          containsByteSequence(req.body, bcBytes),
          `wire body for ${req.url} contains raw BC bytes for ${bcHex}`,
        ).toBe(false);
        expect(
          containsByteSequence(req.body, bcAsciiHex),
          `wire body for ${req.url} contains hex-ASCII BC for ${bcHex}`,
        ).toBe(false);
        expect(
          containsByteSequence(req.body, bcAsciiHex0x),
          `wire body for ${req.url} contains 0x-prefixed hex-ASCII BC for ${bcHex}`,
        ).toBe(false);
      }
    }

    // Server-side cross-check guards against the SDK capturing the wrong body.
    for (const bcHex of queriedBcs) {
      const bcBytes = hexToBytes(bcHex);
      const bcAsciiHex = new TextEncoder().encode(bcHex);
      for (const recv of mock.receivedBodies) {
        if (recv.url.includes("/bc-to-idx-map")) continue;
        expect(
          containsByteSequence(recv.body, bcBytes),
          `server-side received body for ${recv.url} contains raw BC bytes for ${bcHex}`,
        ).toBe(false);
        expect(
          containsByteSequence(recv.body, bcAsciiHex),
          `server-side received body for ${recv.url} contains hex-ASCII BC for ${bcHex}`,
        ).toBe(false);
      }
    }
  });

  it("mixed membership: no BC bytes leak, but the request count still tracks membership (D4)", async () => {
    // The mixed-membership case the file's name promises. The byte-content invariant
    // holds for members and non-members alike; the COUNT line below is a
    // CHARACTERIZATION of the open D4 leak (queries == member count, because a
    // non-member short-circuits before any wire call) — cross-reference the RED pin in
    // privacy_all_paths.test.ts "T1 outbound request count is independent of list
    // membership (D4 / DH-L0-6)", which is the assertion a fix must satisfy. When that
    // pin flips, replace the equality below with the padded relation.
    const sdk = new RavenPOINodeInterface({
      endpoint: mock.url,
      bearerToken: "test-token-must-be-at-least-16",
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${fixture.meta.list_key_hex}`, ctx]]),
      bcToIdxMaps: new Map([
        [
          fixture.meta.list_key_hex,
          new Map(fixture.meta.target_indices.map((idx) => [fixture.meta.bcs_hex[idx], idx])),
        ],
      ]),
    });

    const memberBcs = fixture.meta.target_indices
      .slice(0, 2)
      .map((idx) => fixture.meta.bcs_hex[idx]);
    const nonMemberBcs = ["66".repeat(32), "77".repeat(32)];
    const allBcs = [...memberBcs, ...nonMemberBcs];
    for (const bc of allBcs) {
      try {
        await sdk.getPOIsPerList(
          [fixture.meta.list_key_hex],
          [{ blindedCommitment: bc, type: "Shield" as const }],
        );
      } catch {
      }
    }

    const wireRequests = sdk.lastWireRequests();
    const queryRequests = wireRequests.filter((r) => r.url.includes("/v1/instance/"));
    // D4 characterization: 2 members + 2 non-members -> exactly 2 queries.
    expect(queryRequests.length).toBe(memberBcs.length);

    for (const bcHex of allBcs) {
      const bcBytes = hexToBytes(bcHex);
      const bcAsciiHex = new TextEncoder().encode(bcHex);
      for (const req of wireRequests) {
        expect(
          containsByteSequence(req.body, bcBytes),
          `wire body for ${req.url} contains raw BC bytes for ${bcHex}`,
        ).toBe(false);
        expect(
          containsByteSequence(req.body, bcAsciiHex),
          `wire body for ${req.url} contains hex-ASCII BC for ${bcHex}`,
        ).toBe(false);
      }
    }
  });

  it("legacy plaintext mode (useClientPir=false) DOES leak BC bytes (regression guard)", async () => {
    // Catches a future refactor that silently flips the default to plaintext while leaving useClientPir wired-but-ignored.
    const leakySdk = new RavenPOINodeInterface({
      endpoint: mock.url,
      bearerToken: "test-token-must-be-at-least-16",
      useClientPir: false,
    });

    const queriedBcs = fixture.meta.target_indices.map((idx) => fixture.meta.bcs_hex[idx]);
    try {
      await leakySdk.getPOIsPerList(
        [fixture.meta.list_key_hex],
        queriedBcs.map((bc) => ({ blindedCommitment: bc, type: "Shield" as const })),
      );
    } catch {
    }

    const wireRequests = leakySdk.lastWireRequests();
    expect(wireRequests.length).toBeGreaterThan(0);
    const lastBody = wireRequests[wireRequests.length - 1].body;
    let leaked = false;
    for (const bcHex of queriedBcs) {
      const bcAsciiHex = new TextEncoder().encode(bcHex);
      if (containsByteSequence(lastBody, bcAsciiHex)) {
        leaked = true;
        break;
      }
    }
    expect(leaked, "legacy path must leak BC bytes (regression guard against silent default flip)").toBe(true);
  });
});
