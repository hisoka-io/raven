/**
 * Privacy invariant: when `useClientPir: true`, no plaintext blinded
 * commitment bytes EVER appear in any outbound HTTP body.
 *
 * Test harness:
 *
 * 1. Loads the precomputed fixture (CRS, ShardConfig, params bundle,
 *    test BCs, precomputed PIR responses) emitted by the Rust
 *    `emit_test_fixture` example.
 * 2. Constructs a real `RavenInspireClientSession` from the wasm
 *    artefact (the same `pkg-node` build the SDK ships).
 * 3. Spins up an in-process `node:http` mock server that:
 *    - Serves `/v1/poi/:list/bc-to-idx-map` from the fixture.
 *    - Serves `/v1/instance/:label/query` by mapping the request
 *      body's last 4 bytes (a u32 LE row index marker) to one of the
 *      precomputed responses. (We don't decrypt the request; we map
 *      the request to a known response by index. The privacy
 *      assertion is purely about the OUTGOING body shape, which the
 *      mock has full visibility into.)
 * 4. Drives `RavenPOINodeInterface.getPOIsPerList(...)` against the
 *    mock with `useClientPir: true`.
 * 5. Asserts the captured wire-request ring contains NO body that
 *    contains any of the queried BC byte sequences (substring search
 *    on hex AND raw bytes).
 * 6. Asserts the encrypted PIR query body to `/v1/instance/:label/query`
 *    is non-trivial in size (> 8 KB; rules out a degenerate pass-
 *    through that secretly sends a tiny BC-bearing payload).
 *
 * Optional cross-check: legacy mode (`useClientPir: false`) DOES leak
 * BC bytes — the test confirms this so a regression toward the leaky
 * default is caught.
 */

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
  // Records every body the mock server saw (so the test can also
  // inspect from the server side, not only from the SDK side).
  receivedBodies: { url: string; body: Uint8Array }[];
}

async function startMockServer(
  meta: FixtureMeta,
  responsesByIdx: Map<number, Uint8Array>,
): Promise<MockServerHandle> {
  const receivedBodies: { url: string; body: Uint8Array }[] = [];

  // Sequence of indices the server will reply to, one per query.
  // The SDK iterates BCs in the order we supply, so the mock can
  // return the matching precomputed response by request order.
  let responseCursor = 0;
  const responseSequence = meta.target_indices;

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      receivedBodies.push({ url: req.url ?? "", body: new Uint8Array(body) });

      const url = req.url ?? "";

      // bc-to-idx-map publishing channel
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

      // Encrypted PIR query
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

  it("getPOIsPerList does not leak BC bytes when useClientPir=true", async () => {
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
    // The fixture's precomputed PIR responses were generated by a
    // ClientSession with different sampler entropy than the one this
    // wasm session built. extract_response will therefore throw on
    // the response decryption step. That's expected and irrelevant
    // for the privacy invariant - we only care about the OUTGOING
    // request bodies, which we capture into `lastWireRequests`
    // BEFORE the extract step. End-to-end correctness is covered by
    // the Rust parity tests (parity_native_vs_wasm.rs).
    //
    // Issue one getPOIsPerList per BC so each BC's outbound query
    // fires before the H3 strict-error path aborts the rest of
    // the batch.
    for (const bc of queriedBcs) {
      try {
        await sdk.getPOIsPerList(
          [fixture.meta.list_key_hex],
          [{ blindedCommitment: bc, type: "Shield" as const }],
        );
      } catch {
        // Decryption failure under fixture-mismatched packing keys
        // is expected; we do not assert on it. The assertions below
        // exercise the wire-body invariant, which is independent.
      }
    }

    const wireRequests = sdk.lastWireRequests();
    // Should have at least: 1 query per BC. (No bc-to-idx-map fetch
    // because we preloaded it.)
    expect(wireRequests.length).toBeGreaterThanOrEqual(queriedBcs.length);

    // The encrypted-PIR query bodies are non-trivial in size. Pre-
    // PIR (legacy plaintext-BC) bodies were ~80 bytes per BC; the
    // encrypted query payload is well into the KB range.
    const queryRequests = wireRequests.filter((r) => r.url.includes("/v1/instance/"));
    expect(queryRequests.length).toBe(queriedBcs.length);
    for (const req of queryRequests) {
      expect(req.body.length).toBeGreaterThan(8 * 1024);
    }

    // CORE INVARIANT: no body contains any queried BC's bytes (raw
    // OR hex-encoded as ASCII).
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

    // Cross-check the SERVER side too (defense against a SDK bug
    // that captures the wrong body): inspect what the mock server
    // actually received.
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

  it("legacy plaintext mode (useClientPir=false) DOES leak BC bytes (regression guard)", async () => {
    // We don't actually want this regression to hold long-term, but
    // confirming it now means we'd notice if a future refactor
    // silently flipped the default to plaintext while leaving the
    // useClientPir flag wired-but-ignored.
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
      // The mock server returns 404 for the legacy POST route. We
      // don't care about the response; we only care that the
      // OUTGOING body contained the BCs (proving the legacy path
      // is the one that leaks).
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
