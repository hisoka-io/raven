// End-to-end privacy invariant against the real wasm + Rust-emitted fixture: when
// useClientPir is true, no plaintext BC bytes appear in any outbound body, and the
// encrypted query payload is non-trivial (>8 KB) to rule out a degenerate passthrough.

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { RavenPOINodeInterface, containsByteSequence } from "../src/index";
import type { ClientPirContext, RavenInspireWasm } from "../src/index";

import * as wasmPkg from "raven-inspire-client-wasm";
import { encodeBatchResponseNodes, encodedBatchCount } from "./helpers/auth_path_stub";
import {
  assertNoCommitmentsInPirRequests,
  injectCommitment,
} from "./helpers/private_wire";

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
  receivedBodies: { url: string; method: string; body: Uint8Array }[];
}

async function startMockServer(
  meta: FixtureMeta,
  responsesByIdx: Map<number, Uint8Array>,
): Promise<MockServerHandle> {
  const receivedBodies: { url: string; method: string; body: Uint8Array }[] = [];

  const responseSequence = meta.target_indices;

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      receivedBodies.push({
        url: req.url ?? "",
        method: req.method ?? "GET",
        body: new Uint8Array(body),
      });

      const url = req.url ?? "";

      if (url.endsWith("/session")) {
        res.writeHead(200, {
          "content-type": "application/json",
          "x-raven-session": "1",
        });
        res.end(JSON.stringify({ handle: 1, expires_at_unix_secs: 1 }));
        return;
      }

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

      if (url.match(/^\/v1\/instance\/[^/]+\/batch$/)) {
        const responses = Array.from({ length: encodedBatchCount(body) }, (_unused, slot) =>
          responsesByIdx.get(responseSequence[slot % responseSequence.length])!,
        );
        res.writeHead(200, {
          "content-type": "application/octet-stream",
          "x-raven-freshness": "lag_blocks=1 applied_height=100 epoch=1 confidence=0.99",
        });
        res.end(Buffer.from(encodeBatchResponseNodes(responses)));
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

  beforeEach(() => {
    mock.receivedBodies.length = 0;
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
    await sdk.getPOIsPerList(
      [fixture.meta.list_key_hex],
      queriedBcs.map((blindedCommitment) => ({
        blindedCommitment,
        type: "Shield" as const,
      })),
    );

    const wireRequests = sdk.lastWireRequests();
    expect(wireRequests.length).toBe(1);

    // Both private bodies are KB-scale; legacy plaintext bodies were ~80 B per BC.
    const inspected = assertNoCommitmentsInPirRequests(wireRequests, queriedBcs, {
      expectedQueryCount: 8,
    });
    expect(inspected).toHaveLength(1);
    expect(inspected[0].request.body.length).toBeGreaterThan(8 * 1024);
    expect(wireRequests.some((request) => request.url.endsWith("/session"))).toBe(false);
    const registration = mock.receivedBodies.find((request) => request.url.endsWith("/session"));
    expect(registration!.body.length).toBeGreaterThan(1024);
    expect(registration!.body.subarray(0, 2)).toEqual(new Uint8Array([0, 3]));

    // Server-side cross-check guards against the SDK capturing the wrong body.
    expect(
      assertNoCommitmentsInPirRequests(mock.receivedBodies, queriedBcs, {
        expectedQueryCount: 8,
      }),
    ).toHaveLength(1);

    const prefixedLeak = injectCommitment(inspected[0], queriedBcs[0], "prefixed-ascii");
    expect(() =>
      assertNoCommitmentsInPirRequests([prefixedLeak], queriedBcs, {
        expectedQueryCount: 8,
      }),
    ).toThrow(/contains 0x-prefixed ASCII blinded commitment/);
  });

  it("mixed membership: no BC bytes leak and one padded request hides member count", async () => {
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
    await sdk.getPOIsPerList(
      [fixture.meta.list_key_hex],
      allBcs.map((blindedCommitment) => ({
        blindedCommitment,
        type: "Shield" as const,
      })),
    );

    const wireRequests = sdk.lastWireRequests();
    expect(
      assertNoCommitmentsInPirRequests(wireRequests, allBcs, {
        expectedQueryCount: 2,
      }),
    ).toHaveLength(1);
    expect(
      assertNoCommitmentsInPirRequests(mock.receivedBodies, allBcs, {
        expectedQueryCount: 2,
      }),
    ).toHaveLength(1);
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
