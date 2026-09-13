// First offline T1 end-to-end over REAL wasm-decrypted bytes: getPOIsPerList drives
// build_seeded_query -> padded batch POST -> extract_response -> decodeStatusRow
// against the Rust-emitted fixture, and the verdicts are the ones native Rust encoded.
// Every other offline T1 test stubs extract_response; until the fixture generator wrote
// production-shaped rows ([status, bc[0..31]]) this path could not run at all.

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { RavenPOINodeInterface, RavenError, type POIStatus } from "../src/index";
import type { ClientPirContext } from "../src/index";

import { loadFixture, makeClientPirContext, type LoadedFixture } from "./helpers/fixture";
import { encodeBatchResponseNodes, encodedBatchCount } from "./helpers/auth_path_stub";
import { startMockServer, writeBinary, type MockServer } from "./helpers/mock_server";

const TOKEN = "test-token-padded-long-enough-1234";

/** Verdict the fixture generator encoded for `idx`: status byte `idx % 4`. */
function expectedStatus(idx: number): POIStatus {
  return (["Valid", "ShieldBlocked", "ProofSubmitted", "Missing"] as const)[idx % 4];
}

describe("T1 end-to-end: real PIR decode from wire bytes to verdicts", () => {
  let fixture: LoadedFixture;
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

  function makeSdk(): RavenPOINodeInterface {
    const lk = fixture.meta.list_key_hex;
    return new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${lk}`, ctx]]),
      bcToIdxMaps: new Map([
        [lk, new Map(fixture.meta.target_indices.map((idx) => [fixture.meta.bcs_hex[idx], idx]))],
      ]),
    });
  }

  it("returns the verdicts native Rust encoded, decoded from real responses", async () => {
    // The batch's real prefix keeps supplied order; padding follows it.
    const sequence = [...fixture.meta.target_indices];
    server.reset();
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, body, res) => {
        const responses = Array.from({ length: encodedBatchCount(body) }, (_unused, slot) =>
          fixture.responsesByIdx.get(sequence[slot % sequence.length])!,
        );
        writeBinary(res, encodeBatchResponseNodes(responses));
        return true;
      },
    );

    const sdk = makeSdk();
    const queriedBcs = fixture.meta.target_indices.map((idx) => fixture.meta.bcs_hex[idx]);
    const got = await sdk.getPOIsPerList(
      [fixture.meta.list_key_hex],
      queriedBcs.map((bc) => ({ blindedCommitment: bc, type: "Shield" as const })),
    );

    for (const idx of fixture.meta.target_indices) {
      const bc = fixture.meta.bcs_hex[idx];
      expect(got[bc][fixture.meta.list_key_hex], `verdict for idx ${idx}`).toBe(
        expectedStatus(idx),
      );
    }
  });

  it("refuses a row-substitution: the wrong index's response fails the BC binding check", async () => {
    // A server answering row 3 to a query for row 0 yields a well-formed plaintext whose BC
    // tail names the WRONG commitment; decodeStatusRow must refuse it above the ciphertext.
    server.reset();
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, body, res) => {
        const responses = Array.from(
          { length: encodedBatchCount(body) },
          () => fixture.responsesByIdx.get(3)!,
        );
        writeBinary(res, encodeBatchResponseNodes(responses));
        return true;
      },
    );

    const sdk = makeSdk();
    const bc0 = fixture.meta.bcs_hex[0];
    await expect(
      sdk.getPOIsPerList(
        [fixture.meta.list_key_hex],
        [{ blindedCommitment: bc0, type: "Shield" as const }],
      ),
    ).rejects.toThrow(/BC tail differs/);
  });

  it("refuses an unknown schema envelope version instead of eating two payload bytes", async () => {
    // The discriminating test for the envelope guard (raven-poi-node-interface.ts
    // stripSchemaEnvelope): before this test, deleting the version branch left the
    // ENTIRE suite green (mutation M3, w4d-sdk). The message match is what discriminates —
    // with the guard deleted the misaligned body still dies later, but inside wasm with a
    // different error.
    server.reset();
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, requestBody, res) => {
        const response = fixture.responsesByIdx.get(0)!;
        const out = encodeBatchResponseNodes(
          Array.from({ length: encodedBatchCount(requestBody) }, () => response),
        );
        out[1] = 4;
        writeBinary(res, out);
        return true;
      },
    );

    const sdk = makeSdk();
    const bc0 = fixture.meta.bcs_hex[0];
    try {
      await sdk.getPOIsPerList(
        [fixture.meta.list_key_hex],
        [{ blindedCommitment: bc0, type: "Shield" as const }],
      );
      expect.fail("an unknown envelope version must not decode");
    } catch (e) {
      expect(RavenError.is(e, "DecodeError")).toBe(true);
      expect(String((e as Error).message)).toMatch(/unexpected schema envelope version 4/);
    }
  });

  it("refuses a previous-schema prefix before WASM extraction", async () => {
    server.reset();
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, requestBody, res) => {
        const response = fixture.responsesByIdx.get(0)!;
        const out = encodeBatchResponseNodes(
          Array.from({ length: encodedBatchCount(requestBody) }, () => response),
        );
        out[1] = 2;
        writeBinary(res, out);
        return true;
      },
    );

    const sdk = makeSdk();
    const bc0 = fixture.meta.bcs_hex[0];
    await expect(
      sdk.getPOIsPerList(
        [fixture.meta.list_key_hex],
        [{ blindedCommitment: bc0, type: "Shield" as const }],
      ),
    ).rejects.toThrow(/unexpected schema envelope version 2/);
  });

  it("refuses trailing bytes after a complete batch response", async () => {
    server.reset();
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, requestBody, res) => {
        const response = fixture.responsesByIdx.get(0)!;
        const batch = encodeBatchResponseNodes(
          Array.from({ length: encodedBatchCount(requestBody) }, () => response),
        );
        const overlong = new Uint8Array(batch.length + 1);
        overlong.set(batch);
        overlong[overlong.length - 1] = 0xa5;
        writeBinary(res, overlong);
        return true;
      },
    );

    const sdk = makeSdk();
    const bc0 = fixture.meta.bcs_hex[0];
    await expect(
      sdk.getPOIsPerList(
        [fixture.meta.list_key_hex],
        [{ blindedCommitment: bc0, type: "Shield" as const }],
      ),
    ).rejects.toThrow(/trailing bytes/);
  });

  it("refuses trailing bytes inside a length-delimited response element", async () => {
    server.reset();
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, requestBody, res) => {
        const response = fixture.responsesByIdx.get(0)!;
        const overlong = new Uint8Array(response.length + 1);
        overlong.set(response);
        overlong[overlong.length - 1] = 0xa5;
        writeBinary(
          res,
          encodeBatchResponseNodes(
            Array.from({ length: encodedBatchCount(requestBody) }, () => overlong),
          ),
        );
        return true;
      },
    );

    const sdk = makeSdk();
    const bc0 = fixture.meta.bcs_hex[0];
    await expect(
      sdk.getPOIsPerList(
        [fixture.meta.list_key_hex],
        [{ blindedCommitment: bc0, type: "Shield" as const }],
      ),
    ).rejects.toThrow(/bytes remaining/);
  });

  it("still fails closed when the envelope is stripped entirely (version-byte collision)", async () => {
    // A raw bincode body has no v3 prefix. Either the envelope guard or the strict wasm
    // decoder refuses it; neither layer may fabricate a record from misaligned bytes.
    server.reset();
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, _body, res) => {
        writeBinary(res, fixture.responsesByIdx.get(0)!);
        return true;
      },
    );

    const sdk = makeSdk();
    const bc0 = fixture.meta.bcs_hex[0];
    await expect(
      sdk.getPOIsPerList(
        [fixture.meta.list_key_hex],
        [{ blindedCommitment: bc0, type: "Shield" as const }],
      ),
    ).rejects.toThrow();
  });
});
