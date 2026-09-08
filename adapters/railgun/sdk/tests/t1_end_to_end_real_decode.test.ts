// First offline T1 end-to-end over REAL wasm-decrypted bytes: getPOIsPerList drives
// build_seeded_query -> POST -> stripSchemaEnvelope -> extract_response -> decodeStatusRow
// against the Rust-emitted fixture, and the verdicts are the ones native Rust encoded.
// Every other offline T1 test stubs extract_response; until the fixture generator wrote
// production-shaped rows ([status, bc[0..31]]) this path could not run at all.

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { RavenPOINodeInterface, RavenError, type POIStatus } from "../src/index";
import type { ClientPirContext } from "../src/index";

import { loadFixture, makeClientPirContext, type LoadedFixture } from "./helpers/fixture";
import { startMockServer, writeBinary, type MockServer } from "./helpers/mock_server";

const TOKEN = "test-token-padded-long-enough-1234";

/** The `[u16 BE version = 1][body]` envelope the production server wraps responses in. */
function withSchemaEnvelope(body: Uint8Array): Uint8Array {
  const out = new Uint8Array(2 + body.length);
  out[0] = 0;
  out[1] = 1;
  out.set(body, 2);
  return out;
}

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
    // The SDK queries BCs in supplied order; serve the recorded response for each in turn.
    const sequence = [...fixture.meta.target_indices];
    let cursor = 0;
    server.reset();
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/query$/.test(req.url ?? ""),
      (_req, _body, res) => {
        const idx = sequence[cursor % sequence.length];
        cursor += 1;
        writeBinary(res, withSchemaEnvelope(fixture.responsesByIdx.get(idx)!));
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
      (req) => /^\/v1\/instance\/[^/]+\/query$/.test(req.url ?? ""),
      (_req, _body, res) => {
        writeBinary(res, withSchemaEnvelope(fixture.responsesByIdx.get(3)!));
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
    // stripSchemaEnvelope): before this test, deleting the `envelope !== 1` branch left the
    // ENTIRE suite green (mutation M3, w4d-sdk). The message match is what discriminates —
    // with the guard deleted the misaligned body still dies later, but inside wasm with a
    // different error.
    server.reset();
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/query$/.test(req.url ?? ""),
      (_req, _body, res) => {
        const body = fixture.responsesByIdx.get(0)!;
        const out = new Uint8Array(2 + body.length);
        out[0] = 0;
        out[1] = 2; // a future/wrong version the client does not speak
        out.set(body, 2);
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
      expect(String((e as Error).message)).toMatch(/unexpected schema envelope version 2/);
    }
  });

  it("still fails closed when the envelope is stripped entirely (version-byte collision)", async () => {
    // CHARACTERIZATION: this fixture's raw bincode response begins `00 01` (a leading
    // Vec of length ring_dim = 256, LE u64), which is byte-identical to the BE u16
    // envelope version 1 — so stripSchemaEnvelope cannot tell a stripped d=256 response
    // from a wrapped one, and the misaligned payload is caught one layer down by the wasm
    // decode instead. At production geometry (d=2048, prefix `00 08`) the guard itself
    // fires. Either way nothing decodes; this pins that no layer fabricates a record.
    server.reset();
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/query$/.test(req.url ?? ""),
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
