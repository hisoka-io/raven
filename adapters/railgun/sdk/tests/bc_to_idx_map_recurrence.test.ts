// A blinded commitment may appear more than once on one list: upstream dropped the unique
// `(listKey, blindedCommitment)` index and recreated it non-unique, and the adapter's per-list
// index is a SET of occurrences. The server answers a lookup with the LOWEST occurrence -- the
// one a later append cannot move and a tail reorg cannot take away.
//
// The JSON index channel publishes one entry per leaf, so a recurring commitment arrives twice
// with different `idx`. Feeding those entries straight to `new Map()` is last-wins, which picks
// the HIGHEST occurrence, and the SDK then addresses a different leaf from the one the server
// resolves -- a different PPOI block, a different instance, a different pinned root. Both rows
// carry the same commitment, so the row-binding guard cannot see the difference.
//
// The binary prefix channel is the same index published differently, and it has always returned
// every candidate. It is the oracle here: whatever the JSON channel is turned into must resolve
// to the lowest of the candidates it reports.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  BC_INDEX_PREFIX_BYTES,
  LEAVES_PER_PPOI_BLOCK,
  RavenPOINodeInterface,
  bcToIdxMapFrom,
  fetchBcPrefixIndex,
  indexCandidatesFor,
} from "../src/index";
import { hexToBytes } from "../src/index";
import { encodeBatchResponseNodes, encodedBatchCount } from "./helpers/auth_path_stub";
import { makeRegisterSpy, stubRemoteSessionExports } from "./helpers/register_spy";
import type { ClientPirContext, RavenInspireWasm } from "../src/index";
import { startMockServer, writeBinary, writeJson, type MockServer } from "./helpers/mock_server";
import { stubQueryBundle } from "./helpers/private_wire";
import { shardConfigBincode } from "./helpers/shard_config";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "ab".repeat(32);
const EPOCH = 7;

function bcHex(seed: number): string {
  return seed.toString(16).padStart(8, "0").repeat(8);
}

const RECURRING = bcHex(0x11111111);
const SINGLE = bcHex(0x22222222);

interface IndexRow {
  readonly bc: string;
  readonly idx: number;
}

/** `GET /v1/poi/:list/bc-to-idx-map`, in the shape `poi_shim.rs` serializes. */
function mountJsonChannel(server: MockServer, rows: readonly IndexRow[]): void {
  server.route(
    (req) => req.url === `/v1/poi/${LIST_KEY_HEX}/bc-to-idx-map`,
    (_req, _body, res) => {
      writeJson(res, { epoch: EPOCH, listKey: LIST_KEY_HEX, entries: rows });
      return true;
    },
  );
}

/** The same rows on the binary channel: six bytes per row, position IS the global index. */
function mountPrefixChannel(server: MockServer, rows: readonly IndexRow[]): void {
  const total = rows.length;
  const prefixes = new Uint8Array(total * BC_INDEX_PREFIX_BYTES);
  rows.forEach(({ bc }, row) => {
    for (let byte = 0; byte < BC_INDEX_PREFIX_BYTES; byte += 1) {
      prefixes[row * BC_INDEX_PREFIX_BYTES + byte] = Number.parseInt(
        bc.slice(byte * 2, byte * 2 + 2),
        16,
      );
    }
  });
  server.route(
    (req) => (req.url ?? "").startsWith(`/v1/poi/${LIST_KEY_HEX}/bc-prefixes`),
    (_req, _body, res) => {
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "x-raven-index-base": "0",
        "x-raven-index-next": String(total),
        "x-raven-index-total": String(total),
        "x-raven-index-epoch": String(EPOCH),
      });
      res.end(Buffer.from(prefixes));
      return true;
    },
  );
}

function stubCtx(): ClientPirContext {
  const wasm: RavenInspireWasm = {
    ...stubRemoteSessionExports(),
    build_client_session: () => ({ free: () => undefined }),
    build_seeded_query: () => stubQueryBundle(),
    extract_response: (_s, _c, _st, response, _e) => new Uint8Array(response),
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

describe("a recurring commitment resolves the way the server resolves it", () => {
  let server: MockServer;
  beforeAll(async () => {
    server = await startMockServer();
  });
  afterAll(async () => {
    await server.close();
  });
  afterEach(() => {
    server.reset();
  });

  it("agrees with the binary channel's lowest candidate", async () => {
    const rows: IndexRow[] = [
      { bc: RECURRING, idx: 0 },
      { bc: SINGLE, idx: 1 },
      { bc: RECURRING, idx: 2 },
    ];
    mountJsonChannel(server, rows);
    mountPrefixChannel(server, rows);

    const sdk = new RavenPOINodeInterface({ endpoint: server.url, bearerToken: TOKEN });
    const { entries } = await sdk.fetchBcToIdxMap(LIST_KEY_HEX);
    const prefixIndex = await fetchBcPrefixIndex(fetch, server.url, LIST_KEY_HEX, {});

    const candidates = indexCandidatesFor(prefixIndex, RECURRING);
    expect(candidates.length).toBeGreaterThan(1);

    const map = bcToIdxMapFrom(entries);
    expect(map.get(RECURRING)).toBe(Math.min(...candidates));
    expect(map.get(SINGLE)).toBe(indexCandidatesFor(prefixIndex, SINGLE)[0]);
  });

  // The internal lookup is an exact-string `Map.get` on stripped lower-case hex. A row in any
  // other spelling would miss, and a miss is the "Missing" verdict -- a statement about someone's
  // note, made because of a string format. Asserted end to end rather than on the map, because
  // the map agreeing with itself proves nothing.
  it("resolves rows served in another hex spelling instead of reading them as absent", async () => {
    const rows: IndexRow[] = [{ bc: `0x${RECURRING.toUpperCase()}`, idx: 0 }];
    mountJsonChannel(server, rows);
    mountPrefixChannel(server, [{ bc: RECURRING, idx: 0 }]);
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, body, res) => {
        const row = new Uint8Array(32);
        row[0] = 1;
        row.set(hexToBytes(RECURRING).subarray(0, 31), 1);
        writeBinary(
          res,
          encodeBatchResponseNodes(Array.from({ length: encodedBatchCount(body) }, () => row)),
        );
        return true;
      },
    );

    const bootstrap = new RavenPOINodeInterface({ endpoint: server.url, bearerToken: TOKEN });
    const { entries } = await bootstrap.fetchBcToIdxMap(LIST_KEY_HEX);

    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, bcToIdxMapFrom(entries)]]),
    });
    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: `0x${RECURRING}`, type: "Shield" }],
    );
    expect(got[`0x${RECURRING}`][LIST_KEY_HEX]).toBe("ShieldBlocked");
  });

  it("refuses a malformed row rather than building a map around it", () => {
    expect(() => bcToIdxMapFrom([{ bc: "ff", idx: 0 }])).toThrow(/64 hex chars/);
    expect(() => bcToIdxMapFrom([{ bc: RECURRING, idx: -1 }])).toThrow(/non-negative integer/);
    expect(() => bcToIdxMapFrom([{ bc: RECURRING, idx: 1.5 }])).toThrow(/non-negative integer/);
  });

  it("routes the PIR query to the block the lowest occurrence lives in", async () => {
    // Built from rows directly: two occurrences a block apart are not a body the JSON channel
    // can serve without the 65,536 rows between them, and the fetch is not what is under test.
    const rows: IndexRow[] = [
      { bc: RECURRING, idx: 3 },
      { bc: RECURRING, idx: LEAVES_PER_PPOI_BLOCK + 3 },
    ];
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, _body, res) => {
        // Garbage on purpose: the assertion is WHICH instance was asked, and a malformed
        // PPOI row is refused right after the request is on the wire.
        res.writeHead(200, { "content-type": "application/octet-stream" });
        res.end(Buffer.alloc(16));
        return true;
      },
    );

    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t2Path:${LIST_KEY_HEX}`, stubCtx()]]),
      // One label per block: the URL is then the only place the chosen occurrence shows.
      clientPirInstanceLabels: new Map([
        [`t2Path:${LIST_KEY_HEX}:0`, "block0"],
        [`t2Path:${LIST_KEY_HEX}:1`, "block1"],
      ]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, bcToIdxMapFrom(rows)]]),
    });

    await expect(sdk.getPOIMerkleProofs(LIST_KEY_HEX, [RECURRING])).rejects.toThrow();

    const batched = server.requests.filter((r) => /\/batch$/.test(r.url)).map((r) => r.url);
    expect(batched).toStrictEqual(["/v1/instance/block0/batch"]);
  });
});
