// A batch sent again for the same rows carries the same covers in the same slots, whether the
// resend is the SDK's own retry after a refused session handle or the caller's next call after
// a failure. Fresh covers on each send would leave the real rows as the ones every send shares.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  RavenPOINodeInterface,
  RavenError,
  type ClientPirContext,
  type RavenInspireWasm,
} from "../src/index";
import { encodedBatchCount } from "./helpers/auth_path_stub";
import { forestConfig } from "./helpers/forest";
import { PATH10_ROW_BYTES } from "./helpers/path10_row";
import { EXPECTED_WIRE_SCHEMA_VERSION } from "./helpers/wire_schema";
import { startMockServer, writeJson, type MockServer } from "./helpers/mock_server";
import { stubQueryBundle } from "./helpers/private_wire";
import { shardConfigBincode } from "./helpers/shard_config";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const REGISTRATION_BODY = new Uint8Array([0, EXPECTED_WIRE_SCHEMA_VERSION, 7, 8, 9]);
/** Five rows pad to eight slots, so three covers and a shuffle ride in every batch. */
const COMMITMENTS = [0x11, 0x22, 0x33, 0x44, 0x55].map(
  (marker) => `0e${marker.toString(16).repeat(31)}`,
);
/** Rows the index holds: about thirty shards, so two fresh plans essentially never coincide. */
const LIST_ROWS = 60_000;

interface Rig {
  readonly sdk: RavenPOINodeInterface;
  /** Rows each batch addressed, in slot order, one entry per batch sent. */
  readonly batches: number[][];
}

/** Every batch is refused as a stale handle, so each call sends its plan twice and fails. */
function mountRefusingRig(server: MockServer): Rig {
  const built: number[] = [];
  const batches: number[][] = [];
  let nextHandle = 41n;
  const wasm: RavenInspireWasm = {
    build_client_session: () => ({ free: () => undefined }),
    client_packing_keys_versioned: () => new Uint8Array(REGISTRATION_BODY),
    install_server_session_handle: () => undefined,
    build_seeded_query: (_session, _shardConfig, target) => {
      built.push(Number(target));
      return stubQueryBundle();
    },
    extract_response: (_session, _crs, _state, response) => new Uint8Array(response),
    register_client_session: () => undefined,
    build_instance_params_blob: () => new Uint8Array(0),
  };
  const ctx: ClientPirContext = {
    wasm,
    session: { free: () => undefined },
    crsBincode: new Uint8Array(0),
    shardConfigBincode: shardConfigBincode(),
    entrySize: PATH10_ROW_BYTES,
  };
  server.routeSession((_req, _body, res) => {
    const handle = nextHandle;
    nextHandle += 1n;
    writeJson(res, { handle: Number(handle), expires_at_unix_secs: 1 }, {
      "x-raven-session": handle.toString(),
    });
    return true;
  });
  server.route(
    (req) => (req.url ?? "").endsWith("/batch"),
    (_req, body, res) => {
      batches.push(built.splice(0, encodedBatchCount(body)));
      res.writeHead(409, { "x-raven-schema-version": String(EXPECTED_WIRE_SCHEMA_VERSION) });
      res.end();
      return true;
    },
  );
  const sdk = new RavenPOINodeInterface({
    ...forestConfig({
      endpoint: server.url,
      listKeyHex: LIST_KEY,
      ctx,
      placed: COMMITMENTS.map((bc, at) => [bc, 100 + at * 7] as const),
      total: LIST_ROWS,
    }),
    bearerToken: TOKEN,
  });
  return { sdk, batches };
}

async function refusedCall(rig: Rig): Promise<void> {
  await expect(rig.sdk.getPOIMerkleProofs(LIST_KEY, COMMITMENTS)).rejects.toMatchObject({
    kind: "ServerError",
    context: { status: 409 },
  } satisfies Partial<RavenError>);
}

describe("a batch sent again reuses its cover plan", () => {
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

  it("sends the same rows in the same slots on the retry after a refused handle", async () => {
    const rig = mountRefusingRig(server);
    await refusedCall(rig);

    expect(rig.batches).toHaveLength(2);
    const [first, retry] = rig.batches;
    expect(first).toHaveLength(8);
    expect(new Set(first).size).toBe(8);
    expect(retry).toEqual(first);
  });

  it("sends the same plan again when the caller retries a failed call", async () => {
    const rig = mountRefusingRig(server);
    await refusedCall(rig);
    await refusedCall(rig);

    expect(rig.batches).toHaveLength(4);
    for (const batch of rig.batches) expect(batch).toEqual(rig.batches[0]);
  });
});
