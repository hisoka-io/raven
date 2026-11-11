// A batch sent again for the same rows carries the same covers in the same slots, whether the
// resend is the SDK's own retry after a refused session handle or the caller's retry right after
// a failure. Fresh covers on each send would leave the real rows as the ones every send shares.
// A plan lives only that long: a later call, a refusal a resend meets again, or a table with a
// different shard count gets covers of its own.

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import {
  RavenPOINodeInterface,
  RavenError,
  type ClientPirContext,
  type RavenInspireWasm,
} from "../src/index";
import { encodedBatchCount } from "./helpers/auth_path_stub";
import { blockLabel, forestConfig } from "./helpers/forest";
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

/** Rows each commitment sits at, all in block 0's first shard. */
const LEAVES = COMMITMENTS.map((_bc, at) => 100 + at * 7);
const ENTRIES_PER_SHARD = 2_048;

interface Rig {
  readonly sdk: RavenPOINodeInterface;
  readonly ctx: ClientPirContext;
  /** Rows each batch addressed, in slot order, one entry per batch sent. */
  readonly batches: number[][];
}

/** The batch step a call runs, reached directly so a test can move the table's row bound. */
interface BatchStep {
  runClientPirQueryBatch(
    label: string,
    ctx: ClientPirContext,
    targets: readonly number[],
    populatedRows: number,
  ): Promise<unknown>;
}

/** Every batch is refused with `status`; at 409, a stale handle, each call sends its plan twice. */
function mountRefusingRig(server: MockServer, status = 409): Rig {
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
      res.writeHead(status, { "x-raven-schema-version": String(EXPECTED_WIRE_SCHEMA_VERSION) });
      res.end();
      return true;
    },
  );
  const sdk = new RavenPOINodeInterface({
    ...forestConfig({
      endpoint: server.url,
      listKeyHex: LIST_KEY,
      ctx,
      placed: COMMITMENTS.map((bc, at) => [bc, LEAVES[at]] as const),
      total: LIST_ROWS,
    }),
    bearerToken: TOKEN,
  });
  return { sdk, ctx, batches };
}

async function refusedCall(rig: Rig, status = 409): Promise<void> {
  await expect(rig.sdk.getPOIMerkleProofs(LIST_KEY, COMMITMENTS)).rejects.toMatchObject({
    kind: "ServerError",
    context: { status },
  } satisfies Partial<RavenError>);
}

/** One batch step over `populatedRows`, refused by the rig's server. */
async function refusedStep(rig: Rig, populatedRows: number): Promise<void> {
  const step = rig.sdk as unknown as BatchStep;
  await expect(
    step.runClientPirQueryBatch(blockLabel(LIST_KEY, 0), rig.ctx, LEAVES, populatedRows),
  ).rejects.toMatchObject({ kind: "ServerError" } satisfies Partial<RavenError>);
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
    vi.useRealTimers();
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

  it("keeps the plan through a refusal that a later try can pass", async () => {
    const rig = mountRefusingRig(server, 503);
    await refusedCall(rig, 503);
    await refusedCall(rig, 503);

    expect(rig.batches).toHaveLength(2);
    expect(rig.batches[1]).toEqual(rig.batches[0]);
  });

  it("draws new covers for a call made after the reuse window", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const rig = mountRefusingRig(server);
    await refusedCall(rig);
    vi.setSystemTime(Date.now() + 60 * 60 * 1_000);
    await refusedCall(rig);

    expect(rig.batches).toHaveLength(4);
    expect(rig.batches[1]).toEqual(rig.batches[0]);
    expect(rig.batches[3]).toEqual(rig.batches[2]);
    expect(rig.batches[2]).not.toEqual(rig.batches[0]);
  });

  it("drops the plan on a refusal that a resend would meet again", async () => {
    const rig = mountRefusingRig(server, 400);
    await refusedCall(rig, 400);
    await refusedCall(rig, 400);

    expect(rig.batches).toHaveLength(2);
    expect(rig.batches[1]).not.toEqual(rig.batches[0]);
  });

  it("never replays a plan against a table with a different shard count", async () => {
    const rig = mountRefusingRig(server, 503);
    const shrunk = 2 * ENTRIES_PER_SHARD;
    await refusedStep(rig, LIST_ROWS);
    await refusedStep(rig, shrunk);

    expect(rig.batches).toHaveLength(2);
    expect(rig.batches[0].some((row) => row >= shrunk)).toBe(true);
    for (const row of rig.batches[1]) expect(row).toBeLessThan(shrunk);
  });
});
