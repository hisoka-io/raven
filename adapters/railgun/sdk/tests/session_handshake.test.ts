// Browser-shaped session handshake: one versioned key upload installs the opaque
// server handle before any encrypted query is built.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  RavenPOINodeInterface,
  RavenError,
  hexToBytes,
  type ClientPirContext,
  type RavenInspireWasm,
} from "../src/index";
import { encodeBatchResponseNodes, encodedBatchCount } from "./helpers/auth_path_stub";
import { EXPECTED_WIRE_SCHEMA_VERSION } from "./helpers/wire_schema";
import { startMockServer, writeBinary, writeJson, type MockServer } from "./helpers/mock_server";
import {
  assertNoCommitmentsInPirRequests,
  STUB_QUERY_BYTES,
  stubQueryBundle,
} from "./helpers/private_wire";

const TOKEN = "test-token-padded-long-enough-1234";
const INSTANCE = "t1Status:abababababababababababababababababababababababababababababababab";
const LIST_KEY = "abababababababababababababababababababababababababababababababab";
const BC = "bc00112233445566778899aabbccddeeff00112233445566778899aabbccdd01";
const HANDLE = 9_007_199_254_740_997n;
const REGISTRATION_BODY = new Uint8Array([0, 2, 7, 8, 9]);

function statusRow(): Uint8Array {
  const row = new Uint8Array(32);
  row.set(hexToBytes(BC).subarray(0, 31), 1);
  return row;
}

function queryBundleForHandle(handle: bigint | undefined): Uint8Array {
  if (handle === undefined) throw new Error("query built before a session handle was installed");
  const query = new Uint8Array(STUB_QUERY_BYTES);
  query.fill(0xa5);
  new DataView(query.buffer).setBigUint64(0, handle, true);
  return stubQueryBundle(query);
}

interface RehandshakeRig {
  readonly sdk: RavenPOINodeInterface;
  readonly installedHandles: bigint[];
  readonly batchHandles: bigint[];
  query(): Promise<Record<string, Record<string, string>>>;
  queryPath(): Promise<unknown>;
  flush(): void;
}

function mountRehandshakeRig(
  server: MockServer,
  options: {
    refuseAfterFlush?: boolean;
    deadRequestBarrier?: number;
    genericSameSchema400?: boolean;
  } = {},
): RehandshakeRig {
  let installed: bigint | undefined;
  let active: bigint | undefined;
  let nextHandle = 41n;
  let flushed = false;
  let deadRequests = 0;
  let releaseDeadRequests: (() => void) | undefined;
  const deadRequestsReady = new Promise<void>((resolve) => {
    releaseDeadRequests = resolve;
  });
  const installedHandles: bigint[] = [];
  const batchHandles: bigint[] = [];
  const wasm: RavenInspireWasm = {
    build_client_session: () => ({ free: () => undefined }),
    client_packing_keys_versioned: () => new Uint8Array(REGISTRATION_BODY),
    install_server_session_handle: (_session, handle) => {
      installed = handle;
      installedHandles.push(handle);
    },
    build_seeded_query: () => queryBundleForHandle(installed),
    retarget_seeded_query_shard: (query) => new Uint8Array(query),
    extract_response: (_session, _crs, _state, response) => new Uint8Array(response),
    register_client_session: () => undefined,
    build_instance_params_blob: () => new Uint8Array(0),
    path_indices_for_leaf: () => new Uint32Array(16),
    path_indices_for_per_list_leaf: () => new Uint32Array(16),
  };
  const context: ClientPirContext = {
    wasm,
    session: { free: () => undefined },
    crsBincode: new Uint8Array(0),
    shardConfigBincode: new Uint8Array(0),
    entrySize: 32,
  };

  server.routeSession((_req, body, res) => {
    expect(body).toEqual(REGISTRATION_BODY);
    active = nextHandle;
    nextHandle += 1n;
    writeJson(res, { handle: Number(active), expires_at_unix_secs: 1 }, {
      "x-raven-session": active.toString(),
    });
    return true;
  });
  server.route(
    (req) => (req.url ?? "").endsWith("/batch"),
    async (_req, body, res) => {
      const count = encodedBatchCount(body);
      const bodyView = new DataView(body.buffer, body.byteOffset, body.byteLength);
      const handle = bodyView.getBigUint64(10, true);
      for (let slot = 1; slot < count; slot += 1) {
        expect(bodyView.getBigUint64(10 + slot * STUB_QUERY_BYTES, true)).toBe(handle);
      }
      batchHandles.push(handle);
      const refused = handle !== active || (flushed && options.refuseAfterFlush === true);
      if (refused) {
        deadRequests += 1;
        if (deadRequests >= (options.deadRequestBarrier ?? 1)) releaseDeadRequests?.();
        await deadRequestsReady;
        const sameSchema = String(EXPECTED_WIRE_SCHEMA_VERSION);
        if (options.genericSameSchema400 === true) {
          res.writeHead(400, { "x-raven-schema-version": sameSchema });
        } else {
          res.writeHead(409, { "x-raven-schema-version": sameSchema });
        }
        res.end();
        return true;
      }
      writeBinary(
        res,
        encodeBatchResponseNodes(Array.from({ length: count }, statusRow)),
        { "x-raven-epoch": "1", "x-raven-schema-version": "6" },
      );
      return true;
    },
  );

  const sdk = new RavenPOINodeInterface({
    endpoint: server.url,
    bearerToken: TOKEN,
    useClientPir: true,
    clientPirContexts: new Map([
      [INSTANCE, context],
      ["t3CommitTree:0", context],
    ]),
    bcToIdxMaps: new Map([[LIST_KEY, new Map([[BC, 0]])]]),
  });
  return {
    sdk,
    installedHandles,
    batchHandles,
    query: () =>
      sdk.getPOIsPerList(
        [LIST_KEY],
        [{ blindedCommitment: BC, type: "Shield" }],
      ),
    queryPath: () => sdk.getMerkleProof(0, 0),
    flush: () => {
      flushed = true;
      active = undefined;
    },
  };
}

describe("client-PIR remote session handshake", () => {
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

  it("uploads once, installs the exact u64 header, then builds only handle queries", async () => {
    let installed: bigint | undefined;
    const buildHandles: (bigint | undefined)[] = [];
    const wasm: RavenInspireWasm & {
      client_packing_keys_versioned(session: ClientPirContext["session"]): Uint8Array;
      install_server_session_handle(
        session: ClientPirContext["session"],
        handle: bigint,
      ): void;
    } = {
      build_client_session: () => ({ free: () => undefined }),
      client_packing_keys_versioned: () => new Uint8Array(REGISTRATION_BODY),
      install_server_session_handle: (_session, handle) => {
        installed = handle;
      },
      build_seeded_query: () => {
        buildHandles.push(installed);
        return new Uint8Array(16);
      },
      retarget_seeded_query_shard: (query) => new Uint8Array(query),
      extract_response: (_session, _crs, _state, response) => new Uint8Array(response),
      register_client_session: () => undefined,
      build_instance_params_blob: () => new Uint8Array(0),
      path_indices_for_leaf: () => new Uint32Array(16),
      path_indices_for_per_list_leaf: () => new Uint32Array(16),
    };
    const context: ClientPirContext = {
      wasm,
      session: { free: () => undefined },
      crsBincode: new Uint8Array(0),
      shardConfigBincode: new Uint8Array(0),
      entrySize: 32,
    };

    server.routeSession(
      (_req, body, res) => {
        expect(body).toEqual(REGISTRATION_BODY);
        writeJson(res, { handle: Number(HANDLE), expires_at_unix_secs: 1 }, {
          "x-raven-session": HANDLE.toString(),
        });
        return true;
      },
    );
    server.route(
      (req) => (req.url ?? "").endsWith("/batch"),
      (_req, body, res) => {
        const count = encodedBatchCount(body);
        writeBinary(res, encodeBatchResponseNodes(Array.from({ length: count }, statusRow)));
        return true;
      },
    );

    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[INSTANCE, context]]),
      bcToIdxMaps: new Map([[LIST_KEY, new Map([[BC, 0]])]]),
    });
    const query = () =>
      sdk.getPOIsPerList(
        [LIST_KEY],
        [{ blindedCommitment: BC, type: "Shield" }],
      );

    await expect(query()).resolves.toEqual({ [BC]: { [LIST_KEY]: "Valid" } });
    await expect(query()).resolves.toEqual({ [BC]: { [LIST_KEY]: "Valid" } });

    const sessionRequests = server.requests.filter((request) => request.url.endsWith("/session"));
    const batchRequests = server.requests.filter((request) => request.url.endsWith("/batch"));
    expect(sessionRequests).toHaveLength(1);
    expect(batchRequests).toHaveLength(2);
    const clientIds = [...sessionRequests, ...batchRequests].map(
      (request) => request.headers["x-raven-client-id"],
    );
    expect(clientIds[0]).toMatch(/^[0-9a-f]{32}$/);
    expect(new Set(clientIds)).toEqual(new Set([clientIds[0]]));
    expect(installed).toBe(HANDLE);
    expect(buildHandles).toEqual([HANDLE, HANDLE]);
    expect(sdk.lastWireRequests()).toHaveLength(2);
    expect(sdk.lastWireRequests().every((request) => request.url.endsWith("/batch"))).toBe(true);
  });

  it("replaces a flushed handle once and serves the retried query", async () => {
    const rig = mountRehandshakeRig(server);
    await expect(rig.query()).resolves.toEqual({ [BC]: { [LIST_KEY]: "Valid" } });

    rig.flush();
    await expect(rig.query()).resolves.toEqual({ [BC]: { [LIST_KEY]: "Valid" } });

    expect(rig.installedHandles).toEqual([41n, 41n, 42n]);
    expect(rig.batchHandles).toEqual([41n, 41n, 42n]);
    expect(server.requests.filter((request) => request.url.endsWith("/session"))).toHaveLength(2);
    expect(
      assertNoCommitmentsInPirRequests(server.requests, [BC], {
        expectedQueryCount: 1,
        expectedQueryBytes: STUB_QUERY_BYTES,
      }),
    ).toHaveLength(3);
  });

  it("stops after one replacement when the replacement handle is also refused", async () => {
    const rig = mountRehandshakeRig(server, { refuseAfterFlush: true });
    await expect(rig.query()).resolves.toEqual({ [BC]: { [LIST_KEY]: "Valid" } });

    rig.flush();
    await expect(rig.query()).rejects.toMatchObject({
      kind: "ServerError",
      context: { status: 409 },
    } satisfies Partial<RavenError>);

    expect(rig.installedHandles).toEqual([41n, 41n, 42n]);
    expect(rig.batchHandles).toEqual([41n, 41n, 42n]);
    expect(server.requests.filter((request) => request.url.endsWith("/session"))).toHaveLength(2);
  });

  it("does not re-handshake for a generic same-schema body-decode 400", async () => {
    const rig = mountRehandshakeRig(server, {
      refuseAfterFlush: true,
      genericSameSchema400: true,
    });
    rig.flush();

    await expect(rig.query()).rejects.toMatchObject({
      kind: "ServerError",
      context: { status: 400 },
    } satisfies Partial<RavenError>);

    expect(server.requests.filter((request) => request.url.endsWith("/session"))).toHaveLength(1);
    expect(rig.batchHandles).toEqual([41n]);
  });

  it("uses the same one-replacement state machine for auth-path batches", async () => {
    const rig = mountRehandshakeRig(server);
    await expect(rig.queryPath()).resolves.toMatchObject({ kind: "authPath" });

    rig.flush();
    await expect(rig.queryPath()).resolves.toMatchObject({ kind: "authPath" });

    expect(rig.installedHandles).toEqual([41n, 41n, 42n]);
    expect(rig.batchHandles).toEqual([41n, 41n, 42n]);
    expect(server.requests.filter((request) => request.url.endsWith("/session"))).toHaveLength(2);
  });

  it("uses a distinct stable client identity for each instance", async () => {
    const rig = mountRehandshakeRig(server);
    await expect(rig.query()).resolves.toEqual({ [BC]: { [LIST_KEY]: "Valid" } });
    await expect(rig.queryPath()).resolves.toMatchObject({ kind: "authPath" });

    const statusRequests = server.requests.filter((request) =>
      request.url.includes(encodeURIComponent(`t1Status-${LIST_KEY}`)),
    );
    const treeRequests = server.requests.filter((request) =>
      request.url.includes(encodeURIComponent("commit-tree-0")),
    );
    const statusIds = new Set(
      statusRequests.map((request) => request.headers["x-raven-client-id"]),
    );
    const treeIds = new Set(treeRequests.map((request) => request.headers["x-raven-client-id"]));
    expect(statusIds.size).toBe(1);
    expect(treeIds.size).toBe(1);
    expect([...statusIds][0]).toMatch(/^[0-9a-f]{32}$/);
    expect([...treeIds][0]).toMatch(/^[0-9a-f]{32}$/);
    expect([...statusIds][0]).not.toBe([...treeIds][0]);
  });

  it("deduplicates the replacement handshake across concurrent dead-handle refusals", async () => {
    const rig = mountRehandshakeRig(server, { deadRequestBarrier: 2 });
    await expect(rig.query()).resolves.toEqual({ [BC]: { [LIST_KEY]: "Valid" } });

    rig.flush();
    await expect(Promise.all([rig.query(), rig.query()])).resolves.toHaveLength(2);

    expect(server.requests.filter((request) => request.url.endsWith("/session"))).toHaveLength(2);
    expect(rig.installedHandles.filter((handle) => handle === 42n)).toHaveLength(2);
    expect(rig.batchHandles.filter((handle) => handle === 42n)).toHaveLength(2);
  });
});
