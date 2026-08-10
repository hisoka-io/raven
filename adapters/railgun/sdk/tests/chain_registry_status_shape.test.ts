// `GET /v1/status` answers `{scheme, instances:[{id, epoch, ...}], consumer}`. The
// `{epoch, wire_schema_version}` pair belongs to `GET /v1/instance/{id}/params`; a registry
// that reads it off /v1/status silently keeps epoch 0 forever against a real adapter.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { ChainRegistry, RavenError } from "../src/index";

import { startMockServer, writeJson, type MockServer } from "./helpers/mock_server";
import { TOKEN } from "./helpers/auth_path_stub";

const TREE_INSTANCE = "commit-tree-0";
const LIST_INSTANCE = "t2Path-abab";

function instanceRow(id: string, epoch: number): Record<string, unknown> {
  return {
    id,
    epoch,
    role: "live",
    drain_state: "active",
    in_flight: 0,
    active_k_concurrency: 4,
  };
}

function mountStatus(server: MockServer, payload: unknown): void {
  server.route(
    (req) => req.url === "/v1/status",
    (_req, _body, res) => {
      writeJson(res, payload);
      return true;
    },
  );
}

function registryFor(server: MockServer, schemaVersion: number): ChainRegistry {
  return new ChainRegistry([
    { chainId: 1, endpoint: server.url, bearerToken: TOKEN, schemaVersion },
  ]);
}

async function captureThrow(run: () => Promise<unknown>): Promise<unknown> {
  let thrown: unknown;
  let returned = false;
  try {
    await run();
    returned = true;
  } catch (e) {
    thrown = e;
  }
  expect(returned).toBe(false);
  return thrown;
}

describe("ChainRegistry.refresh parses the /v1/status shape", () => {
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

  it("records one epoch per instance", async () => {
    mountStatus(server, {
      scheme: "inspire",
      instances: [instanceRow(TREE_INSTANCE, 9), instanceRow(LIST_INSTANCE, 7)],
      consumer: null,
    });
    const refreshed = await registryFor(server, 1).refresh(1);
    expect(refreshed.instanceEpochs?.get(TREE_INSTANCE)).toBe(9);
    expect(refreshed.instanceEpochs?.get(LIST_INSTANCE)).toBe(7);
  });

  it("summarises the chain at the oldest instance epoch, never the newest", async () => {
    mountStatus(server, {
      scheme: "inspire",
      instances: [instanceRow(TREE_INSTANCE, 9), instanceRow(LIST_INSTANCE, 7)],
      consumer: null,
    });
    const refreshed = await registryFor(server, 1).refresh(1);
    expect(refreshed.epoch).toBe(7);
  });

  it("rejects the /v1/instance/{id}/params body instead of reading its epoch", async () => {
    mountStatus(server, { epoch: 42, wire_schema_version: 1 });
    const thrown = await captureThrow(() => registryFor(server, 1).refresh(1));
    expect(RavenError.is(thrown, "DecodeError")).toBe(true);
    expect((thrown as RavenError).message).toContain("instances");
  });

  it("rejects an instance row whose epoch is missing", async () => {
    mountStatus(server, {
      scheme: "inspire",
      instances: [{ id: TREE_INSTANCE, role: "live", drain_state: "active", in_flight: 0, active_k_concurrency: 4 }],
      consumer: null,
    });
    const thrown = await captureThrow(() => registryFor(server, 1).refresh(1));
    expect(RavenError.is(thrown, "DecodeError")).toBe(true);
    expect((thrown as RavenError).message).toContain("epoch");
  });

  it("rejects an instance row whose epoch is negative or fractional", async () => {
    mountStatus(server, {
      scheme: "inspire",
      instances: [instanceRow(TREE_INSTANCE, -1)],
      consumer: null,
    });
    expect(RavenError.is(await captureThrow(() => registryFor(server, 1).refresh(1)), "DecodeError")).toBe(true);
    server.reset();
    mountStatus(server, {
      scheme: "inspire",
      instances: [instanceRow(TREE_INSTANCE, 1.5)],
      consumer: null,
    });
    expect(RavenError.is(await captureThrow(() => registryFor(server, 1).refresh(1)), "DecodeError")).toBe(true);
  });

  it("carries schemaVersion forward, since /v1/status does not report one", async () => {
    mountStatus(server, {
      scheme: "inspire",
      instances: [instanceRow(TREE_INSTANCE, 9)],
      consumer: null,
    });
    const refreshed = await registryFor(server, 3).refresh(1);
    expect(refreshed.schemaVersion).toBe(3);
  });

  it("keeps the refreshed entry resolvable", async () => {
    mountStatus(server, {
      scheme: "inspire",
      instances: [instanceRow(TREE_INSTANCE, 9)],
      consumer: null,
    });
    const registry = registryFor(server, 1);
    await registry.refresh(1);
    expect(registry.resolve(1).instanceEpochs?.get(TREE_INSTANCE)).toBe(9);
  });
});
