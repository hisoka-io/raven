import { execFileSync, spawnSync } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  RavenError,
  RavenPOINodeInterface,
  type ClientPirContext,
  type RavenInspireWasm,
} from "../src/index";
import {
  buildFanoutCoverPlan,
  recoverRealFanoutResponses,
  type FanoutCoverPlan,
} from "../src/fanout-cover";
import { encodeBatchResponseNodes } from "./helpers/auth_path_stub";
import { startMockServer, writeBinary } from "./helpers/mock_server";
import { assertNoCommitmentsInPirRequests, stubQueryBundle } from "./helpers/private_wire";
import { makeRegisterSpy, stubRemoteSessionExports } from "./helpers/register_spy";

const WIRE_SCHEMA_VERSION = 7;
const sdkRoot = fileURLToPath(new URL("../", import.meta.url));
const fixtureRoot = fileURLToPath(new URL("./fixtures/", import.meta.url));

interface DeterministicCrypto {
  readonly crypto: Crypto;
  readonly draws: () => number;
}

function deterministicCrypto(words: readonly number[]): DeterministicCrypto {
  let cursor = 0;
  const crypto = Object.create(globalThis.crypto) as Crypto;
  crypto.getRandomValues = <T extends ArrayBufferView | null>(array: T): T => {
    if (array instanceof Uint8Array) {
      array.fill(0x5a);
      return array;
    }
    if (!(array instanceof Uint32Array)) {
      throw new TypeError("fanout test RNG accepts Uint8Array or Uint32Array only");
    }
    for (let i = 0; i < array.length; i += 1) {
      const word = words[cursor];
      if (word === undefined) throw new Error(`fanout test RNG exhausted at draw ${cursor}`);
      array[i] = word;
      cursor += 1;
    }
    return array;
  };
  return { crypto, draws: () => cursor };
}

function installWords(words: readonly number[]): DeterministicCrypto {
  const deterministic = deterministicCrypto(words);
  vi.stubGlobal("crypto", deterministic.crypto);
  return deterministic;
}

function zeroWords(count: number = 128): number[] {
  return Array.from({ length: count }, () => 0);
}

function readU64Low(view: DataView, offset: number): number {
  expect(view.getUint32(offset + 4, true)).toBe(0);
  return view.getUint32(offset, true);
}

interface FanoutCapture {
  readonly body: Uint8Array;
  readonly rows: readonly Uint8Array[];
  readonly shardIds: readonly number[];
  readonly retargetedTo: readonly number[];
  readonly queryBuilds: number;
  readonly requestUrls: readonly string[];
}

async function captureHighLevelFanout(
  realShardIds: readonly number[],
  shardCount: number,
  queryBytes: Uint8Array,
  randomWords: readonly number[],
): Promise<FanoutCapture> {
  const server = await startMockServer();
  const retargetedTo: number[] = [];
  let queryBuilds = 0;
  let body = new Uint8Array();
  let shardIds: number[] = [];
  const wasm: RavenInspireWasm = {
    ...stubRemoteSessionExports(),
    build_client_session: () => ({ free: () => undefined }),
    build_seeded_query: () => {
      queryBuilds += 1;
      return stubQueryBundle(new Uint8Array(queryBytes));
    },
    retarget_seeded_query_shard: (query, nominalShardId) => {
      retargetedTo.push(nominalShardId);
      const retargeted = new Uint8Array(query);
      if (retargeted.length >= 4) {
        new DataView(retargeted.buffer).setUint32(0, nominalShardId, true);
      }
      return retargeted;
    },
    extract_response: (_session, _crs, _state, response) => new Uint8Array(response),
    build_instance_params_blob: () => new Uint8Array(0),
    register_client_session: makeRegisterSpy(),
    path_indices_for_leaf: () => new Uint32Array(16),
    path_indices_for_per_list_leaf: () => new Uint32Array(16),
  };
  const ctx: ClientPirContext = {
    wasm,
    session: { free: () => undefined },
    crsBincode: new Uint8Array(0),
    shardConfigBincode: new Uint8Array(0),
    entrySize: 32,
  };
  server.route(
    (req) => req.url === "/v1/instance/cover-capture/fanout",
    (_req, requestBody, res) => {
      body = new Uint8Array(requestBody);
      const countOffset = 2 + queryBytes.length;
      const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
      const count = readU64Low(view, countOffset);
      shardIds = Array.from({ length: count }, (_unused, position) =>
        view.getUint32(countOffset + 8 + position * 4, true),
      );
      writeBinary(
        res,
        encodeBatchResponseNodes(shardIds.map((shardId) => new Uint8Array([shardId]))),
      );
      return true;
    },
  );

  try {
    installWords(randomWords);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: "fanout-capture-token-long-enough",
      useClientPir: true,
    });
    const rows = await sdk.queryClientPirFanout(
      "cover-capture",
      ctx,
      7n,
      realShardIds,
      shardCount,
    );
    return {
      body,
      rows,
      shardIds,
      retargetedTo,
      queryBuilds,
      requestUrls: server.requests.map((request) => request.url),
    };
  } finally {
    await server.close();
  }
}

afterEach(() => vi.unstubAllGlobals());

describe("one-query fanout cover", () => {
  it("exposes only the high-level fanout request constructor from the supported SDK", async () => {
    const supported = await import("../src/index");

    expect("buildFanoutCoverPlan" in supported).toBe(false);
    expect("encodeFanoutRequest" in supported).toBe(false);
    expect("recoverRealFanoutResponses" in supported).toBe(false);
    expect(typeof supported.RavenPOINodeInterface.prototype.queryClientPirFanout).toBe("function");
  });

  it("refuses the packed deep import that can emit a real unretargeted query", () => {
    const packageProbeRoot = mkdtempSync(
      join(sdkRoot, "node_modules/.w1-25-package-boundary-"),
    );
    try {
      const packOutput = execFileSync(
        "npm",
        ["pack", "--json", "--ignore-scripts", "--pack-destination", packageProbeRoot],
        { cwd: sdkRoot, encoding: "utf8" },
      );
      const packEntries = JSON.parse(packOutput) as unknown;
      if (!Array.isArray(packEntries) || packEntries.length !== 1) {
        throw new Error(`npm pack returned an unexpected manifest: ${packOutput}`);
      }
      const filename = (packEntries[0] as { readonly filename?: unknown }).filename;
      if (typeof filename !== "string" || filename.length === 0) {
        throw new Error(`npm pack omitted the tarball filename: ${packOutput}`);
      }

      const packageRoot = join(
        packageProbeRoot,
        "node_modules/@raven/railgun-poi-node-interface",
      );
      mkdirSync(packageRoot, { recursive: true });
      execFileSync(
        "tar",
        ["-xzf", join(packageProbeRoot, filename), "-C", packageRoot, "--strip-components=1"],
        { cwd: packageProbeRoot },
      );
      const rawEncoderExports = readdirSync(join(packageRoot, "src"), {
        withFileTypes: true,
      })
        .filter((entry) => entry.isFile() && entry.name.endsWith(".ts"))
        .filter((entry) => {
          const source = readFileSync(join(packageRoot, "src", entry.name), "utf8");
          return (
            /export\s+(?:async\s+)?(?:function|const|class)\s+encodeFanoutRequest\b/.test(
              source,
            ) || /export\s*{[^}]*\bencodeFanoutRequest\b/s.test(source)
          );
        })
        .map((entry) => entry.name);

      const consumerPath = join(packageProbeRoot, "deep-import-consumer.test.ts");
      writeFileSync(
        consumerPath,
        `import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, it, vi } from "vitest";
import * as wasmPkg from "raven-inspire-client-wasm";
import {
  buildFanoutCoverPlan,
  encodeFanoutRequest,
} from "@raven/railgun-poi-node-interface/src/fanout-cover";
import {
  decodeClientPirQueryBundle,
  type RavenInspireWasm,
} from "@raven/railgun-poi-node-interface/src/client-pir";

const fixtureRoot = ${JSON.stringify(fixtureRoot)};
const read = (name: string): Uint8Array =>
  new Uint8Array(readFileSync(resolve(fixtureRoot, name)));

it("cannot compose a real issued plan with an unretargeted caller-real query", () => {
  const wasm = wasmPkg as unknown as RavenInspireWasm;
  const session = wasm.build_client_session(read("params_bundle.bin"), read("crs.bin"));
  try {
    const originalQuery = decodeClientPirQueryBundle(
      wasm.build_seeded_query(session, read("shard_config.bin"), 0n),
    ).queryBytes;
    const originalShard = new DataView(
      originalQuery.buffer,
      originalQuery.byteOffset,
      originalQuery.byteLength,
    ).getUint32(0, true);
    expect(originalShard).toBe(0);

    let cursor = 0;
    const words = [0, 0, 0, 0, 2];
    const crypto = Object.create(globalThis.crypto) as Crypto;
    crypto.getRandomValues = <T extends ArrayBufferView | null>(array: T): T => {
      if (!(array instanceof Uint32Array)) throw new TypeError("expected Uint32Array");
      for (let index = 0; index < array.length; index += 1) {
        const word = words[cursor];
        if (word === undefined) throw new Error("package consumer RNG exhausted");
        array[index] = word;
        cursor += 1;
      }
      return array;
    };
    vi.stubGlobal("crypto", crypto);

    const plan = buildFanoutCoverPlan([0, 2, 5], 8, 32);
    expect(plan.nominalShardId).toBe(1);
    const body = encodeFanoutRequest(originalQuery, plan, ${WIRE_SCHEMA_VERSION});
    const emittedShard = new DataView(
      body.buffer,
      body.byteOffset,
      body.byteLength,
    ).getUint32(2, true);
    expect(emittedShard).toBe(originalShard);
    expect(emittedShard).not.toBe(plan.nominalShardId);
  } finally {
    vi.unstubAllGlobals();
    session.free();
  }
});
`,
        "utf8",
      );
      const configPath = join(packageProbeRoot, "vitest.config.ts");
      writeFileSync(
        configPath,
        `import { defineConfig } from "vitest/config";

export default defineConfig({
  root: ${JSON.stringify(packageProbeRoot)},
  test: { include: ["deep-import-consumer.test.ts"], testTimeout: 120_000 },
});
`,
        "utf8",
      );

      const nested = spawnSync(
        process.execPath,
        [resolve(sdkRoot, "node_modules/vitest/vitest.mjs"), "run", "--config", configPath],
        {
          cwd: packageProbeRoot,
          encoding: "utf8",
          env: { ...process.env, NO_COLOR: "1" },
        },
      );
      const diagnostic = `${nested.stdout}\n${nested.stderr}`;
      expect(nested.error).toBeUndefined();
      expect(nested.status, diagnostic).not.toBe(0);
      expect(diagnostic).toMatch(
        /No matching export.*encodeFanoutRequest|does not provide an export named ['"]encodeFanoutRequest|encodeFanoutRequest.*not exported|encodeFanoutRequest is not a function/s,
      );
      expect(rawEncoderExports).toEqual([]);
    } finally {
      rmSync(packageProbeRoot, { recursive: true, force: true });
    }
  }, 120_000);

  it("pads equal-ladder real counts to equal production request lengths with one query", async () => {
    const query = new Uint8Array([0, 0, 0, 0, 0xee, 0x52]);
    const lengths: number[] = [];
    for (const realCount of [5, 6, 7, 8]) {
      const capture = await captureHighLevelFanout(
        Array.from({ length: realCount }, (_unused, shardId) => shardId),
        32,
        query,
        zeroWords(),
      );
      const encodedQuery = capture.body.subarray(2, 2 + query.length);

      expect(capture.shardIds).toHaveLength(8);
      expect(new DataView(encodedQuery.buffer, encodedQuery.byteOffset).getUint32(0, true)).toBe(
        capture.retargetedTo[0],
      );
      expect(encodedQuery.subarray(4)).toEqual(query.subarray(4));
      expect(
        readU64Low(new DataView(capture.body.buffer, capture.body.byteOffset), 2 + query.length),
      ).toBe(8);
      expect(capture.body).toHaveLength(2 + query.length + 8 + 8 * 4);
      expect(capture.queryBuilds).toBe(1);
      lengths.push(capture.body.length);
    }

    expect(new Set(lengths)).toEqual(new Set([lengths[0]]));
  });

  it("draws non-cyclic covers and records the real response permutation", () => {
    installWords([1, 3, 4, 0, 0, 0, 0, 0, 0, 0, 4]);
    const plan = buildFanoutCoverPlan([2, 5, 7, 9, 11], 16, 32);

    expect(plan.wireShardIds).toEqual([5, 7, 9, 11, 1, 6, 10, 2]);
    expect(plan.responseSlotByRealPosition).toEqual([7, 0, 1, 2, 3]);
    expect(plan.nominalShardId).toBe(1);
    expect(plan.wireShardIds.filter((shardId) => ![2, 5, 7, 9, 11].includes(shardId))).toEqual([
      1, 6, 10,
    ]);
  });

  it("encodes the Rust FanoutRequest field order and integer endianness in production", async () => {
    const query = new Uint8Array([0, 0, 0, 0, 0xee, 0x52]);
    const capture = await captureHighLevelFanout(
      [2, 5, 7, 9, 11],
      16,
      query,
      [1, 3, 4, 0, 0, 0, 0, 0, 0, 0, 4],
    );
    const body = capture.body;
    const view = new DataView(body.buffer, body.byteOffset, body.byteLength);

    expect(view.getUint16(0, false)).toBe(WIRE_SCHEMA_VERSION);
    expect(view.getUint32(2, true)).toBe(capture.retargetedTo[0]);
    expect(body.subarray(6, 2 + query.length)).toEqual(query.subarray(4));
    let offset = 2 + query.length;
    expect(readU64Low(view, offset)).toBe(capture.shardIds.length);
    offset += 8;
    const encodedShardIds = capture.shardIds.map((_unused, position) =>
      view.getUint32(offset + position * 4, true),
    );
    expect(encodedShardIds).toEqual(capture.shardIds);
    expect(encodedShardIds).toEqual([5, 7, 9, 11, 1, 6, 10, 2]);
    expect(offset + encodedShardIds.length * 4).toBe(body.length);
  });

  it("restores every real response in caller shard order", () => {
    installWords([1, 3, 4, 0, 0, 0, 0, 0, 0, 0, 4]);
    const realShardIds = [2, 5, 7, 9, 11];
    const plan = buildFanoutCoverPlan(realShardIds, 16, 32);
    const wireResponses = plan.wireShardIds.map(
      (shardId, wireSlot) => `shard=${shardId};slot=${wireSlot}`,
    );

    expect(recoverRealFanoutResponses(plan, wireResponses)).toEqual([
      "shard=2;slot=7",
      "shard=5;slot=0",
      "shard=7;slot=1",
      "shard=9;slot=2",
      "shard=11;slot=3",
    ]);
  });

  it("keeps duplicate real shards as distinct caller positions", () => {
    installWords([6, 0, 0, 0, 2]);
    const plan = buildFanoutCoverPlan([2, 2, 5], 8, 32);
    const wireResponses = plan.wireShardIds.map((shardId, wireSlot) => `${shardId}:${wireSlot}`);

    expect(plan.responseSlotByRealPosition).toEqual([3, 0, 1]);
    expect(recoverRealFanoutResponses(plan, wireResponses)).toEqual(["2:3", "2:0", "5:1"]);
  });

  it("rejection-samples a u32 draw instead of introducing modulo bias", () => {
    const deterministic = installWords([0xffff_ffff, 4, 0, 0, 0, 0]);
    const plan = buildFanoutCoverPlan([1, 2, 3], 10, 32);

    expect(plan.wireShardIds).toContain(7);
    expect(deterministic.draws()).toBe(6);
  });

  it("fails closed when padding needs an unavailable CSPRNG", () => {
    vi.stubGlobal("crypto", undefined);
    expect(() => buildFanoutCoverPlan([1, 2, 3], 8, 32)).toThrow(/CSPRNG/);
  });

  it("refuses empty, out-of-range, malformed, and cap-insufficient cover inputs", async () => {
    expect(() => buildFanoutCoverPlan([], 8, 32)).toThrow(/must not be empty/);
    expect(() => buildFanoutCoverPlan([8], 8, 32)).toThrow(/out of range/);
    expect(() => buildFanoutCoverPlan([1.5], 8, 32)).toThrow(/non-negative integer/);
    expect(() => buildFanoutCoverPlan([1, 2, 3, 4, 5], 8, 7)).toThrow(/padded length 8/);
    expect(() => buildFanoutCoverPlan([1], 0, 32)).toThrow(/shard count/);
    expect(() => buildFanoutCoverPlan([0, 1, 2], 3, 32)).toThrow(
      /insufficient distinct cover shards/,
    );

    await expect(captureHighLevelFanout([1], 8, new Uint8Array(), [0])).rejects.toThrow(
      /query bytes must not be empty/,
    );
  });

  it("refuses missing or surplus responses and forged permutation maps", () => {
    installWords([1, 3, 4, 0, 0, 0, 0, 0, 0, 0, 4]);
    const plan = buildFanoutCoverPlan([2, 5, 7, 9, 11], 16, 32);
    expect(() => recoverRealFanoutResponses(plan, Array.from({ length: 7 }, () => "x"))).toThrow(
      /expected 8 responses, got 7/,
    );
    expect(() => recoverRealFanoutResponses(plan, Array.from({ length: 9 }, () => "x"))).toThrow(
      /expected 8 responses, got 9/,
    );

    const malformed = { ...plan, responseSlotByRealPosition: [99] };
    expect(() =>
      recoverRealFanoutResponses(malformed, Array.from({ length: 8 }, () => "x")),
    ).toThrow(/issued by buildFanoutCoverPlan/);
    const noRealResponses = { ...plan, responseSlotByRealPosition: [] };
    expect(() =>
      recoverRealFanoutResponses(noRealResponses, Array.from({ length: 8 }, () => "x")),
    ).toThrow(/issued by buildFanoutCoverPlan/);
  });

  it("returns typed errors and never falls back to Math.random", () => {
    const mathRandom = vi.spyOn(Math, "random");
    vi.stubGlobal("crypto", undefined);
    try {
      buildFanoutCoverPlan([1, 2, 3], 8, 32);
      expect.fail("missing CSPRNG must refuse");
    } catch (cause) {
      expect(RavenError.is(cause, "InvalidQuery")).toBe(true);
    }
    expect(mathRandom).not.toHaveBeenCalled();
  });

  it("refuses forged plans, adapter-cap drift, and oversized production bodies", async () => {
    const forgedPlans = [
      { wireShardIds: [1, 2, 2, 3], responseSlotByRealPosition: [0] },
      { wireShardIds: [1, 2, 3], responseSlotByRealPosition: [0] },
      {
        wireShardIds: Array.from({ length: 33 }, (_unused, shardId) => shardId),
        responseSlotByRealPosition: [0],
      },
    ];
    for (const forged of forgedPlans) {
      expect(() =>
        recoverRealFanoutResponses(
          forged as unknown as FanoutCoverPlan,
          Array.from({ length: forged.wireShardIds.length }, () => "x"),
        ),
      ).toThrow(/issued by buildFanoutCoverPlan/);
    }

    expect(() => buildFanoutCoverPlan([1], 8, 33)).toThrow(/adapter cap 32/);
    await expect(
      captureHighLevelFanout([1], 8, new Uint8Array(8 * 1024 * 1024), [0]),
    ).rejects.toThrow(/body cap/);
  });

  it("posts one retargeted query to fanout and restores real rows to caller order", async () => {
    const server = await startMockServer();
    const retargetedTo: number[] = [];
    let queryBuilds = 0;
    const wasm: RavenInspireWasm = {
      ...stubRemoteSessionExports(),
      build_client_session: () => ({ free: () => undefined }),
      build_seeded_query: () => {
        queryBuilds += 1;
        const query = new Uint8Array(64);
        new DataView(query.buffer).setUint32(0, 7, true);
        return stubQueryBundle(query);
      },
      retarget_seeded_query_shard: (_query, nominalShardId) => {
        retargetedTo.push(nominalShardId);
        const query = new Uint8Array(_query);
        new DataView(query.buffer).setUint32(0, nominalShardId, true);
        return query;
      },
      extract_response: (_session, _crs, _state, response) => new Uint8Array(response),
      build_instance_params_blob: () => new Uint8Array(0),
      register_client_session: makeRegisterSpy(),
      path_indices_for_leaf: () => new Uint32Array(16),
      path_indices_for_per_list_leaf: () => new Uint32Array(16),
    };
    const ctx: ClientPirContext = {
      wasm,
      session: { free: () => undefined },
      crsBincode: new Uint8Array(0),
      shardConfigBincode: new Uint8Array(0),
      entrySize: 32,
    };
    let capturedBody = new Uint8Array();
    let capturedShardIds: number[] = [];
    server.route(
      (req) => req.url === "/v1/instance/cover-instance/fanout",
      (_req, body, res) => {
        capturedBody = new Uint8Array(body);
        const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
        const queryBytes = 64;
        const countOffset = 2 + queryBytes;
        expect(view.getBigUint64(countOffset, true)).toBe(4n);
        capturedShardIds = Array.from({ length: 4 }, (_unused, position) =>
          view.getUint32(countOffset + 8 + position * 4, true),
        );
        writeBinary(
          res,
          encodeBatchResponseNodes(
            capturedShardIds.map((shardId) => new Uint8Array([shardId])),
          ),
        );
        return true;
      },
    );

    try {
      installWords([0, 0, 0, 0, 2]);
      const sdk = new RavenPOINodeInterface({
        endpoint: server.url,
        bearerToken: "fanout-cover-token-long-enough",
        useClientPir: true,
      });
      const rows = await sdk.queryClientPirFanout(
        "cover-instance",
        ctx,
        7n,
        [2, 5, 7],
        8,
      );

      expect(rows.map((row) => row[0])).toEqual([2, 5, 7]);
      expect(queryBuilds).toBe(1);
      expect(retargetedTo).toEqual([0]);
      expect(new Set(capturedShardIds)).toEqual(new Set([0, 2, 5, 7]));
      expect(new DataView(capturedBody.buffer, capturedBody.byteOffset).getUint32(2, true)).toBe(0);
      expect(capturedBody).toHaveLength(2 + 64 + 8 + 4 * 4);
      expect(server.requests.filter((request) => request.url.endsWith("/fanout"))).toHaveLength(1);
      expect(server.requests.some((request) => request.url.endsWith("/batch"))).toBe(false);
      assertNoCommitmentsInPirRequests(sdk.lastWireRequests(), ["ff".repeat(32)], {
        expectedQueryCount: 1,
      });

      server.reset();
      server.route(
        (req) => req.url === "/v1/instance/cover-instance/fanout",
        (_req, _body, res) => {
          writeBinary(res, new Uint8Array(), {
            "x-raven-freshness": "lag_blocks=9 applied_height=40 epoch=41 confidence=0.1",
          });
          return true;
        },
      );
      installWords([0, 0, 0, 0, 2]);
      let stale: unknown;
      try {
        await sdk.queryClientPirFanout("cover-instance", ctx, 7n, [2, 5, 7], 8);
      } catch (cause) {
        stale = cause;
      }
      expect(RavenError.is(stale, "StaleData")).toBe(true);
      if (RavenError.is(stale, "StaleData")) {
        expect(stale.context.operation).toBe("fanout");
        expect(stale.context.confidence).toBe(0.1);
      }
    } finally {
      await server.close();
    }
  });
});
