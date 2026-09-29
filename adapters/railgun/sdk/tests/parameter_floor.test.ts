// A node chooses the parameters the client encrypts under. Through the wasm this package links,
// a served set outside the shipped bounds is refused before any key is derived from it, whether it
// arrives as the instance's params or inside its CRS, and reaches the caller as a `DecodeError`.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import * as wasmPkg from "@hisoka-io/raven-inspire-client-wasm";
import { describe, expect, it } from "vitest";

import { RavenError, loadClientPirContext, type RavenInspireWasm } from "../src/index";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const read = (name: string): Uint8Array => new Uint8Array(readFileSync(join(FIXTURES, name)));
const wasm = wasmPkg as unknown as RavenInspireWasm;

const inspireParams = read("inspire_params.bin");
const crs = read("crs.bin");
const shardConfig = read("shard_config.bin");

// Bincode offsets of `InspireParams` fields; the CRS carries the same struct after its 16-byte magic.
const RING_DIM_AT = 0;
const SIGMA_AT = 40;
const GADGET_BASE_AT = 48;
const QUERY_GADGET_LEN_AT = 56;
const PACKING_GADGET_LEN_AT = 64;
const CRS_PARAMS_AT = 16;

function patched(bytes: Uint8Array, write: (view: DataView) => void): Uint8Array {
  const out = new Uint8Array(bytes);
  write(new DataView(out.buffer));
  return out;
}

/** The refusal a caller catches: a `RavenError`, never the bare string the wasm throws. */
async function refusal(params: Uint8Array, crsBincode: Uint8Array): Promise<RavenError> {
  const thrown = await load(params, crsBincode).then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(RavenError.is(thrown, "DecodeError"), `got ${typeof thrown}: ${String(thrown)}`).toBe(true);
  expect((thrown as RavenError).retryable).toBe(false);
  expect((thrown as RavenError).message).toMatch(/outside this client's floors/);
  return thrown as RavenError;
}

function load(params: Uint8Array, crsBincode: Uint8Array) {
  return loadClientPirContext({
    wasm,
    instanceId: "floor",
    crsBincode,
    shardConfigBincode: shardConfig,
    inspireParamsBincode: params,
    entrySize: 32,
  });
}

describe("parameter floors, through the linked wasm", () => {
  it("loads the shipped preset", async () => {
    expect(new DataView(inspireParams.buffer).getBigUint64(RING_DIM_AT, true)).toBe(2048n);
    await expect(load(inspireParams, crs)).resolves.toMatchObject({ cacheHit: false });
  });

  it.each([
    ["a 1024 ring", (v: DataView) => v.setBigUint64(RING_DIM_AT, 1024n, true), /ring_dim 1024/],
    ["sigma 3.2", (v: DataView) => v.setFloat64(SIGMA_AT, 3.2, true), /sigma 3.2 is not/],
    ["sigma 1e9", (v: DataView) => v.setFloat64(SIGMA_AT, 1e9, true), /sigma 1000000000 is not/],
    [
      "a four-digit packing gadget",
      (v: DataView) => v.setBigUint64(PACKING_GADGET_LEN_AT, 4n, true),
      /packing gadget has 4 digits/,
    ],
    [
      "base-2 gadgets of 60 digits",
      (v: DataView) => {
        v.setBigUint64(GADGET_BASE_AT, 2n, true);
        v.setBigUint64(QUERY_GADGET_LEN_AT, 60n, true);
        v.setBigUint64(PACKING_GADGET_LEN_AT, 60n, true);
      },
      /query gadget has 60 digits, above the shipped 3/,
    ],
  ] as const)("refuses served params with %s", async (_name, write, reason) => {
    const thrown = await refusal(patched(inspireParams, write), crs);
    expect(thrown.message).toMatch(
      new RegExp(`parameter floor refused inspire_params: ${reason.source}`),
    );
  });

  it("refuses a CRS whose own params are below the floor", async () => {
    const weakCrs = patched(crs, (v) => v.setFloat64(CRS_PARAMS_AT + SIGMA_AT, 3.2, true));
    const thrown = await refusal(inspireParams, weakCrs);
    expect(thrown.message).toMatch(/parameter floor refused server_crs: sigma 3.2 is not/);
  });
});
