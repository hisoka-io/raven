// The cached session blob carries the client's RLWE secret key, so writing it is a consent
// decision, not a capability decision: a wasm build exposing serialize/deserialize must not
// by itself put that secret at rest.

import { afterEach, describe, expect, it } from "vitest";

import { idbClear, loadClientPirContext } from "../src/index";
import type { RavenInspireClientSession, RavenInspireWasm } from "../src/index";

const INSTANCE_ID = "t1Status-persistence";
const CRS = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
const SESSION_BLOB = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);

interface PersistenceSpy {
  wasm: RavenInspireWasm;
  serializeCalls: number;
  deserializeCalls: number;
  buildCalls: number;
}

function spyWasm(): PersistenceSpy {
  const session: RavenInspireClientSession = { free: () => undefined };
  const spy: PersistenceSpy = {
    serializeCalls: 0,
    deserializeCalls: 0,
    buildCalls: 0,
    wasm: {
      build_client_session: () => {
        spy.buildCalls += 1;
        return session;
      },
      build_seeded_query: () => new Uint8Array(16),
      extract_response: () => new Uint8Array(32),
      build_instance_params_blob: () => new Uint8Array([9, 9]),
      register_client_session: () => {},
      path_indices_for_leaf: () => new Uint32Array(16),
      path_indices_for_per_list_leaf: () => new Uint32Array(16),
      serialize_client_session: () => {
        spy.serializeCalls += 1;
        return SESSION_BLOB;
      },
      deserialize_client_session: () => {
        spy.deserializeCalls += 1;
        return session;
      },
    },
  };
  return spy;
}

describe("client-PIR session persistence is opt-in", () => {
  afterEach(async () => {
    await idbClear();
  });

  it("writes no session blob when persistSession is omitted", async () => {
    const spy = spyWasm();
    const loaded = await loadClientPirContext({
      wasm: spy.wasm,
      instanceId: INSTANCE_ID,
      crsBincode: CRS,
      shardConfigBincode: new Uint8Array(0),
      inspireParamsBincode: new Uint8Array(0),
      entrySize: 32,
    });
    expect(loaded.cacheHit).toBe(false);
    expect(spy.serializeCalls).toBe(0);
    expect(spy.deserializeCalls).toBe(0);
    expect(spy.buildCalls).toBe(1);
  });

  it("writes no session blob when persistSession is false", async () => {
    const spy = spyWasm();
    await loadClientPirContext({
      wasm: spy.wasm,
      instanceId: INSTANCE_ID,
      crsBincode: CRS,
      shardConfigBincode: new Uint8Array(0),
      inspireParamsBincode: new Uint8Array(0),
      entrySize: 32,
      persistSession: false,
    });
    expect(spy.serializeCalls).toBe(0);
  });

  it("persists and reuses the session only once opted in", async () => {
    const cold = spyWasm();
    const first = await loadClientPirContext({
      wasm: cold.wasm,
      instanceId: INSTANCE_ID,
      crsBincode: CRS,
      shardConfigBincode: new Uint8Array(0),
      inspireParamsBincode: new Uint8Array(0),
      entrySize: 32,
      persistSession: true,
    });
    expect(first.cacheHit).toBe(false);
    expect(cold.serializeCalls).toBe(1);

    const warm = spyWasm();
    const second = await loadClientPirContext({
      wasm: warm.wasm,
      instanceId: INSTANCE_ID,
      crsBincode: CRS,
      shardConfigBincode: new Uint8Array(0),
      inspireParamsBincode: new Uint8Array(0),
      entrySize: 32,
      persistSession: true,
    });
    expect(second.cacheHit).toBe(true);
    expect(warm.deserializeCalls).toBe(1);
    expect(warm.buildCalls).toBe(0);
  });

  it("an opted-in load leaves nothing readable for a later opted-out load", async () => {
    const opted = spyWasm();
    await loadClientPirContext({
      wasm: opted.wasm,
      instanceId: INSTANCE_ID,
      crsBincode: CRS,
      shardConfigBincode: new Uint8Array(0),
      inspireParamsBincode: new Uint8Array(0),
      entrySize: 32,
      persistSession: true,
    });
    const optedOut = spyWasm();
    const loaded = await loadClientPirContext({
      wasm: optedOut.wasm,
      instanceId: INSTANCE_ID,
      crsBincode: CRS,
      shardConfigBincode: new Uint8Array(0),
      inspireParamsBincode: new Uint8Array(0),
      entrySize: 32,
    });
    expect(loaded.cacheHit).toBe(false);
    expect(optedOut.deserializeCalls).toBe(0);
    expect(optedOut.buildCalls).toBe(1);
  });
});
