/**
 * Recording stand-in for `register_client_session` in stub WASM objects.
 *
 * Twelve test files used to stub the geometry guard as `() => {}` — a no-op that made
 * the guard invisible: deleting `register_client_session` from the SDK entirely left the
 * whole suite green (D3). This spy records every call and enforces the argument contract,
 * so the cold-path call site remains observable from every stubbed suite. The Rust guard
 * compares that bundle with the session's retained CRS; this spy does not model the comparison.
 */

import type { RavenInspireClientSession, RavenInspireWasm } from "../../src/index";

export interface RegisterCall {
  session: RavenInspireClientSession;
  bundle: Uint8Array;
}

export interface RegisterClientSessionSpy {
  (session: RavenInspireClientSession, instanceParamsBincode: Uint8Array): void;
  calls: RegisterCall[];
}

export function makeRegisterSpy(): RegisterClientSessionSpy {
  const calls: RegisterCall[] = [];
  const spy = ((session: RavenInspireClientSession, instanceParamsBincode: Uint8Array): void => {
    if (!(instanceParamsBincode instanceof Uint8Array)) {
      throw new Error(
        "register_client_session: instanceParamsBincode must be a Uint8Array",
      );
    }
    calls.push({ session, bundle: new Uint8Array(instanceParamsBincode) });
  }) as RegisterClientSessionSpy;
  spy.calls = calls;
  return spy;
}

/** Minimal remote-session and typed-fanout exports for tests whose concern starts later. */
export function stubRemoteSessionExports(): Pick<
  RavenInspireWasm,
  | "client_packing_keys_versioned"
  | "install_server_session_handle"
  | "retarget_seeded_query_shard"
> {
  return {
    client_packing_keys_versioned: () => new Uint8Array([0, 3]),
    install_server_session_handle: () => undefined,
    retarget_seeded_query_shard: (query, nominalShardId) => {
      if (query.length < 4) throw new Error("stub seeded query is shorter than shard_id");
      const retargeted = new Uint8Array(query);
      new DataView(retargeted.buffer).setUint32(0, nominalShardId, true);
      return retargeted;
    },
  };
}
