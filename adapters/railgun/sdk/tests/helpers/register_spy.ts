/**
 * Recording stand-in for `register_client_session` in stub WASM objects.
 *
 * Twelve test files used to stub the geometry guard as `() => {}` — a no-op that made
 * the guard invisible: deleting `register_client_session` from the SDK entirely left the
 * whole suite green (D3). This spy records every call and enforces the argument contract,
 * so the cold-path call site remains observable from every stubbed suite. The Rust guard
 * compares that bundle with the session's retained CRS; this spy does not model the comparison.
 */

import type { RavenInspireClientSession } from "../../src/index";

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
