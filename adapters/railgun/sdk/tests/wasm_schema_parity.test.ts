// The suite pins the wire schema version in TypeScript (`helpers/wire_schema.ts`) and
// every other assertion compares TS-built bytes against that same TS literal. Nothing
// compared it to the number the LINKED RUST BINARY actually emits — so the pin could
// agree with itself while disagreeing with production, and 385 green tests would not
// notice. `crates/client/src/lib.rs:310` is the Rust source of truth and it is stamped
// into the wasm at `:548` and `:743`.
//
// This is the parity gate the suite was missing: it drives the REAL wasm through a real
// session and reads the prefix off the bytes it produces.
//
// It is NOT the only assertion that crosses that boundary — `privacy_invariant.test.ts`
// binds the real wasm too and asserts the registration prefix. An earlier version of this
// comment claimed otherwise and was wrong. It IS the only one whose sole purpose is
// the crossing, so it is the one that names the failure clearly when the binary drifts.
//
// The OTHER half of this parity — that `EXPECTED_WIRE_SCHEMA_VERSION` itself still matches
// production's Rust constant — is not checkable from inside the suite, because both are
// literals that can drift together. `scripts/check-sdk-constant-parity.sh` chains the test
// pin to `http/src/versioned.rs`; the two gates only work as a pair.

import { describe, expect, it } from "vitest";

import { loadFixture, makeClientPirContext } from "./helpers/fixture";
import {
  EXPECTED_WIRE_SCHEMA_PREFIX,
  EXPECTED_WIRE_SCHEMA_VERSION,
} from "./helpers/wire_schema";

describe("the linked wasm agrees with the TypeScript schema pin", () => {
  it("stamps EXPECTED_WIRE_SCHEMA_VERSION on the versioned packing-key blob", () => {
    const ctx = makeClientPirContext(loadFixture());
    const blob = ctx.wasm.client_packing_keys_versioned(ctx.session);
    const bytes = new Uint8Array(blob);

    expect(bytes.length).toBeGreaterThan(2);
    const emitted = (bytes[0] << 8) | bytes[1];
    expect(
      emitted,
      `the wasm the tests load emits schema ${emitted}, the suite pins ` +
        `${EXPECTED_WIRE_SCHEMA_VERSION}. A TS-only pin agrees with itself.`,
    ).toBe(EXPECTED_WIRE_SCHEMA_VERSION);
    expect([bytes[0], bytes[1]]).toEqual([...EXPECTED_WIRE_SCHEMA_PREFIX]);
  });
});
