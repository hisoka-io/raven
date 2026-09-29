// Typecheck only. Every binding site casts the package `as unknown as RavenInspireWasm`, which hides
// an export the Rust build dropped until a test happens to call it. This assignment names it.
import type * as builtWasm from "@hisoka-io/raven-inspire-client-wasm";

import type { RavenInspireWasm } from "../src/index";

// Required: the optional members tolerate older builds at runtime, but the build pinned here must
// still carry every one of them.
export function builtWasmSatisfiesSdkContract(built: typeof builtWasm): Required<RavenInspireWasm> {
  return built;
}
