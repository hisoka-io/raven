// Typecheck only. Every binding site casts the package `as unknown as RavenInspireWasm`, which hides
// an export the Rust build dropped until a test happens to call it. This assignment names it.
import type * as builtWasm from "@hisoka-io/raven-inspire-client-wasm";

import type { RavenInspireWasm } from "../src/index";

// Required: members optional in the interface must still all be present in the build pinned here.
export function builtWasmSatisfiesSdkContract(built: typeof builtWasm): Required<RavenInspireWasm> {
  return built;
}
