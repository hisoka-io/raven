import { RavenError } from "./errors";

const U32_RANGE = 0x1_0000_0000;

/** Uniform CSPRNG draw in `[0, bound)` using rejection sampling. */
export function uniformRandomBelow(bound: number): number {
  if (!Number.isSafeInteger(bound) || bound < 1 || bound > U32_RANGE) {
    throw RavenError.invalidQuery(
      `uniformRandomBelow: bound must be an integer in [1, ${U32_RANGE}], got ${bound}`,
    );
  }
  if (bound === 1) return 0;
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi || typeof cryptoApi.getRandomValues !== "function") {
    throw RavenError.invalidQuery(
      "uniformRandomBelow: globalThis.crypto.getRandomValues is unavailable; " +
        "privacy padding requires a CSPRNG and cannot fall back to cycling",
    );
  }
  // The bound is public request geometry, so rejection timing is independent of query bytes.
  const limit = Math.floor(U32_RANGE / bound) * bound;
  const word = new Uint32Array(1);
  for (;;) {
    cryptoApi.getRandomValues(word);
    if (word[0] < limit) return word[0] % bound;
  }
}
