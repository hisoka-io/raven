# K1 - Poseidon2-BN254: the specification, its provenance, and the oracle

Written 2026-08-27, before any Rust exists. Everything here is measured against a runnable oracle,
not recalled. Nothing in `darkpool-v2` was modified; it was read and executed only.

## 1. What must be matched, exactly

Howl's generator is a 15-line wrapper:

```ts
// darkpool-v2/packages/wallets/src/crypto/Poseidon.ts
import { poseidon2Hash } from "@aztec/foundation/crypto";
export class Poseidon {
  public static async hash(inputs: Fr[]): Promise<Fr> { return poseidon2Hash(inputs); }
}
```

**So the thing to match is Aztec's `poseidon2Hash`, not a Howl-local construction.** That is a
scoping fact worth stating plainly: there is no Howl-specific parameterisation to reverse engineer.

`poseidon2Hash` is **WASM-backed by Barretenberg** (`@aztec/bb.js`, `BarretenbergSync`), so the round
constants are NOT present in readable JavaScript. They exist in three citable places:

| implementation | where | note |
|---|---|---|
| Barretenberg (canonical) | `@aztec/bb.js` WASM | the oracle; constants not source-readable |
| Noir | `std::hash::poseidon2_permutation` | an intrinsic, so also not source-readable |
| Solidity/Yul | `darkpool-v2/packages/evm-contracts/contracts/Poseidon/LibPoseidon2Yul.sol` | constants INLINED; cites `https://github.com/zemse/poseidon2-evm` (MIT) |

## 2. The sponge, read off the vendored Noir and then CONFIRMED against the oracle

`darkpool-v2/packages/circuits/vendor/poseidon/src/poseidon2.nr`:

- state is `[Field; 4]`, **RATE = 3**, capacity is index 3.
- `iv = in_len * 2^64`, written to `state[3]` at construction. `two_pow_64 = 18446744073709551616`.
- absorb fills a 3-element cache; when full, duplex.
- duplex: `state[0..3] += cache[0..3]`, then `state = poseidon2_permutation(state)`.
- squeeze: duplex once more, return `state[0]`.

**Confirmed against both oracles rather than assumed:**

| prediction from the model | result |
|---|---|
| `hash([])` == `perm([0,0,0,0])[0]` | **MATCH** |
| `hash([1])` == `perm([1,0,0,2^64])[0]` | **MATCH** |

That is the whole sponge, verified with no Rust written.

## 3. The oracle, and why it makes this safe

Two independent oracles are exported and both are runnable locally:

- `poseidon2Hash(Fr[]) -> Fr` - the sponge.
- `poseidon2Permutation(Fr[4]) -> Fr[4]` - **the raw permutation.**

The second is what removes the hallucination risk. Any candidate round-constant set can be
CHECKED against random states rather than trusted. This is what "port, don't invent" requires, and
without the permutation oracle K1 would have been a matter of transcribing constants and hoping.

## 4. Vectors captured, in this lane

| file | contents |
|---|---|
| `poseidon2-kats.json` | **20** sponge vectors: empty, lengths 1-8, all-zero at 1/3/4, rate boundaries 3/4/6/7, `p-1`, `(p-1, p-2)`, mixed |
| `poseidon2-perm-kats.json` | **18** permutation vectors: basis states, `1..4`, near-modulus, the IV states for lengths 1 and 2, and 8 deterministic pseudo-random states |
| `gen-kats.mjs`, `gen-perm-kats.mjs` | the generators, so the corpus is reproducible rather than pasted |

**The corpus is cross-verified against a value Howl has COMMITTED.**
`darkpool-v2/packages/evm-contracts/test/poseidon-parity.test.ts` pins
`KNOWN_HASH_2_1_2 = 0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383` and calls it
"the published test vector". My generated vector for inputs `(1, 2)` is byte-identical. So the oracle
I am generating against is provably the one Howl ships against, not merely one with the same name.

To regenerate directly against Aztec, install `@aztec/foundation@2.1.11` and point
`AZTEC_FOUNDATION_ROOT` at that package's root before running either generator. The generators
refuse missing, unreadable, wrong-version, or API-incompatible packages.

## 5. Deliberate non-decisions

Rate boundaries are covered at 3, 4, 6 and 7 inputs specifically because the duplex fires on multiples
of RATE, and an implementation that mishandles the boundary passes lengths 1 and 2 and fails at 3.
The zero-input case is included because `iv = 0` there and the state is entirely zero, which is the
one input where a missing IV cannot be detected by any other vector.

## 6. What remains, and it is one owner decision

The implementation needs BN254 `Fr` arithmetic. That is a crate-layout and dependency decision, which
`CLAUDE.md`'s Decision-Making Protocol and V6 PART 2.2 both reserve, and which
`ROADMAP-HOWL-v2.md` section 7 already carries as open question 10 ("Home for Poseidon2-BN254").
It is batched, with a recommendation, rather than taken.
