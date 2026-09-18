// Sponge vectors from Aztec's poseidon2Hash - the oracle Howl's generator wraps.
// Deterministic: the pseudo-random stream is seeded, so this regenerates identically.
import { loadAztecFoundation } from "./aztec-foundation.mjs";
const { poseidon2Hash, Fr } = await loadAztecFoundation();

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const hex = (fr) => "0x" + fr.toBuffer().toString("hex");
const vectors = [];
const add = async (label, inputs) => {
  const out = await poseidon2Hash(inputs.map((x) => new Fr(BigInt(x))));
  vectors.push({ label, inputs: inputs.map(String), output: hex(out) });
};

await add("empty", []);
// Lengths 1..16 walk five rate boundaries; the duplex fires on multiples of 3, so an
// off-by-one in the cache is invisible below 3 and again below 6.
for (let n = 1; n <= 16; n++) await add(`seq_${n}`, Array.from({ length: n }, (_, i) => i + 1));
// Lengths that bracket each boundary from both sides, plus larger multiples.
for (const n of [17, 18, 19, 20, 23, 24, 25, 31, 32, 33, 47, 48, 49, 64, 100])
  await add(`len_${n}`, Array.from({ length: n }, (_, i) => i + 1));
// All-zero at each boundary: the only inputs where a missing IV is otherwise undetectable.
for (const n of [1, 2, 3, 4, 6, 7, 9, 12]) await add(`zeros_${n}`, Array(n).fill(0));
await add("one", [1]);
for (const n of [3, 4, 6, 7]) await add(`rate_boundary_${n}`, Array.from({ length: n }, (_, i) => i + 1));
// Near-modulus, where a reduction bug shows.
await add("max_minus_one", [(P - 1n).toString()]);
await add("max_minus_one_pair", [(P - 1n).toString(), (P - 2n).toString()]);
await add("all_max_3", Array(3).fill((P - 1n).toString()));
await add("all_max_4", Array(4).fill((P - 1n).toString()));
await add("big_mixed", ["0", (P - 1n).toString(), "1", "12345678901234567890"]);
// Order sensitivity and repetition: a sponge that dropped the cache index would collide these.
await add("order_ab", [7, 9]);
await add("order_ba", [9, 7]);
await add("repeat_same_3", [5, 5, 5]);
await add("repeat_same_4", [5, 5, 5, 5]);
// Powers of two across the limb boundaries of the field representation.
for (const s of [63, 64, 65, 127, 128, 129, 191, 192, 253])
  await add(`pow2_${s}`, [(1n << BigInt(s)).toString()]);

let st = 88172645463325252n;
const next = () => { st ^= st << 13n; st &= (1n<<64n)-1n; st ^= st >> 7n; st ^= st << 17n; st &= (1n<<64n)-1n; return st; };
for (let i = 0; i < 12; i++) {
  const n = 1 + Number(next() % 9n);
  await add(`rand_${i}_len${n}`, Array.from({ length: n }, () => ((next() * next()) % P).toString()));
}
console.log(JSON.stringify({ source: "@aztec/foundation@2.1.11 poseidon2Hash", vectors }, null, 2));
