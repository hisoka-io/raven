// Raw permutation vectors from Barretenberg. Deterministic and independent of the sponge, so a
// failure localises to the constants or the linear layers.
import { loadAztecFoundation } from "./aztec-foundation.mjs";
const { poseidon2Permutation, Fr } = await loadAztecFoundation();

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const hex = (fr) => "0x" + fr.toBuffer().toString("hex");
const perm = async (st) => (await poseidon2Permutation(st.map((x) => new Fr(x)))).map(hex);
const TWO64 = 18446744073709551616n;

const states = [
  [0n,0n,0n,0n], [1n,0n,0n,0n], [0n,1n,0n,0n], [0n,0n,1n,0n], [0n,0n,0n,1n],
  [1n,2n,3n,4n], [4n,3n,2n,1n],
  [P-1n,P-2n,P-3n,P-4n], [P-1n,P-1n,P-1n,P-1n],
];
// Every IV state a sponge of length 0..8 constructs, so the permutation corpus covers exactly
// the inputs the sponge will hand it at each boundary.
for (let n = 0; n <= 8; n++) states.push([0n,0n,0n,BigInt(n)*TWO64]);
// One lane at each power-of-two boundary of the limb representation.
for (const s of [63,64,127,128,191,192,253]) states.push([1n<<BigInt(s),0n,0n,0n]);

let st = 88172645463325252n;
const next = () => { st ^= st << 13n; st &= (1n<<64n)-1n; st ^= st >> 7n; st ^= st << 17n; st &= (1n<<64n)-1n; return st; };
for (let i = 0; i < 20; i++) states.push([0,0,0,0].map(() => (next()*next()) % P));

const vectors = [];
for (const s of states) vectors.push({ input: s.map(String), output: await perm(s) });
// Chained: feed each output back in. A constant applied in the wrong ROUND survives a single
// permutation on some inputs and diverges once the state is iterated.
let cur = [1n,2n,3n,4n];
for (let i = 0; i < 8; i++) {
  const out = await perm(cur);
  vectors.push({ input: cur.map(String), output: out, chained: i });
  cur = out.map((h) => BigInt(h));
}
console.log(JSON.stringify({
  source: "@aztec/foundation@2.1.11 -> @aztec/bb.js BarretenbergSync.poseidon2Permutation",
  note: "state is [s0,s1,s2,s3]; rate=3, capacity index 3", vectors }, null, 2));
