// Test-only translation of reference.py; the committed Barretenberg corpora remain the oracle.
import { readFileSync } from "node:fs";

const P = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;
const TWO64 = 1n << 64n;
const constants = JSON.parse(
  readFileSync(new URL("./yul-constants.json", import.meta.url), "utf8"),
);
const roundConstants = constants.round_constants_in_order.map(BigInt);
const diagonal = constants.repeated.map(BigInt);

const reduce = (value) => value % P;
const sbox = (value) => {
  const square = reduce(value * value);
  return reduce(square * square * value);
};

const externalMatrix = (state) => {
  const t0 = state[0] + state[1];
  const t1 = state[2] + state[3];
  const t2 = 2n * state[1] + t1;
  const t3 = 2n * state[3] + t0;
  const t4 = 4n * t1 + t3;
  const t5 = 4n * t0 + t2;
  const t6 = t3 + t5;
  const t7 = t2 + t4;
  return [reduce(t6), reduce(t5), reduce(t7), reduce(t4)];
};

const permute = (input) => {
  let state = input.map(reduce);
  state = externalMatrix(state);
  let constantIndex = 0;

  for (let round = 0; round < 4; round += 1) {
    state = state.map((value, lane) => reduce(value + roundConstants[constantIndex + lane]));
    constantIndex += 4;
    state = state.map(sbox);
    state = externalMatrix(state);
  }

  for (let round = 0; round < 56; round += 1) {
    state[0] = sbox(reduce(state[0] + roundConstants[constantIndex]));
    constantIndex += 1;
    const sum = reduce(state.reduce((total, value) => total + value, 0n));
    state = state.map((value, lane) => reduce(value * diagonal[lane] + sum));
  }

  for (let round = 0; round < 4; round += 1) {
    state = state.map((value, lane) => reduce(value + roundConstants[constantIndex + lane]));
    constantIndex += 4;
    state = state.map(sbox);
    state = externalMatrix(state);
  }

  if (constantIndex !== roundConstants.length) {
    throw new Error(`round constant count ${constantIndex} != ${roundConstants.length}`);
  }
  return state;
};

export class Fr {
  constructor(value) {
    this.value = reduce(BigInt(value));
  }

  toBuffer() {
    return Buffer.from(this.value.toString(16).padStart(64, "0"), "hex");
  }
}

export const poseidon2Permutation = async (input) => permute(input.map((field) => field.value)).map(
  (value) => new Fr(value),
);

export const poseidon2Hash = async (input) => {
  let state = [0n, 0n, 0n, reduce(BigInt(input.length) * TWO64)];
  let cache = [];
  const duplex = () => {
    cache.forEach((value, lane) => {
      state[lane] = reduce(state[lane] + value);
    });
    state = permute(state);
    cache = [];
  };

  for (const field of input) {
    if (cache.length === 3) {
      duplex();
    }
    cache.push(field.value);
  }
  duplex();
  return new Fr(state[0]);
};
