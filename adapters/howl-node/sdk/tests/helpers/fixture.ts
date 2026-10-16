import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as wasmModule from "@hisoka-io/howl-client-wasm";
import type { HowlWasm } from "../../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));

export const wasm = wasmModule as unknown as HowlWasm;

export function unhex(text: string): Uint8Array {
  const digits = text.startsWith("0x") ? text.slice(2) : text;
  const out = new Uint8Array(digits.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(digits.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function fixtureFile(name: string): Uint8Array {
  return new Uint8Array(readFileSync(join(here, "..", "fixtures", name)));
}

export interface FixtureLog {
  readonly log_index: number;
  readonly address: string;
  readonly topics: string[];
  readonly data: string;
}

export interface FixtureKey {
  readonly index: number;
  readonly x: string;
  readonly even_y: boolean;
}

export interface FixtureWallet {
  readonly label: string;
  readonly sk_root: string;
  readonly sk_view: string;
  readonly self_keys: FixtureKey[];
  readonly incoming_keys: FixtureKey[];
  readonly owned_leaves: number[];
}

export interface Fixture {
  readonly chain_id: number;
  readonly pool: string;
  readonly head: number;
  readonly leaf_count: number;
  readonly root: string;
  readonly topics: Record<string, string>;
  readonly blocks: { number: number; logs: FixtureLog[] }[];
  readonly leaves: {
    leaf_index: number;
    kind: string;
    commitment: string;
    tag: string | null;
    prefix: string;
    cell: string | null;
  }[];
  readonly wallets: FixtureWallet[];
}

/** The 160-leaf chain Howl's own code produced, shared with the Rust suites. */
export const fixture: Fixture = JSON.parse(
  readFileSync(join(here, "../../../../howl/indexer/tests/vectors/chain.json"), "utf8"),
);

/** The tags a fixture wallet scans for: its even-y keys' x, own and incoming. */
export function walletTags(wallet: FixtureWallet): Uint8Array[] {
  return [...wallet.self_keys, ...wallet.incoming_keys].filter((k) => k.even_y).map((k) => unhex(k.x));
}

/** `root at count i + 1` from every `LeafInserted` of the fixture. */
export function chainRoots(): Map<number, string> {
  const roots = new Map<number, string>();
  for (const block of fixture.blocks) {
    for (const log of block.logs) {
      if (log.topics[0] !== fixture.topics.LeafInserted) continue;
      const index = Number(BigInt(log.topics[1]!));
      roots.set(index + 1, log.data.slice(2 + 64, 2 + 128));
    }
  }
  return roots;
}
