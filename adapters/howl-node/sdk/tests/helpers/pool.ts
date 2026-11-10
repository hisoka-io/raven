// An in-test node: one pool state and the answers a node gives for it, encoded in the wire layout.
import { randomBytes } from "node:crypto";
import { HowlError, KIND, type Exchange, type HowlTransport } from "../../src/index.js";
import { wasm } from "./fixture.js";

export const SEGMENT_ROWS = 65_536;
export const BLOCK = 1024;
export const CHAIN_BLOCK = 4_242;

function u16(v: number): number[] {
  return [(v >> 8) & 0xff, v & 0xff];
}
function u32(v: number): number[] {
  return [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff];
}
function u64(v: number): number[] {
  return [...u32(Math.floor(v / 0x1_0000_0000)), ...u32(v >>> 0)];
}

/** One pool state and the answers a node gives for it. */
export class Pool {
  readonly leaves: Uint8Array;
  readonly rows: Uint8Array;
  readonly upper: Uint8Array;
  readonly root: Uint8Array;

  /** `count` random leaves after those of `base`, when given. */
  constructor(readonly count: number, planted: Map<number, Uint8Array>, base?: Pool) {
    this.leaves = new Uint8Array(randomBytes(count * 32));
    for (let i = 0; i < count; i++) this.leaves[i * 32]! &= 0x0f;
    this.rows = new Uint8Array(randomBytes(count * 6));
    if (base !== undefined) {
      this.leaves.set(base.leaves);
      this.rows.set(base.rows);
    }
    for (const [position, prefix] of planted) this.rows.set(prefix, position * 6);
    const full = Math.floor(count / BLOCK);
    this.upper = new Uint8Array(full * 32);
    for (let b = 0; b < full; b++) {
      this.upper.set(wasm.blockNode(this.leaves.subarray(b * BLOCK * 32, (b + 1) * BLOCK * 32)), b * 32);
    }
    this.root = wasm.treeRoot(count, this.upper, this.leaves.subarray(full * BLOCK * 32));
  }

  #answer(kind: number, body: number[] | Uint8Array[]): Uint8Array {
    const head = [...u16(1), ...u16(1), kind, 0, 0, 0, ...u64(this.count), ...u64(CHAIN_BLOCK), ...this.root];
    const parts: Uint8Array[] = [Uint8Array.from(head)];
    for (const part of body) parts.push(part instanceof Uint8Array ? part : Uint8Array.from([part]));
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) {
      out.set(p, at);
      at += p.length;
    }
    return out;
  }

  /** Full block `b`, as the plaintext block route answers it. */
  block(b: number): Exchange {
    const leaves = this.leaves.subarray(b * BLOCK * 32, (b + 1) * BLOCK * 32);
    return { status: 200, body: this.#answer(KIND.block, [Uint8Array.from([...u32(b), ...u32(BLOCK)]), leaves]) };
  }

  /** The node's sync answer; `held` as the node reads it, `skip` leaves dropped by a lying node. */
  sync(since: number, upperSince: number, held = 0, skip = 0): Exchange {
    if (since > this.count || held > this.count) return { status: 409, body: this.#answer(KIND.stale, []) };
    const next = Math.min((Math.floor(since / SEGMENT_ROWS) + 1) * SEGMENT_ROWS, this.count);
    const full = Math.floor(this.count / BLOCK);
    const newest = Math.floor((this.count - 1) / BLOCK);
    const from = Math.max(held, newest * BLOCK) + skip;
    const newestLeaves = this.leaves.subarray(from * 32, this.count * 32);
    return {
      status: 200,
      body: this.#answer(KIND.sync, [
        Uint8Array.from([...u64(since), ...u64(next)]),
        this.rows.subarray(since * 6, next * 6),
        Uint8Array.from([...u64(upperSince), ...u64(full)]),
        this.upper.subarray(upperSince * 32, full * 32),
        Uint8Array.from([...u32(newest), ...u32(newestLeaves.length / 32)]),
        newestLeaves,
      ]),
    };
  }
}

/**
 * A transport over `pool` that loses the connection on the requests numbered in `drop`. A node
 * that predates `held` ignores it; a lying one drops `skip` more leaves.
 */
export function served(
  pool: Pool,
  drop: Set<number>,
  node: { ignoresHeld?: boolean; skip?: number } = {},
): HowlTransport & { paths: string[]; down: number[] } {
  const paths: string[] = [];
  const down: number[] = [];
  return {
    paths,
    down,
    get: async (path) => {
      paths.push(path);
      if (drop.has(paths.length)) throw new HowlError("Network", `GET ${path}: connection reset`);
      const b = /^\/howl\/v1\/block\/(\d+)$/.exec(path);
      if (b !== null) return pool.block(Number(b[1]));
      const m = /^\/howl\/v1\/sync\?since=(\d+)&upper=(\d+)(?:&held=(\d+))?$/.exec(path);
      if (m === null) throw new Error(`unexpected ${path}`);
      const held = node.ignoresHeld === true ? 0 : Number(m[3] ?? 0);
      const ex = pool.sync(Number(m[1]), Number(m[2]), held, node.skip ?? 0);
      down.push(ex.body.length);
      return ex;
    },
    post: async (path) => {
      throw new Error(`unexpected POST ${path}`);
    },
  };
}

