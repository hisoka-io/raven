/**
 * The ONE test-side writer of the PPOI v2 path-10 served slot.
 *
 * The path-10 record changed the t2Path read from sixteen 32 B node queries to a single
 * 512 B row carrying merkle levels 0..10, with levels 11..15 riding along as a 160 B
 * cleartext addendum that `runClientPirQueryBatch` splits off the tail. That change
 * reached production without reaching the test corpus, which is why sixteen assertions
 * failed as `malformed PPOI v2 row` and several more as `query count 1, expected 16`.
 *
 * Every fixture that serves a path-10 row goes through here, so the next layout change
 * has one place to edit rather than nine.
 */

import { foldMerkleRoot } from "../../src/poseidon";
import { encodeBatchResponseNodes } from "./auth_path_stub";
import type { MockServer } from "./mock_server";

export const PATH10_ROW_BYTES = 512;
export const PATH10_ADDENDUM_BYTES = 160;
/** What one served slot weighs: the row plus the upper-sibling addendum. */
export const PATH10_SLOT_BYTES = PATH10_ROW_BYTES + PATH10_ADDENDUM_BYTES;
/** Levels 0..10 live in the row; 11..15 ride in the addendum. */
export const PATH10_ROW_LEVELS = 11;
export const PATH10_ADDENDUM_LEVELS = 5;
const NODES_OFFSET = 38;
const MAGIC = "RVP2";

/** Sixteen siblings, distinct per level, so a dropped or reordered level changes the root. */
export function path10Siblings(marker = 0xab): Uint8Array[] {
  return Array.from({ length: PATH10_ROW_LEVELS + PATH10_ADDENDUM_LEVELS }, (_u, level) => {
    const node = new Uint8Array(32);
    node[0] = marker;
    node[31] = level;
    return node;
  });
}

export interface Path10SlotOptions {
  readonly bcHex: string;
  readonly nodes: readonly Uint8Array[];
  readonly status?: number;
  readonly eventType?: number;
  /** Corrupt the magic, to prove a consumer actually checks it. */
  readonly magic?: string;
}

/** One served slot exactly as the Rust encoder lays it out. */
export function path10Slot(options: Path10SlotOptions): Uint8Array {
  const { bcHex, nodes } = options;
  if (nodes.length !== PATH10_ROW_LEVELS + PATH10_ADDENDUM_LEVELS) {
    throw new Error(`path10Slot needs 16 siblings, got ${nodes.length}`);
  }
  const row = new Uint8Array(PATH10_ROW_BYTES);
  row.set(Buffer.from(bcHex.replace(/^0x/, ""), "hex"), 0);
  row[32] = options.status ?? 0;
  row[33] = options.eventType ?? 0;
  row.set(new TextEncoder().encode(options.magic ?? MAGIC), 34);
  for (let level = 0; level < PATH10_ROW_LEVELS; level += 1) {
    row.set(nodes[level], NODES_OFFSET + level * 32);
  }
  const addendum = new Uint8Array(PATH10_ADDENDUM_BYTES);
  for (let level = 0; level < PATH10_ADDENDUM_LEVELS; level += 1) {
    addendum.set(nodes[PATH10_ROW_LEVELS + level], level * 32);
  }
  const slot = new Uint8Array(PATH10_SLOT_BYTES);
  slot.set(row, 0);
  slot.set(addendum, PATH10_ROW_BYTES);
  return slot;
}

/** The root the SDK must fold to for this (BC, siblings, local leaf index). */
export function path10Root(
  bcHex: string,
  nodes: readonly Uint8Array[],
  localIndex: number,
): string {
  return foldMerkleRoot(
    bcHex,
    nodes.map((n) => Buffer.from(n).toString("hex")),
    BigInt(localIndex),
  );
}

export interface Path10RouteOptions extends Path10SlotOptions {
  readonly epoch?: number;
  readonly schemaVersion?: number;
  readonly freshness?: string;
  readonly onHit?: () => void;
  /**
   * Restrict the route to one instance label. Commit-tree (t3) reads still serve 32 B
   * nodes on the same `/batch` path, so a suite exercising both must discriminate or the
   * first route mounted swallows the other's requests.
   */
  readonly instance?: string;
}

/** Mount a batch route serving one path-10 slot per requested query slot. */
export function mountPath10Route(server: MockServer, options: Path10RouteOptions): void {
  const pattern = options.instance
    ? new RegExp(`^/v1/instance/${options.instance}/batch$`)
    : /^\/v1\/instance\/[^/]+\/batch$/;
  server.route(
    (req) => pattern.test(req.url ?? ""),
    (_req, _body, res) => {
      options.onHit?.();
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "x-raven-epoch": String(options.epoch ?? 1),
        "x-raven-schema-version": String(options.schemaVersion ?? 7),
        "x-raven-freshness":
          options.freshness ?? "lag_blocks=0 applied_height=0 epoch=1 confidence=1",
      });
      res.end(Buffer.from(encodeBatchResponseNodes([path10Slot(options)])));
      return true;
    },
  );
}
