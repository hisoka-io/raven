/** A list the mock node serves on the prefix channel, and indexes built without asking one. */

import {
  BC_INDEX_PREFIX_BYTES,
  LEAVES_PER_PPOI_BLOCK,
  hexToBytes,
  type BcPrefixIndex,
  type ClientPirContext,
  type RavenInspireWasm,
} from "../../src/index";
import type { MockServer } from "./mock_server";
import { stubQueryBundle } from "./private_wire";
import { makeRegisterSpy, stubRemoteSessionExports } from "./register_spy";
import { shardConfigBincode } from "./shard_config";

const QUERY_BYTES = 64;

/** Mutable, so a test can append rows between two calls. */
export interface MockList {
  commitments: string[];
  epoch?: number;
  /** Answer every prefix request with this status instead of rows. */
  failStatus?: number;
}

/** Same segmentation as the server: sealed block segments carry only their cursor, the frontier
 *  carries the list's total and epoch, and a cursor past the frontier is a 416. */
export function mountPrefixChannel(server: MockServer, listKeyHex: string, list: MockList): void {
  server.route(
    (req) => (req.url ?? "").startsWith(`/v1/poi/${listKeyHex}/bc-prefixes`),
    (req, _body, res) => {
      if (list.failStatus !== undefined) {
        res.writeHead(list.failStatus, { "content-type": "text/plain" });
        res.end("refused");
        return true;
      }
      const since = Number(new URL(req.url ?? "", "http://mock.invalid").searchParams.get("since"));
      const total = list.commitments.length;
      if (since > total) {
        res.writeHead(416, {
          "x-raven-index-total": String(total),
          "x-raven-index-epoch": String(list.epoch ?? 0),
        });
        res.end();
        return true;
      }
      const blockEnd = (Math.floor(since / LEAVES_PER_PPOI_BLOCK) + 1) * LEAVES_PER_PPOI_BLOCK;
      const next = Math.min(blockEnd, total);
      const body = new Uint8Array((next - since) * BC_INDEX_PREFIX_BYTES);
      for (let row = since; row < next; row += 1) {
        body.set(
          hexToBytes(list.commitments[row]).subarray(0, BC_INDEX_PREFIX_BYTES),
          (row - since) * BC_INDEX_PREFIX_BYTES,
        );
      }
      const headers: Record<string, string> = {
        "content-type": "application/octet-stream",
        "x-raven-index-base": String(since),
        "x-raven-index-next": String(next),
      };
      if (next !== blockEnd) {
        headers["x-raven-index-total"] = String(total);
        headers["x-raven-index-epoch"] = String(list.epoch ?? 0);
      }
      res.writeHead(200, headers);
      res.end(Buffer.from(body));
      return true;
    },
  );
}

/** The index a node serving `commitments` publishes, built without asking one. */
export function prefixIndexOf(commitments: readonly string[], epoch = 0): BcPrefixIndex {
  const prefixes = new Uint8Array(commitments.length * BC_INDEX_PREFIX_BYTES);
  commitments.forEach((bc, row) => {
    prefixes.set(hexToBytes(bc).subarray(0, BC_INDEX_PREFIX_BYTES), row * BC_INDEX_PREFIX_BYTES);
  });
  return { epoch, prefixes, total: commitments.length };
}

/** A context whose every query names its target, so the mock can answer per index. */
export function targetNamingCtx(entrySize = 32): ClientPirContext {
  const wasm: RavenInspireWasm = {
    ...stubRemoteSessionExports(),
    build_client_session: () => ({ free: () => undefined }),
    build_seeded_query: (_session, _shards, target) => {
      const query = new Uint8Array(QUERY_BYTES).fill(0x5a);
      new DataView(query.buffer).setBigUint64(0, BigInt(target), true);
      return stubQueryBundle(query);
    },
    extract_response: (_s, _c, _st, response, _e) => new Uint8Array(response),
    build_instance_params_blob: () => new Uint8Array(0),
    register_client_session: makeRegisterSpy(),
  };
  return {
    wasm,
    session: { free: () => undefined },
    crsBincode: new Uint8Array(0),
    shardConfigBincode: shardConfigBincode(),
    entrySize,
  };
}

/** Targets of a batch built by `targetNamingCtx`, in slot order. */
export function batchTargets(body: Uint8Array): number[] {
  const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
  const count = view.getUint32(2, true);
  const out: number[] = [];
  for (let slot = 0; slot < count; slot += 1) {
    out.push(Number(view.getBigUint64(10 + slot * QUERY_BYTES, true)));
  }
  return out;
}

/** Distinct 32-byte commitments below the BN254 modulus, with distinct six-byte prefixes. */
export function commitmentAt(seed: number): string {
  return `10${seed.toString(16).padStart(10, "0")}${"ab".repeat(26)}`;
}

/** A second commitment sharing `commitmentAt(seed)`'s prefix and nothing after it. */
export function prefixTwinOf(seed: number): string {
  return `10${seed.toString(16).padStart(10, "0")}${"cd".repeat(26)}`;
}

/** Filler rows start 0xfffe, a prefix no commitment below the BN254 modulus can carry. */
function fillerPrefix(row: number): Uint8Array {
  return new Uint8Array([0xff, 0xfe, row >>> 24, (row >>> 16) & 0xff, (row >>> 8) & 0xff, row & 0xff]);
}

/** An index of `total` rows holding each commitment at its index and filler everywhere else. */
export function indexHolding(
  placed: readonly (readonly [string, number])[],
  total = Math.max(0, ...placed.map(([, idx]) => idx + 1)),
): BcPrefixIndex {
  const prefixes = new Uint8Array(total * BC_INDEX_PREFIX_BYTES);
  for (let row = 0; row < total; row += 1) {
    prefixes.set(fillerPrefix(row), row * BC_INDEX_PREFIX_BYTES);
  }
  for (const [bc, idx] of placed) {
    prefixes.set(hexToBytes(bc).subarray(0, BC_INDEX_PREFIX_BYTES), idx * BC_INDEX_PREFIX_BYTES);
  }
  return { epoch: 0, prefixes, total };
}

/** The commitments of an index built by `indexHolding`, filler included, for a mock channel. */
export function listHolding(
  placed: readonly (readonly [string, number])[],
  total = Math.max(0, ...placed.map(([, idx]) => idx + 1)),
): string[] {
  const rows = Array.from({ length: total }, (_unused, row) =>
    Buffer.from(fillerPrefix(row)).toString("hex").padEnd(64, "0"),
  );
  for (const [bc, idx] of placed) rows[idx] = bc.replace(/^0x/i, "").toLowerCase();
  return rows;
}
