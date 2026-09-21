/** Auth-path test rig: a path-indices wasm stub and a batch encoder whose nodes carry their serving epoch. */

import {
  TREE_DEPTH,
  type ClientPirContext,
  type CommitTreeAuthPath,
  type CommitTreeProof,
  type RavenInspireWasm,
} from "../../src/index";
import { makeRegisterSpy, stubRemoteSessionExports } from "./register_spy";
import { stubQueryBundle } from "./private_wire";

export const TOKEN = "test-token-padded-long-enough-1234";
export const NODE_BYTES = 32;

function flatIndex(level: number, idxAtLevel: number): number {
  const total = 1 << (TREE_DEPTH + 1);
  return total - (1 << (TREE_DEPTH + 1 - level)) + idxAtLevel;
}

function siblingPath(leafIdx: number): Uint32Array {
  const out = new Uint32Array(TREE_DEPTH);
  let walk = leafIdx;
  for (let i = 0; i < TREE_DEPTH; i += 1) {
    out[i] = flatIndex(i, walk ^ 1);
    walk = walk >>> 1;
  }
  return out;
}

export function stubWasm(queryBytes?: Uint8Array): RavenInspireWasm {
  return {
    ...stubRemoteSessionExports(),
    build_client_session: () => ({ free: () => undefined }),
    build_seeded_query: () => stubQueryBundle(queryBytes),
    extract_response: (_session, _crs, _state, response, _entry) => new Uint8Array(response),
    build_instance_params_blob: () => new Uint8Array(0),
    register_client_session: makeRegisterSpy(),
    path_indices_for_leaf: (_tree: number, leafIdx: number): Uint32Array => siblingPath(leafIdx),
    path_indices_for_per_list_leaf: (listKey: Uint8Array, idx: number): Uint32Array => {
      if (listKey.length !== 32) {
        throw new Error("path_indices_for_per_list_leaf: list_key length must be 32");
      }
      return siblingPath(idx);
    },
  };
}

export function stubCtx(queryBytes?: Uint8Array): ClientPirContext {
  return {
    wasm: stubWasm(queryBytes),
    session: { free: () => undefined },
    crsBincode: new Uint8Array(0),
    shardConfigBincode: new Uint8Array(0),
    entrySize: NODE_BYTES,
  };
}

/**
 * The ONE test-side writer of the batch-response envelope
 * `[u16 BE version = 8][u64 LE count][{u64 LE len, bytes}*]` that
 * `decodeBatchBody` (src/raven-poi-node-interface.ts) reads. Six hand-rolled copies of
 * this shape used to live across the suite; a wire change would have left five of them
 * silently asserting a format the server no longer speaks. auth_path_stub_parity.test.ts
 * round-trips this encoder through the SDK's own decode path to pin it to the real shape.
 */
export function encodeBatchResponseNodes(nodes: readonly Uint8Array[]): Uint8Array {
  let total = 2 + 8;
  for (const n of nodes) {
    total += 8 + n.length;
  }
  const out = new Uint8Array(total);
  out[0] = 0;
  out[1] = 8;
  const dv = new DataView(out.buffer);
  dv.setUint32(2, nodes.length, true);
  dv.setUint32(6, 0, true);
  let off = 10;
  for (const n of nodes) {
    dv.setUint32(off, n.length, true);
    dv.setUint32(off + 4, 0, true);
    off += 8;
    out.set(n, off);
    off += n.length;
  }
  return out;
}

/** Byte 0 of every node carries the serving epoch, so a mixed-epoch fold shows up in `elements`. */
export function encodeBatchResponse(epoch: number, slots: number): Uint8Array {
  const nodes: Uint8Array[] = [];
  for (let slot = 0; slot < slots; slot += 1) {
    const node = new Uint8Array(NODE_BYTES);
    node[0] = epoch;
    node[NODE_BYTES - 1] = slot;
    nodes.push(node);
  }
  return encodeBatchResponseNodes(nodes);
}

/** Slot count encoded in a `[u16 BE version][u64 LE count][...]` batch body. */
export function encodedBatchCount(body: Uint8Array): number {
  const dv = new DataView(body.buffer, body.byteOffset, body.byteLength);
  return dv.getUint32(2, true);
}

export function epochMarkers(elements: string[]): string[] {
  return Array.from(new Set(elements.map((e) => e.slice(0, 2)))).sort();
}

/** Narrow a commit-tree result to its rootless auth-path arm. */
export function authPathOf(proof: CommitTreeProof): CommitTreeAuthPath {
  if (proof.kind !== "authPath") {
    throw new Error(`expected a commit-tree auth path, got kind=${proof.kind}`);
  }
  return proof;
}
