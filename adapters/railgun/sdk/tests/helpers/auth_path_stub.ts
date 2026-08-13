/** Auth-path test rig: a path-indices wasm stub and a batch encoder whose nodes carry their serving epoch. */

import {
  TREE_DEPTH,
  type ClientPirContext,
  type CommitTreeAuthPath,
  type CommitTreeProof,
  type RavenInspireWasm,
} from "../../src/index";

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

export function stubWasm(): RavenInspireWasm {
  return {
    build_client_session: () => ({ free: () => undefined }),
    build_seeded_query: () => new Uint8Array(16),
    extract_response: (_session, _crs, _state, response, _entry) => new Uint8Array(response),
    build_instance_params_blob: () => new Uint8Array(0),
    register_client_session: () => {},
    path_indices_for_leaf: (_tree: number, leafIdx: number): Uint32Array => siblingPath(leafIdx),
    path_indices_for_per_list_leaf: (listKey: Uint8Array, idx: number): Uint32Array => {
      if (listKey.length !== 32) {
        throw new Error("path_indices_for_per_list_leaf: list_key length must be 32");
      }
      return siblingPath(idx);
    },
  };
}

export function stubCtx(): ClientPirContext {
  return {
    wasm: stubWasm(),
    session: { free: () => undefined },
    crsBincode: new Uint8Array(0),
    shardConfigBincode: new Uint8Array(0),
    entrySize: NODE_BYTES,
  };
}

/** Byte 0 of every node carries the serving epoch, so a mixed-epoch fold shows up in `elements`. */
export function encodeBatchResponse(epoch: number, slots: number): Uint8Array {
  const out = new Uint8Array(2 + 8 + slots * (8 + NODE_BYTES));
  out[1] = 1;
  const dv = new DataView(out.buffer);
  dv.setUint32(2, slots, true);
  let off = 10;
  for (let slot = 0; slot < slots; slot += 1) {
    dv.setUint32(off, NODE_BYTES, true);
    off += 8;
    out[off] = epoch;
    out[off + NODE_BYTES - 1] = slot;
    off += NODE_BYTES;
  }
  return out;
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
