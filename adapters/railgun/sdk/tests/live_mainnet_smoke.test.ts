/**
 * Live mainnet PIR smoke test.
 *
 * Exercises the full end-to-end flow against a deployed Raven adapter
 * and the live Ethereum mainnet `RailgunSmartWallet` proxy:
 *
 *   1. Fetch `/v1/instance/<id>/params` (server's bincode envelope)
 *      and decode it into `crsBincode`, `shardConfigBincode`, and
 *      `inspireParamsBincode`.
 *   2. Build a real WASM client session via
 *      `build_instance_params_blob` + `build_client_session`.
 *   3. Issue a `getMerkleProof` (T3) auth-path PIR query against the
 *      live commit-tree instance.
 *   4. Decrypt the 16 sibling node hashes with `extract_response`.
 *   5. Fold the leaf with the path via Poseidon to recover the root.
 *   6. Cross-validate the recovered root against on-chain
 *      `RailgunSmartWallet.rootHistory(treeNumber, root)` via Infura.
 *
 * Gated entirely behind `RAVEN_LIVE_URL` + `RAVEN_LIVE_TOKEN` +
 * `RAVEN_INFURA_URL` (mainnet RPC for the on-chain root cross-check) env
 * vars. When any is unset (the CI default), every block is `it.skip(...)`'d
 * so this test never makes network calls in offline lanes.
 */

import { afterAll, describe, expect, it } from "vitest";

import * as wasmPkg from "raven-inspire-client-wasm";

import {
  RavenPOINodeInterface,
  type ClientPirContext,
  type RavenInspireWasm,
  TREE_DEPTH,
  foldMerkleRoot,
} from "../src/index";
import { RavenError } from "../src/errors";
import { decodeClientPirQueryBundle } from "../src/client-pir";

const LIVE_URL = process.env.RAVEN_LIVE_URL;
const LIVE_TOKEN = process.env.RAVEN_LIVE_TOKEN;
const INFURA_URL = process.env.RAVEN_INFURA_URL ?? "";
const RAILGUN_PROXY = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9";
const CHAIN_ID = 1;

const RUN_LIVE =
  LIVE_URL !== undefined && LIVE_TOKEN !== undefined && INFURA_URL !== "";
const liveIt = RUN_LIVE ? it : it.skip;

const PARAMS_DOWNLOAD_TIMEOUT_MS = 240_000;
const TEST_TIMEOUT_MS = 600_000;

interface DecodedInstanceParams {
  wireSchemaVersion: number;
  crsBincode: Uint8Array;
  shardConfigBincode: Uint8Array;
  inspireParamsBincode: Uint8Array;
  entrySize: number;
  variant: string;
  epoch: bigint;
}

function readU64LE(view: DataView, offset: number): number {
  const lo = view.getUint32(offset, true);
  const hi = view.getUint32(offset + 4, true);
  if (hi !== 0) {
    throw new Error(`readU64LE: payload exceeds 2^32 (hi=${hi}) at offset ${offset}`);
  }
  return lo;
}

function readByteVec(buf: Uint8Array, offset: number): { value: Uint8Array; next: number } {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const len = readU64LE(view, offset);
  const start = offset + 8;
  const end = start + len;
  if (end > buf.length) {
    throw new Error(
      `readByteVec: truncated (need ${end}, have ${buf.length}) at offset ${offset}`,
    );
  }
  return {
    value: new Uint8Array(buf.subarray(start, end)),
    next: end,
  };
}

function readString(buf: Uint8Array, offset: number): { value: string; next: number } {
  const inner = readByteVec(buf, offset);
  return {
    value: new TextDecoder().decode(inner.value),
    next: inner.next,
  };
}

/**
 * Decode the `/v1/instance/:id/params` response. Wire shape (mirrors
 * `raven-railgun-http::InstanceParams` plus the `write_versioned`
 * envelope at the front):
 *
 *   [u16 BE  schema_version]
 *   [u16 LE  wire_schema_version]
 *   [u64 LE  crs_bincode.len]      [crs_bincode bytes]
 *   [u64 LE  shard_config.len]     [shard_config bytes]
 *   [u64 LE  inspire_params.len]   [inspire_params bytes]
 *   [u64 LE  entry_size]
 *   [u64 LE  variant.len]          [variant utf-8]
 *   [u64 LE  epoch]
 */
function decodeInstanceParams(buf: Uint8Array): DecodedInstanceParams {
  if (buf.length < 4) {
    throw new Error(`decodeInstanceParams: too short (${buf.length})`);
  }
  const envelopeView = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const envelope = (envelopeView.getUint8(0) << 8) | envelopeView.getUint8(1);
  if (envelope !== 1) {
    throw new Error(`decodeInstanceParams: unexpected envelope version ${envelope}`);
  }
  let off = 2;
  const wireSchemaVersion = envelopeView.getUint16(off, true);
  off += 2;
  const crs = readByteVec(buf, off);
  off = crs.next;
  const shard = readByteVec(buf, off);
  off = shard.next;
  const inspire = readByteVec(buf, off);
  off = inspire.next;
  const entrySize = readU64LE(envelopeView, off);
  off += 8;
  const variant = readString(buf, off);
  off = variant.next;
  if (off + 8 > buf.length) {
    throw new Error(`decodeInstanceParams: truncated trailing epoch (off=${off})`);
  }
  const epochLo = envelopeView.getUint32(off, true);
  const epochHi = envelopeView.getUint32(off + 4, true);
  const epoch = (BigInt(epochHi) << 32n) | BigInt(epochLo);
  return {
    wireSchemaVersion,
    crsBincode: crs.value,
    shardConfigBincode: shard.value,
    inspireParamsBincode: inspire.value,
    entrySize,
    variant: variant.value,
    epoch,
  };
}

interface InstanceBundle {
  decoded: DecodedInstanceParams;
  context: ClientPirContext;
  fetchMs: number;
}

const wasm = wasmPkg as unknown as RavenInspireWasm;
// Install the Rust panic hook so any panic surfaces as a structured
// JS Error with the original Rust file:line:msg, rather than the
// opaque `RuntimeError: unreachable executed` that obliterates all
// diagnostic context. Without this, every internal raven-inspire
// panic looks identical to the wallet.
const wasmInit = wasmPkg as unknown as { init_panic_hook?: () => void };
if (typeof wasmInit.init_panic_hook === "function") {
  wasmInit.init_panic_hook();
}

async function fetchInstanceParams(
  endpoint: string,
  token: string,
  instanceId: string,
): Promise<InstanceBundle> {
  const start = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), PARAMS_DOWNLOAD_TIMEOUT_MS);
  let res: Response;
  try {
    res = await fetch(`${endpoint}/v1/instance/${instanceId}/params`, {
      headers: { authorization: `Bearer ${token}` },
      signal: ctrl.signal,
    });
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    throw new Error(
      `fetchInstanceParams(${instanceId}): HTTP ${res.status} ${res.statusText}`,
    );
  }
  const body = new Uint8Array(await res.arrayBuffer());
  const fetchMs = Date.now() - start;
  const decoded = decodeInstanceParams(body);
  const paramsBundle = wasm.build_instance_params_blob(
    decoded.inspireParamsBincode,
    decoded.shardConfigBincode,
  );
  const session = wasm.build_client_session(paramsBundle, decoded.crsBincode);
  const context: ClientPirContext = {
    wasm,
    session,
    crsBincode: decoded.crsBincode,
    shardConfigBincode: decoded.shardConfigBincode,
    entrySize: decoded.entrySize,
  };
  return { decoded, context, fetchMs };
}

function bytesToHexNoPrefix(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 1) {
    s += bytes[i].toString(16).padStart(2, "0");
  }
  return s;
}

interface JsonRpcResponse<T> {
  jsonrpc: "2.0";
  id: number;
  result?: T;
  error?: { code: number; message: string };
}

async function ethCall(
  rpc: string,
  to: string,
  data: string,
  blockTag: string = "latest",
): Promise<string> {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "eth_call",
    params: [{ to, data }, blockTag],
  });
  const res = await fetch(rpc, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });
  if (!res.ok) {
    throw new Error(`eth_call: HTTP ${res.status}`);
  }
  const json = (await res.json()) as JsonRpcResponse<string>;
  if (json.error) {
    throw new Error(`eth_call: ${json.error.message}`);
  }
  if (typeof json.result !== "string") {
    throw new Error(`eth_call: missing result`);
  }
  return json.result;
}

/**
 * Encode a call to `rootHistory(uint256 treeNumber, bytes32 root)`.
 *
 * Selector = first 4 bytes of keccak256("rootHistory(uint256,bytes32)").
 * Verified locally via `cast sig 'rootHistory(uint256,bytes32)'`. The
 * mapping shape is `mapping(uint256 => mapping(bytes32 => bool)) public
 * rootHistory` (Solidity auto-getter) at upstream
 * `contract/contracts/logic/Commitments.sol:58`.
 */
const ROOT_HISTORY_SELECTOR = "0xc718dbda";

function encodeRootHistoryCall(treeNumber: number, rootHexNoPrefix: string): string {
  const treeHex = BigInt(treeNumber).toString(16).padStart(64, "0");
  const rootHex = rootHexNoPrefix.padStart(64, "0").toLowerCase();
  return `${ROOT_HISTORY_SELECTOR}${treeHex}${rootHex}`;
}

async function rootHistoryContains(
  rpc: string,
  treeNumber: number,
  rootHexNoPrefix: string,
): Promise<boolean> {
  const data = encodeRootHistoryCall(treeNumber, rootHexNoPrefix);
  const result = await ethCall(rpc, RAILGUN_PROXY, data);
  // Result is 32 bytes hex. `true` = 0x...01, `false` = 0x...00.
  return /[1-9a-f]/.test(result.replace(/^0x/, ""));
}

/**
 * Issue a single direct PIR query for a flat-global row index. Used to
 * fetch the leaf node hash itself (level-0 row in the `PerNodeEncoder`
 * layout) so the test can fold leaf+siblings → root locally without
 * relying on a separately-known BC.
 */
async function fetchSingleRow(
  endpoint: string,
  token: string,
  instanceId: string,
  ctx: ClientPirContext,
  flatIdx: number,
): Promise<Uint8Array> {
  const queryBundle = decodeClientPirQueryBundle(
    ctx.wasm.build_seeded_query(ctx.session, ctx.shardConfigBincode, BigInt(flatIdx)),
  );
  const url = `${endpoint}/v1/instance/${encodeURIComponent(instanceId)}/query`;
  // Server's `read_versioned` expects `[u16 BE schema][bincode body]`.
  // Mirrors what the SDK's `runClientPirQuery` and the Rust
  // `native_live_replay.rs` do.
  const wireBody = new Uint8Array(2 + queryBundle.queryBytes.length);
  wireBody[0] = 0;
  wireBody[1] = 1;
  wireBody.set(queryBundle.queryBytes, 2);
  // ArrayBuffer view that the WHATWG fetch impl accepts as BodyInit.
  // Some tsc targets refuse a `Uint8Array<ArrayBufferLike>`; the
  // explicit `BodyInit` cast keeps the test source portable.
  const fetchBody = wireBody as unknown as BodyInit;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/octet-stream",
      authorization: `Bearer ${token}`,
    },
    body: fetchBody,
  });
  if (!res.ok) {
    throw new Error(`fetchSingleRow(${instanceId}, flat=${flatIdx}): HTTP ${res.status}`);
  }
  const enveloped = new Uint8Array(await res.arrayBuffer());
  if (enveloped.length < 2 || ((enveloped[0] << 8) | enveloped[1]) !== 1) {
    throw new Error(
      `fetchSingleRow(${instanceId}, flat=${flatIdx}): bad response envelope`,
    );
  }
  const responseBytes = enveloped.subarray(2);
  const plaintext = ctx.wasm.extract_response(
    ctx.session,
    ctx.crsBincode,
    queryBundle.clientStateBincode,
    responseBytes,
    ctx.entrySize,
  );
  return plaintext.subarray(0, 32);
}

interface FindingsRow {
  scope: string;
  bytes: number;
  ms: number;
  rootMatch: boolean | null;
  rootHex: string;
  leafHex: string;
  notes: string;
}

const findings: FindingsRow[] = [];

function recordFinding(row: FindingsRow): void {
  findings.push(row);
}

// Module-level cache so successive tests in one run reuse downloaded
// params (each `/v1/instance/<id>/params` blob is ~35 MB).
const bundleCache = new Map<string, InstanceBundle>();

async function getInstance(instanceId: string): Promise<InstanceBundle> {
  if (!LIVE_URL || !LIVE_TOKEN) throw new Error("env guard");
  const hit = bundleCache.get(instanceId);
  if (hit) return hit;
  const fresh = await fetchInstanceParams(LIVE_URL, LIVE_TOKEN, instanceId);
  bundleCache.set(instanceId, fresh);
  return fresh;
}

describe("live mainnet PIR smoke", () => {
  if (!RUN_LIVE) {
    it.skip("requires RAVEN_LIVE_URL + RAVEN_LIVE_TOKEN env vars", () => {
      // Recorded so test runs in unset env make this fact visible.
    });
  }

  afterAll(() => {
    for (const bundle of bundleCache.values()) {
      bundle.context.session.free();
    }
    bundleCache.clear();
  });

  liveIt(
    "T3 commit-tree-0 leaf 0: PIR-derived root matches on-chain rootHistory",
    async () => {
      if (!LIVE_URL || !LIVE_TOKEN) throw new Error("env guard");
      const bundle = await getInstance("commit-tree-0");
      const sdk = new RavenPOINodeInterface({
        endpoint: LIVE_URL,
        bearerToken: LIVE_TOKEN,
        chainId: CHAIN_ID,
        useClientPir: true,
        clientPirContexts: new Map([[`t3CommitTree:${CHAIN_ID}:0`, bundle.context]]),
      });

      const leafIndex = 0;
      const t0 = Date.now();
      const proof = await sdk.getMerkleProof(0, leafIndex);
      // Independently PIR-fetch the leaf node (PerNodeEncoder level-0
      // row at flat_index=leafIndex). Required because the SDK's
      // getMerkleProof currently surfaces an empty leaf placeholder.
      const leafBytes = await fetchSingleRow(
        LIVE_URL,
        LIVE_TOKEN,
        "commit-tree-0",
        bundle.context,
        leafIndex,
      );
      const elapsed = Date.now() - t0;

      expect(proof.elements.length).toBe(TREE_DEPTH);
      for (const elem of proof.elements) {
        expect(elem.length).toBe(64);
      }
      const leafHex = bytesToHexNoPrefix(leafBytes);
      const computedRoot = foldMerkleRoot(leafHex, proof.elements, BigInt(leafIndex));
      expect(computedRoot.length).toBe(64);

      const onChain = await rootHistoryContains(INFURA_URL, 0, computedRoot);
      recordFinding({
        scope: "T3 commit-tree-0 leaf 0",
        bytes: bundle.decoded.crsBincode.length,
        ms: elapsed,
        rootMatch: onChain,
        rootHex: computedRoot,
        leafHex,
        notes: `params_fetch=${bundle.fetchMs}ms variant=${bundle.decoded.variant} epoch=${bundle.decoded.epoch}`,
      });
      // Honest-stop: surface the raw bytes rather than papering over.
      expect(onChain).toBe(true);
    },
    TEST_TIMEOUT_MS,
  );

  liveIt(
    "T3 commit-tree-3 leaf 100: PIR-derived root matches on-chain rootHistory",
    async () => {
      if (!LIVE_URL || !LIVE_TOKEN) throw new Error("env guard");
      const bundle = await getInstance("commit-tree-3");
      const sdk = new RavenPOINodeInterface({
        endpoint: LIVE_URL,
        bearerToken: LIVE_TOKEN,
        chainId: CHAIN_ID,
        useClientPir: true,
        clientPirContexts: new Map([[`t3CommitTree:${CHAIN_ID}:3`, bundle.context]]),
      });

      const leafIndex = 100;
      const t0 = Date.now();
      const proof = await sdk.getMerkleProof(3, leafIndex);
      const leafBytes = await fetchSingleRow(
        LIVE_URL,
        LIVE_TOKEN,
        "commit-tree-3",
        bundle.context,
        leafIndex,
      );
      const elapsed = Date.now() - t0;

      expect(proof.elements.length).toBe(TREE_DEPTH);
      const leafHex = bytesToHexNoPrefix(leafBytes);
      const computedRoot = foldMerkleRoot(leafHex, proof.elements, BigInt(leafIndex));

      const onChain = await rootHistoryContains(INFURA_URL, 3, computedRoot);
      recordFinding({
        scope: "T3 commit-tree-3 leaf 100",
        bytes: bundle.decoded.crsBincode.length,
        ms: elapsed,
        rootMatch: onChain,
        rootHex: computedRoot,
        leafHex,
        notes: `params_fetch=${bundle.fetchMs}ms variant=${bundle.decoded.variant} epoch=${bundle.decoded.epoch}`,
      });
      expect(onChain).toBe(true);
    },
    TEST_TIMEOUT_MS,
  );

  liveIt(
    "T1 ppoi-status-ofac architecture path: SDK preflight returns Missing for unmapped BC",
    async () => {
      if (!LIVE_URL || !LIVE_TOKEN) throw new Error("env guard");
      const bundle = await getInstance("ppoi-status-ofac");
      const listKey = "00".repeat(32);
      // Empty bc-to-idx map proves the SDK preflight short-circuits to
      // "Missing" without a wire query, exercising the T1 architecture
      // contract even when the per-list IMT is empty.
      const sdk = new RavenPOINodeInterface({
        endpoint: LIVE_URL,
        bearerToken: LIVE_TOKEN,
        chainId: CHAIN_ID,
        useClientPir: true,
        clientPirContexts: new Map([
          [`t1Status:${CHAIN_ID}:${listKey}`, bundle.context],
        ]),
        bcToIdxMaps: new Map([[`${CHAIN_ID}:${listKey}`, new Map()]]),
      });
      const bcHex = "01".padStart(64, "0");
      const t0 = Date.now();
      const got = await sdk.getPOIsPerList(
        [listKey],
        [{ blindedCommitment: bcHex, type: "Shield" }],
      );
      const elapsed = Date.now() - t0;
      expect(got[bcHex][listKey]).toBe("Missing");
      // No wire request for the BC: the bcToIdxMap miss short-circuits
      // before any HTTP call is issued.
      expect(sdk.lastWireRequests().length).toBe(0);
      recordFinding({
        scope: "T1 ppoi-status-ofac empty bcToIdxMap",
        bytes: bundle.decoded.crsBincode.length,
        ms: elapsed,
        rootMatch: null,
        rootHex: "",
        leafHex: "",
        notes: `params_fetch=${bundle.fetchMs}ms variant=${bundle.decoded.variant} epoch=${bundle.decoded.epoch}`,
      });
    },
    TEST_TIMEOUT_MS,
  );

  liveIt(
    "T2 ppoi-paths-ofac architecture path: SDK preflight throws on unmapped BC",
    async () => {
      if (!LIVE_URL || !LIVE_TOKEN) throw new Error("env guard");
      const bundle = await getInstance("ppoi-paths-ofac");
      const listKey = "00".repeat(32);
      const sdk = new RavenPOINodeInterface({
        endpoint: LIVE_URL,
        bearerToken: LIVE_TOKEN,
        chainId: CHAIN_ID,
        useClientPir: true,
        clientPirContexts: new Map([
          [`t2Path:${CHAIN_ID}:${listKey}`, bundle.context],
        ]),
        bcToIdxMaps: new Map([[`${CHAIN_ID}:${listKey}`, new Map()]]),
      });
      const bcHex = "01".padStart(64, "0");
      const t0 = Date.now();
      let threw = false;
      try {
        await sdk.getPOIMerkleProofs(listKey, [bcHex]);
      } catch (e) {
        threw = true;
        expect(RavenError.is(e, "InvalidQuery")).toBe(true);
      }
      const elapsed = Date.now() - t0;
      expect(threw).toBe(true);
      expect(sdk.lastWireRequests().length).toBe(0);
      recordFinding({
        scope: "T2 ppoi-paths-ofac empty bcToIdxMap",
        bytes: bundle.decoded.crsBincode.length,
        ms: elapsed,
        rootMatch: null,
        rootHex: "",
        leafHex: "",
        notes: `params_fetch=${bundle.fetchMs}ms variant=${bundle.decoded.variant} epoch=${bundle.decoded.epoch}`,
      });
    },
    TEST_TIMEOUT_MS,
  );

  liveIt("emits FINDINGS rows summary on stderr", () => {
    process.stderr.write("--- live PIR smoke FINDINGS ---\n");
    for (const f of findings) {
      process.stderr.write(
        `${f.scope} | bytes=${f.bytes} ms=${f.ms} match=${f.rootMatch ?? "n/a"} ` +
          `root=${f.rootHex || "-"} leaf=${f.leafHex || "-"} | ${f.notes}\n`,
      );
    }
  });
});
