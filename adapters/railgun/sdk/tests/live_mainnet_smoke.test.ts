/**
 * Live mainnet smoke: params fetch -> WASM session -> auth-path PIR query ->
 * Poseidon fold -> on-chain `rootHistory` cross-check.
 *
 * Every block skips unless `RAVEN_LIVE_URL` + `RAVEN_INFURA_URL` are set, so offline
 * lanes make no network calls. `RAVEN_LIVE_TOKEN` is sent when set, for a node that
 * still gates reads.
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
import { authPathOf, encodedBatchCount } from "./helpers/auth_path_stub";
import {
  LIVE_TOKEN,
  LIVE_URL,
  PPOI_STATUS_INSTANCE,
  decodeInstanceParams,
  liveHeaders,
  ppoiPathInstance,
  stripVersionedResponse,
  versionedQueryBody,
  type DecodedInstanceParams,
} from "./helpers/live_wire";

const INFURA_URL = process.env.RAVEN_INFURA_URL ?? "";
const RAILGUN_PROXY = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9";
const CHAIN_ID = 1;

const RUN_LIVE = LIVE_URL !== undefined && INFURA_URL !== "";
const liveIt = RUN_LIVE ? it : it.skip;

const PARAMS_DOWNLOAD_TIMEOUT_MS = 240_000;
const TEST_TIMEOUT_MS = 600_000;

interface InstanceBundle {
  decoded: DecodedInstanceParams;
  context: ClientPirContext;
  fetchMs: number;
}

const wasm = wasmPkg as unknown as RavenInspireWasm;
// Without the hook every Rust panic reaches the wallet as an identical opaque
// `RuntimeError: unreachable executed`.
const wasmInit = wasmPkg as unknown as { init_panic_hook?: () => void };
if (typeof wasmInit.init_panic_hook === "function") {
  wasmInit.init_panic_hook();
}

async function fetchInstanceParams(
  endpoint: string,
  instanceId: string,
): Promise<InstanceBundle> {
  const start = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), PARAMS_DOWNLOAD_TIMEOUT_MS);
  let res: Response;
  try {
    res = await fetch(`${endpoint}/v1/instance/${instanceId}/params`, {
      headers: liveHeaders(),
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
 * Encode `rootHistory(uint256,bytes32)`; the selector is the first 4 bytes of its
 * keccak256, and the getter is auto-generated from the `mapping(uint256 =>
 * mapping(bytes32 => bool)) public rootHistory` in upstream `Commitments.sol`.
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
  return /[1-9a-f]/.test(result.replace(/^0x/, ""));
}

/** Direct PIR query for a flat-global row index, so the leaf hash itself can be
 * folded with its siblings without a separately-known BC. */
async function fetchSingleRow(
  endpoint: string,
  instanceId: string,
  ctx: ClientPirContext,
  flatIdx: number,
): Promise<Uint8Array> {
  const queryBundle = decodeClientPirQueryBundle(
    ctx.wasm.build_seeded_query(ctx.session, ctx.shardConfigBincode, BigInt(flatIdx)),
  );
  const url = `${endpoint}/v1/instance/${encodeURIComponent(instanceId)}/query`;
  // Some tsc targets refuse `Uint8Array<ArrayBufferLike>` as BodyInit.
  const fetchBody = versionedQueryBody(queryBundle.queryBytes) as unknown as BodyInit;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/octet-stream",
      ...liveHeaders(),
    },
    body: fetchBody,
  });
  if (!res.ok) {
    throw new Error(`fetchSingleRow(${instanceId}, flat=${flatIdx}): HTTP ${res.status}`);
  }
  const responseBytes = stripVersionedResponse(
    new Uint8Array(await res.arrayBuffer()),
    `fetchSingleRow(${instanceId}, flat=${flatIdx})`,
  );
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

// Each params blob is ~35 MB, so successive tests in a run reuse it.
const bundleCache = new Map<string, InstanceBundle>();

async function getInstance(instanceId: string): Promise<InstanceBundle> {
  if (!LIVE_URL) throw new Error("env guard");
  const hit = bundleCache.get(instanceId);
  if (hit) return hit;
  const fresh = await fetchInstanceParams(LIVE_URL, instanceId);
  bundleCache.set(instanceId, fresh);
  return fresh;
}

describe("live mainnet PIR smoke", () => {
  if (!RUN_LIVE) {
    // RUN_LIVE also requires RAVEN_INFURA_URL; without it the on-chain rootHistory
    // cross-check has nothing to compare against and the whole block is decoration.
    it.skip("requires RAVEN_LIVE_URL + RAVEN_INFURA_URL", () => {
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
      if (!LIVE_URL) throw new Error("env guard");
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
      const path = authPathOf(await sdk.getMerkleProof(0, leafIndex));
      // The auth path carries no leaf, so the row is fetched on its own to fold a root.
      const leafBytes = await fetchSingleRow(
        LIVE_URL,
        "commit-tree-0",
        bundle.context,
        leafIndex,
      );
      const elapsed = Date.now() - t0;

      expect(path.elements.length).toBe(TREE_DEPTH);
      for (const elem of path.elements) {
        expect(elem.length).toBe(64);
      }
      const leafHex = bytesToHexNoPrefix(leafBytes);
      const computedRoot = foldMerkleRoot(leafHex, path.elements, BigInt(leafIndex));
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
      expect(onChain).toBe(true);
    },
    TEST_TIMEOUT_MS,
  );

  liveIt(
    "T3 commit-tree-3 leaf 100: PIR-derived root matches on-chain rootHistory",
    async () => {
      if (!LIVE_URL) throw new Error("env guard");
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
      const path = authPathOf(await sdk.getMerkleProof(3, leafIndex));
      const leafBytes = await fetchSingleRow(
        LIVE_URL,
        "commit-tree-3",
        bundle.context,
        leafIndex,
      );
      const elapsed = Date.now() - t0;

      expect(path.elements.length).toBe(TREE_DEPTH);
      const leafHex = bytesToHexNoPrefix(leafBytes);
      const computedRoot = foldMerkleRoot(leafHex, path.elements, BigInt(leafIndex));

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
    `T1 ${PPOI_STATUS_INSTANCE} architecture path: SDK preflight returns MissingStale for unmapped BC`,
    async () => {
      if (!LIVE_URL) throw new Error("env guard");
      const bundle = await getInstance(PPOI_STATUS_INSTANCE);
      const listKey = "00".repeat(32);
      // An empty bc-to-idx map carries no row count, so the opt-in answers "MissingStale".
      const sdk = new RavenPOINodeInterface({
        endpoint: LIVE_URL,
        bearerToken: LIVE_TOKEN,
        chainId: CHAIN_ID,
        useClientPir: true,
        clientPirContexts: new Map([
          [`t1Status:${CHAIN_ID}:${listKey}`, bundle.context],
        ]),
        bcToIdxMaps: new Map([[`${CHAIN_ID}:${listKey}`, new Map()]]),
        indexStalenessPolicy: "answer-at-index-rows",
      });
      const bcHex = "01".padStart(64, "0");
      const t0 = Date.now();
      const got = await sdk.getPOIsPerList(
        [listKey],
        [{ blindedCommitment: bcHex, type: "Shield" }],
      );
      const elapsed = Date.now() - t0;
      expect(got[bcHex][listKey]).toBe("MissingStale");
      // Membership must not change what goes out, so an all-absent call still sends its list's
      // one-slot cover batch, and nothing else.
      const wires = sdk.lastWireRequests();
      expect(wires.length).toBeGreaterThan(0);
      for (const wire of wires) {
        expect(wire.method).toBe("POST");
        expect(wire.url).toMatch(/\/v1\/instance\/[^/]+\/batch$/);
        expect(encodedBatchCount(wire.body)).toBe(1);
      }
      recordFinding({
        scope: `T1 ${PPOI_STATUS_INSTANCE} empty bcToIdxMap`,
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
    `T2 ${ppoiPathInstance(0)} architecture path: SDK preflight throws on unmapped BC`,
    async () => {
      if (!LIVE_URL) throw new Error("env guard");
      const bundle = await getInstance(ppoiPathInstance(0));
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
        scope: `T2 ${ppoiPathInstance(0)} empty bcToIdxMap`,
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
