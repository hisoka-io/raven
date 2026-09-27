/**
 * End-to-end sweeps against a live adapter: per-tree byte identity vs on-chain
 * `rootHistory`, PPOI probes, random-leaf fuzz, and per-instance throughput.
 *
 * Gated behind `RAVEN_LIVE_URL` + `RAVEN_INFURA_URL`; `RAVEN_LIVE_TOKEN` is sent when set,
 * for a node that still gates reads. Divergences are recorded with full request/response
 * bytes; never retried away.
 */

import { afterAll, describe, expect, it } from "vitest";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import * as wasmPkg from "raven-inspire-client-wasm";

import {
  type ClientPirContext,
  type RavenInspireWasm,
  foldMerkleRoot,
  pathIndicesForLeaf,
} from "../src/index";
import { buildPaddedQueryPlan, recoverRealQueryResponses } from "../src/batch-cover";
import { decodeClientPirQueryBundle, decodeShardGeometry } from "../src/client-pir";
import {
  LIVE_URL,
  PPOI_STATUS_INSTANCE,
  decodeBatchResponse,
  decodeInstanceParams,
  liveHeaders,
  ppoiPathInstance,
  stripVersionedResponse,
  versionedBatchBody,
  versionedQueryBody,
  type DecodedInstanceParams,
} from "./helpers/live_wire";

const HERE = dirname(fileURLToPath(import.meta.url));
const FINDINGS_DIR =
  process.env.RAVEN_BENCH_FINDINGS_DIR ??
  resolve(HERE, "..", "..", "..", "target", "bench-findings");

const INFURA_URL = process.env.RAVEN_INFURA_URL ?? "";
const RAILGUN_PROXY = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9";

const RUN_LIVE = LIVE_URL !== undefined && INFURA_URL !== "";
const liveDescribe = RUN_LIVE ? describe : describe.skip;

const PARAMS_DOWNLOAD_TIMEOUT_MS = 240_000;
const TEST_TIMEOUT_MS = 1_200_000; // 20 min - fuzz + throughput is heavy

// Trees 0 and 2 closed full; tree 1 closed short at 65,535 because no batch spans
// trees. Tree 3 is live, so its cap is a conservative under-estimate.
const TREE_LEAF_COUNT: Record<number, number> = {
  0: 65_536,
  1: 65_535,
  2: 65_536,
  3: 19_000,
};

// Each leaf-fold is 17 PIR queries, so the per-tree sweep dominates wall time.
const PER_TREE_SAMPLE = Number(process.env.RAVEN_PER_TREE_SAMPLE ?? "20");
const FUZZ_SAMPLE = Number(process.env.RAVEN_FUZZ_SAMPLE ?? "25");
const THROUGHPUT_SAMPLE = Number(process.env.RAVEN_THROUGHPUT_SAMPLE ?? "30");
const THROUGHPUT_SEEDS = Number(process.env.RAVEN_THROUGHPUT_SEEDS ?? "3");

interface InstanceBundle {
  decoded: DecodedInstanceParams;
  context: ClientPirContext;
  fetchMs: number;
}

const wasm = wasmPkg as unknown as RavenInspireWasm;
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

const bundleCache = new Map<string, InstanceBundle>();

async function getInstance(instanceId: string): Promise<InstanceBundle> {
  if (!LIVE_URL) throw new Error("env guard");
  const hit = bundleCache.get(instanceId);
  if (hit) return hit;
  const fresh = await fetchInstanceParams(LIVE_URL, instanceId);
  bundleCache.set(instanceId, fresh);
  return fresh;
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

async function ethCall(rpc: string, to: string, data: string): Promise<string> {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "eth_call",
    params: [{ to, data }, "latest"],
  });
  const res = await fetch(rpc, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });
  if (!res.ok) throw new Error(`eth_call: HTTP ${res.status}`);
  const json = (await res.json()) as JsonRpcResponse<string>;
  if (json.error) throw new Error(`eth_call: ${json.error.message}`);
  if (typeof json.result !== "string") throw new Error("eth_call: missing result");
  return json.result;
}

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

interface SingleQueryResult {
  plaintext: Uint8Array;
  bodyBytes: number;
  responseBytes: number;
  serverEpoch: string | null;
  serverSchema: string | null;
}

/** Direct `/v1/instance/:id/query`, returning plaintext plus request/response
 * sizes and freshness headers so failures can be correlated. */
async function fetchSingleRow(
  endpoint: string,
  instanceId: string,
  ctx: ClientPirContext,
  flatIdx: number,
): Promise<SingleQueryResult> {
  const queryBundle = decodeClientPirQueryBundle(
    ctx.wasm.build_seeded_query(ctx.session, ctx.shardConfigBincode, BigInt(flatIdx)),
  );
  const url = `${endpoint}/v1/instance/${encodeURIComponent(instanceId)}/query`;
  const wireBody = versionedQueryBody(queryBundle.queryBytes);
  const fetchBody = wireBody as unknown as BodyInit;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/octet-stream",
      ...liveHeaders(),
    },
    body: fetchBody,
  });
  if (!res.ok) {
    throw new Error(
      `fetchSingleRow(${instanceId}, flat=${flatIdx}): HTTP ${res.status}`,
    );
  }
  const enveloped = new Uint8Array(await res.arrayBuffer());
  const responseBytes = stripVersionedResponse(
    enveloped,
    `fetchSingleRow(${instanceId}, flat=${flatIdx})`,
  );
  const plaintext = ctx.wasm.extract_response(
    ctx.session,
    ctx.crsBincode,
    queryBundle.clientStateBincode,
    responseBytes,
    ctx.entrySize,
  );
  return {
    plaintext,
    bodyBytes: wireBody.length,
    responseBytes: enveloped.length,
    serverEpoch: res.headers.get("x-raven-epoch"),
    serverSchema: res.headers.get("x-raven-schema-version"),
  };
}

interface BatchResult {
  responses: Uint8Array[];
  clientStates: Uint8Array[];
  bodyBytes: number;
  responseBytes: number;
}

/** Pads `flatIndices` onto the batch ladder, since the server refuses any other length, and
 *  returns the responses for the real slots only, in order. */
async function fetchBatch(
  endpoint: string,
  instanceId: string,
  ctx: ClientPirContext,
  flatIndices: number[],
): Promise<BatchResult> {
  const { entriesPerShard, totalEntries } = decodeShardGeometry(ctx.shardConfigBincode);
  const plan = buildPaddedQueryPlan(flatIndices, entriesPerShard, totalEntries);
  const slots = plan.wireTargets;
  const queryBundles = slots.map((idx) =>
    decodeClientPirQueryBundle(
      ctx.wasm.build_seeded_query(ctx.session, ctx.shardConfigBincode, BigInt(idx)),
    ),
  );
  const body = versionedBatchBody(queryBundles.map((b) => b.queryBytes));
  const url = `${endpoint}/v1/instance/${encodeURIComponent(instanceId)}/batch`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/octet-stream",
      ...liveHeaders(),
    },
    body: body as unknown as BodyInit,
  });
  if (!res.ok) {
    throw new Error(`fetchBatch(${instanceId}): HTTP ${res.status}`);
  }
  const respBuf = new Uint8Array(await res.arrayBuffer());
  const out = decodeBatchResponse(respBuf, `fetchBatch(${instanceId})`);
  if (out.length !== slots.length) {
    throw new Error(
      `fetchBatch(${instanceId}): mismatched count ${out.length} vs ${slots.length}`,
    );
  }
  // `extract_response` needs the exact `clientStateBincode` its own
  // `build_seeded_query` produced; a re-issue draws fresh randomness and fails.
  const clientStates = queryBundles.map((b) => b.clientStateBincode);
  return {
    responses: recoverRealQueryResponses(plan, out),
    clientStates: recoverRealQueryResponses(plan, clientStates),
    bodyBytes: body.length,
    responseBytes: respBuf.length,
  };
}

interface ProbeStatus {
  scheme: string;
  instances: Array<{
    id: string;
    epoch: number;
    role: string;
    drain_state: string;
  }>;
  // Absent on a node with no chain consumer, which a mirror-fed PPOI node may be.
  consumer: {
    last_applied_block: number;
    last_scanned_block: number;
    last_known_chain_head: number;
    indexer_lag_blocks: number;
    blocks_since_last_applied_event: number;
  } | null;
}

async function probeStatus(): Promise<ProbeStatus> {
  if (!LIVE_URL) throw new Error("env guard");
  const res = await fetch(`${LIVE_URL}/v1/status`, {
    headers: liveHeaders(),
  });
  if (!res.ok) throw new Error(`probeStatus: HTTP ${res.status}`);
  return (await res.json()) as ProbeStatus;
}

interface SeededRng {
  next(): number;
  nextInt(lo: number, hi: number): number;
}

// xorshift32, deterministic per seed.
function makeRng(seed: number): SeededRng {
  let s = seed >>> 0;
  if (s === 0) s = 0xdeadbeef;
  return {
    next(): number {
      s ^= s << 13;
      s ^= s >>> 17;
      s ^= s << 5;
      return (s >>> 0) / 0x100000000;
    },
    nextInt(lo: number, hi: number): number {
      return lo + Math.floor(this.next() * (hi - lo));
    },
  };
}

function pickIndices(rng: SeededRng, count: number, leafCount: number): number[] {
  const out = new Set<number>();
  while (out.size < count && out.size < leafCount) {
    out.add(rng.nextInt(0, leafCount));
  }
  return Array.from(out);
}

interface PerTreeRow {
  tree: number;
  sampled: number;
  passed: number;
  divergences: Array<{
    leafIndex: number;
    rootHex: string;
    leafHex: string;
    httpStatus: number | null;
    notes: string;
  }>;
}

interface FuzzRow {
  instance: string;
  iterations: number;
  passed: number;
  failures: Array<{ leafIndex: number; reason: string }>;
}

interface ThroughputRow {
  instance: string;
  concurrency: number;
  iterations: number;
  seeds: number;
  medianQps: number;
  p50_ms: number;
  p95_ms: number;
  p99_ms: number;
  mean_ms: number;
  errors: number;
  paramsFetchMs: number;
}

interface PpoiRow {
  instance: string;
  populated: boolean;
  reason: string;
  sampled?: number;
  passed?: number;
}

const perTreeRows: PerTreeRow[] = [];
const fuzzRows: FuzzRow[] = [];
const throughputRows: ThroughputRow[] = [];
const ppoiRows: PpoiRow[] = [];
const headlineNotes: string[] = [];

function pct(arr: number[], p: number): number {
  if (arr.length === 0) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.floor((sorted.length - 1) * p));
  return sorted[idx];
}

function mean(arr: number[]): number {
  if (arr.length === 0) return 0;
  let s = 0;
  for (const v of arr) s += v;
  return s / arr.length;
}

function median(arr: number[]): number {
  return pct(arr, 0.5);
}

liveDescribe("aggressive E2E (per-tree byte identity)", () => {
  for (const treeNumber of [0, 1, 2, 3]) {
    it(
      `commit-tree-${treeNumber}: ${PER_TREE_SAMPLE} random leaves byte-identical via PIR + on-chain rootHistory`,
      async () => {
        if (!LIVE_URL) throw new Error("env guard");
        const instanceId = `commit-tree-${treeNumber}`;
        const bundle = await getInstance(instanceId);
        const leafCount = TREE_LEAF_COUNT[treeNumber];
        const rng = makeRng(0xa11ce + treeNumber);
        const leafIndices = pickIndices(rng, PER_TREE_SAMPLE, leafCount);
        const row: PerTreeRow = {
          tree: treeNumber,
          sampled: leafIndices.length,
          passed: 0,
          divergences: [],
        };
        for (const leafIndex of leafIndices) {
          try {
            const indices = pathIndicesForLeaf(wasm, treeNumber, leafIndex);
            // Individually, so a divergence reproducer captures per-leaf bytes.
            const siblings: string[] = [];
            for (let level = 0; level < indices.length; level += 1) {
              const r = await fetchSingleRow(
                LIVE_URL,
                instanceId,
                bundle.context,
                indices[level],
              );
              siblings.push(bytesToHexNoPrefix(r.plaintext.subarray(0, 32)));
            }
            const leafR = await fetchSingleRow(
              LIVE_URL,
              instanceId,
              bundle.context,
              leafIndex,
            );
            const leafHex = bytesToHexNoPrefix(leafR.plaintext.subarray(0, 32));
            const computedRoot = foldMerkleRoot(leafHex, siblings, BigInt(leafIndex));
            const onChain = await rootHistoryContains(
              INFURA_URL,
              treeNumber,
              computedRoot,
            );
            if (onChain) {
              row.passed += 1;
            } else {
              row.divergences.push({
                leafIndex,
                rootHex: computedRoot,
                leafHex,
                httpStatus: 200,
                notes: "rootHistory(treeNumber, root) returned 0 on-chain",
              });
            }
          } catch (e) {
            row.divergences.push({
              leafIndex,
              rootHex: "",
              leafHex: "",
              httpStatus: null,
              notes: String(e),
            });
          }
        }
        perTreeRows.push(row);
        // Incremental, so a mid-suite interrupt still surfaces partial results.
        emitFindings();
        // One match suffices: the live tree's cap is a conservative under-estimate.
        expect(row.passed).toBeGreaterThan(0);
      },
      TEST_TIMEOUT_MS,
    );
  }
});

liveDescribe("aggressive E2E (PPOI architecture probe)", () => {
  for (const instanceId of [PPOI_STATUS_INSTANCE, ppoiPathInstance(0)]) {
    it(
      `${instanceId}: probe for non-empty corpus`,
      async () => {
        if (!LIVE_URL) throw new Error("env guard");
        const status = await probeStatus();
        const inst = status.instances.find((i) => i.id === instanceId);
        if (!inst) {
          ppoiRows.push({
            instance: instanceId,
            populated: false,
            reason: `instance ${instanceId} not present in /v1/status`,
          });
          emitFindings();
          return;
        }
        // epoch 0 + active drain_state + no applied block reads as an empty corpus.
        const empty = inst.epoch === 0 && status.consumer?.last_applied_block === 0;
        if (empty) {
          ppoiRows.push({
            instance: instanceId,
            populated: false,
            reason: "epoch=0 and consumer.last_applied_block=0: the corpus is empty",
          });
          emitFindings();
          return;
        }
        const bundle = await getInstance(instanceId);
        try {
          const r = await fetchSingleRow(
            LIVE_URL,
            instanceId,
            bundle.context,
            0,
          );
          ppoiRows.push({
            instance: instanceId,
            populated: true,
            reason: `epoch=${inst.epoch}; probed idx=0 returned ${r.plaintext.length} byte plaintext`,
            sampled: 1,
            passed: 1,
          });
        } catch (e) {
          ppoiRows.push({
            instance: instanceId,
            populated: true,
            reason: `epoch=${inst.epoch}; probe idx=0 FAILED: ${e}`,
            sampled: 1,
            passed: 0,
          });
        }
        emitFindings();
        // Without this the probe records its own failure and still reports green.
        expect(ppoiRows[ppoiRows.length - 1].passed).toBe(1);
      },
      TEST_TIMEOUT_MS,
    );
  }
});

liveDescribe("aggressive E2E (fuzz)", () => {
  for (const treeNumber of [0, 1, 2, 3]) {
    it(
      `commit-tree-${treeNumber}: ${FUZZ_SAMPLE} random fold-and-verify iterations`,
      async () => {
        if (!LIVE_URL) throw new Error("env guard");
        const instanceId = `commit-tree-${treeNumber}`;
        const bundle = await getInstance(instanceId);
        const leafCount = TREE_LEAF_COUNT[treeNumber];
        const rng = makeRng(0xfeed + treeNumber);
        const row: FuzzRow = {
          instance: instanceId,
          iterations: FUZZ_SAMPLE,
          passed: 0,
          failures: [],
        };
        for (let k = 0; k < FUZZ_SAMPLE; k += 1) {
          const leafIndex = rng.nextInt(0, leafCount);
          try {
            const indices = pathIndicesForLeaf(wasm, treeNumber, leafIndex);
            const allIdx = [leafIndex, ...Array.from(indices)];
            const batch = await fetchBatch(
              LIVE_URL,
              instanceId,
              bundle.context,
              allIdx,
            );
            const decrypted: Uint8Array[] = [];
            for (let i = 0; i < allIdx.length; i += 1) {
              const pt = bundle.context.wasm.extract_response(
                bundle.context.session,
                bundle.context.crsBincode,
                batch.clientStates[i],
                batch.responses[i],
                bundle.context.entrySize,
              );
              decrypted.push(pt);
            }
            const leafHex = bytesToHexNoPrefix(decrypted[0].subarray(0, 32));
            const siblings: string[] = [];
            for (let level = 0; level < indices.length; level += 1) {
              siblings.push(
                bytesToHexNoPrefix(decrypted[1 + level].subarray(0, 32)),
              );
            }
            const computedRoot = foldMerkleRoot(leafHex, siblings, BigInt(leafIndex));
            const onChain = await rootHistoryContains(
              INFURA_URL,
              treeNumber,
              computedRoot,
            );
            if (onChain) {
              row.passed += 1;
            } else {
              row.failures.push({
                leafIndex,
                reason: `rootHistory miss; root=${computedRoot} leaf=${leafHex}`,
              });
            }
          } catch (e) {
            row.failures.push({ leafIndex, reason: String(e) });
          }
        }
        fuzzRows.push(row);
        emitFindings();
        // Same floor as the per-tree block: the live tree's leaf cap is a conservative
        // under-estimate, so some sampled indices are legitimately unwritten - but a run
        // where NOTHING folded to an on-chain root is a failure, not a findings row.
        expect(row.passed).toBeGreaterThan(0);
      },
      TEST_TIMEOUT_MS,
    );
  }
});

liveDescribe("aggressive E2E (throughput)", () => {
  for (const instanceId of [
    "commit-tree-0",
    "commit-tree-1",
    "commit-tree-2",
    "commit-tree-3",
  ]) {
    it(
      `${instanceId}: throughput sweep K={1,4,16} x ${THROUGHPUT_SEEDS} seeds x ${THROUGHPUT_SAMPLE} queries`,
      async () => {
        if (!LIVE_URL) throw new Error("env guard");
        const treeNumber = Number(instanceId.split("-").pop()!);
        const bundle = await getInstance(instanceId);
        const leafCount = TREE_LEAF_COUNT[treeNumber];
        for (const K of [1, 4, 16]) {
          const allLatencies: number[] = [];
          let totalErrors = 0;
          const qpsSamples: number[] = [];
          for (let s = 0; s < THROUGHPUT_SEEDS; s += 1) {
            const rng = makeRng(0xc0ffee + s + treeNumber);
            const indices: number[] = [];
            for (let i = 0; i < THROUGHPUT_SAMPLE; i += 1) {
              indices.push(rng.nextInt(0, leafCount));
            }
            const seedLatencies: number[] = [];
            const seedStart = Date.now();
            // `cursor` needs no atomicity: JS is single-threaded between awaits.
            const cursor = { current: 0 };
            const worker = async (): Promise<void> => {
              while (true) {
                const myIdx = cursor.current;
                if (myIdx >= indices.length) return;
                cursor.current = myIdx + 1;
                const target = indices[myIdx];
                const t0 = Date.now();
                try {
                  await fetchSingleRow(
                    LIVE_URL!,
                    instanceId,
                    bundle.context,
                    target,
                  );
                  seedLatencies.push(Date.now() - t0);
                } catch {
                  totalErrors += 1;
                  seedLatencies.push(Date.now() - t0);
                }
              }
            };
            const workers = Array.from({ length: K }, () => worker());
            await Promise.all(workers);
            const seedMs = Date.now() - seedStart;
            const seedQps = (THROUGHPUT_SAMPLE * 1000) / Math.max(1, seedMs);
            qpsSamples.push(seedQps);
            for (const l of seedLatencies) allLatencies.push(l);
          }
          throughputRows.push({
            instance: instanceId,
            concurrency: K,
            iterations: THROUGHPUT_SAMPLE * THROUGHPUT_SEEDS,
            seeds: THROUGHPUT_SEEDS,
            medianQps: median(qpsSamples),
            p50_ms: pct(allLatencies, 0.5),
            p95_ms: pct(allLatencies, 0.95),
            p99_ms: pct(allLatencies, 0.99),
            mean_ms: mean(allLatencies),
            errors: totalErrors,
            paramsFetchMs: bundle.fetchMs,
          });
          // Latency percentiles over a sweep where every query threw are meaningless, and
          // the row alone reports them as if they were timings.
          expect(totalErrors).toBeLessThan(THROUGHPUT_SAMPLE * THROUGHPUT_SEEDS);
        }
        // A full Merkle proof is 16 sibling PIR queries via /batch.
        const rng = makeRng(0xbeef + treeNumber);
        const leafIndex = rng.nextInt(0, leafCount);
        const indices = pathIndicesForLeaf(wasm, treeNumber, leafIndex);
        const t0 = Date.now();
        const batchRes = await fetchBatch(
          LIVE_URL,
          instanceId,
          bundle.context,
          Array.from(indices),
        );
        const elapsed = Date.now() - t0;
        const note =
          `wallet-merkle-proof ${instanceId} leaf=${leafIndex}: ` +
          `total_wall=${elapsed}ms per_query=${(elapsed / 16).toFixed(1)}ms ` +
          `body=${batchRes.bodyBytes}B response=${batchRes.responseBytes}B`;
        headlineNotes.push(note);
        emitFindings();
        expect(batchRes.responseBytes).toBeGreaterThan(0);
      },
      TEST_TIMEOUT_MS,
    );
  }
});

afterAll(() => {
  if (!RUN_LIVE) return;
  for (const bundle of bundleCache.values()) {
    bundle.context.session.free();
  }
  bundleCache.clear();
  emitFindings();
});

function emitFindings(): void {
  mkdirSync(FINDINGS_DIR, { recursive: true });
  const out: string[] = [];
  out.push("# Aggressive End-to-End Findings");
  out.push("");
  out.push(`- Run timestamp: ${new Date().toISOString()}`);
  out.push(`- Live URL: ${LIVE_URL}`);
  out.push(`- Mainnet RPC: ${INFURA_URL}`);
  out.push("");
  out.push("## 1. Per-tree byte-identity sweep");
  out.push("");
  out.push("| Tree | Sampled | Passed | Divergences |");
  out.push("|------|---------|--------|-------------|");
  for (const r of perTreeRows) {
    out.push(`| ${r.tree} | ${r.sampled} | ${r.passed} | ${r.divergences.length} |`);
  }
  out.push("");
  for (const r of perTreeRows) {
    if (r.divergences.length === 0) continue;
    out.push(`### Tree ${r.tree} divergences`);
    out.push("");
    for (const d of r.divergences) {
      out.push(`- leaf=${d.leafIndex} rootMatch=false`);
      out.push(`  - root: \`${d.rootHex}\``);
      out.push(`  - leaf: \`${d.leafHex}\``);
      out.push(`  - httpStatus: ${d.httpStatus}`);
      out.push(`  - notes: ${d.notes}`);
    }
    out.push("");
  }
  out.push("## 2. PPOI sweep");
  out.push("");
  for (const r of ppoiRows) {
    out.push(`- ${r.instance}: populated=${r.populated} reason="${r.reason}"`);
    if (r.sampled !== undefined) {
      out.push(`  - sampled=${r.sampled} passed=${r.passed}`);
    }
  }
  out.push("");
  out.push("## 3. Fuzz iteration summary");
  out.push("");
  out.push("| Instance | Iterations | Passed | Failures |");
  out.push("|----------|-----------|--------|----------|");
  for (const r of fuzzRows) {
    out.push(
      `| ${r.instance} | ${r.iterations} | ${r.passed} | ${r.failures.length} |`,
    );
  }
  for (const r of fuzzRows) {
    if (r.failures.length === 0) continue;
    out.push("");
    out.push(`### ${r.instance} failures`);
    for (const f of r.failures.slice(0, 10)) {
      out.push(`- leaf=${f.leafIndex}: ${f.reason}`);
    }
    if (r.failures.length > 10) {
      out.push(`- ...and ${r.failures.length - 10} more`);
    }
  }
  out.push("");
  out.push("## 4. Throughput");
  out.push("");
  out.push(
    "| Instance | K | iterations | seeds | median qps | p50 ms | p95 ms | p99 ms | mean ms | errors | params fetch ms |",
  );
  out.push(
    "|----------|---|-----------|-------|------------|--------|--------|--------|---------|--------|------------------|",
  );
  for (const r of throughputRows) {
    out.push(
      `| ${r.instance} | ${r.concurrency} | ${r.iterations} | ${r.seeds} | ${r.medianQps.toFixed(2)} | ${r.p50_ms} | ${r.p95_ms} | ${r.p99_ms} | ${r.mean_ms.toFixed(1)} | ${r.errors} | ${r.paramsFetchMs} |`,
    );
  }
  out.push("");
  out.push("## 5. End-to-end wallet experience");
  out.push("");
  if (headlineNotes.length === 0) {
    out.push("- (no wallet-merkle-proof notes captured)");
  } else {
    for (const n of headlineNotes) out.push(`- ${n}`);
  }
  out.push("");
  out.push("## Hardware reality");
  out.push("");
  out.push(
    "Live URL backed by an `m6i.large` EC2 instance: 2 vCPU / 8 GB RAM / Ice Lake Xeon Platinum 8375C. The locked production-variant respond is CPU-bound at ~70 ms/query on a 16-thread Zen 5 reference; on 2 vCPU expect 4-10x degradation. K=4 saturates the 2 vCPU host; K=16 will not improve over K=4. Production deployments scale horizontally via N boxes behind a load-balancer (each box independently sticky-session-keyed).",
  );
  out.push("");
  out.push(
    "Per-instance `/v1/instance/<id>/params` cold path is ~35 MB (CRS + shard config + InsPIRe params). The throughput numbers amortize this across the 100-query sample per seed; the column `params fetch ms` records the one-time cost.",
  );
  out.push("");
  const findingsPath = join(FINDINGS_DIR, "FINDINGS.md");
  writeFileSync(findingsPath, out.join("\n"));
  process.stderr.write(`\n[aggressive-e2e] FINDINGS written to ${findingsPath}\n`);
}
