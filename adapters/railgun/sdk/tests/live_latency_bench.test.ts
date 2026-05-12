/**
 * Round-trip latency bench against the live Raven adapter URL.
 *
 * Times every stage of a wallet's PIR flow with sub-millisecond
 * `performance.now()` timestamps:
 *
 *   COLD (one-time per session boot):
 *     1. fetch /v1/instance/<id>/params  (HTTP + body read)
 *     2. decode params envelope          (bincode parse)
 *     3. build_client_session            (WASM init + automorph table)
 *
 *   HOT (per query, N iterations against same warm session):
 *     4. build_seeded_query              (WASM)
 *     5. POST /v1/instance/<id>/query    (HTTP + body read)
 *     6. extract_response                (WASM decrypt)
 *
 * Env guards:
 *   RAVEN_LIVE_URL, RAVEN_LIVE_TOKEN
 *   RAVEN_BENCH_INSTANCE       (default commit-tree-0)
 *   RAVEN_BENCH_HOT_QUERIES    (default 10)
 *   RAVEN_BENCH_TARGET_IDX     (default 0; subsequent queries hit
 *                              targetIdx + i to spread cache misses)
 *
 * Skipped when env not set so vitest --workspace stays green.
 */

import { afterAll, describe, expect, it } from "vitest";
import { performance } from "node:perf_hooks";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as wasmPkg from "raven-inspire-client-wasm";
import { decodeClientPirQueryBundle } from "../src/client-pir";

const HERE = dirname(fileURLToPath(import.meta.url));
const FINDINGS_DIR = resolve(
  HERE,
  "..",
  "..",
  "..",
  "no-commit",
  "bench-results",
  "2026-05-07-live-latency-bench",
);

const LIVE_URL = process.env.RAVEN_LIVE_URL;
const LIVE_TOKEN = process.env.RAVEN_LIVE_TOKEN;
const INSTANCE = process.env.RAVEN_BENCH_INSTANCE ?? "commit-tree-0";
const HOT_QUERIES = Number(process.env.RAVEN_BENCH_HOT_QUERIES ?? "10");
const TARGET_IDX = Number(process.env.RAVEN_BENCH_TARGET_IDX ?? "0");

const RUN = LIVE_URL !== undefined && LIVE_TOKEN !== undefined;
const liveDescribe = RUN ? describe : describe.skip;

const PARAMS_TIMEOUT_MS = 600_000;
const QUERY_TIMEOUT_MS = 60_000;

interface ColdTimings {
  paramsFetchMs: number;
  paramsBodyBytes: number;
  envelopeDecodeMs: number;
  buildSessionMs: number;
}

interface WarmTimings {
  serializeMs: number;
  serializedBlobBytes: number;
  deserializeMs: number;
  /** Total per-warm-load wall: only `deserialize_client_session`.
   *  `serializeMs` is paid once at the END of the cold path (right
   *  after `build_client_session`) so it is NOT in the per-warm
   *  budget; it is reported separately for completeness.
   *  The IndexedDB read is a cheap memory copy on the Node-side
   *  in-memory backend used by this bench; we expose the WASM-bound
   *  cost which is the load-bearing latency on real wallets. */
  totalWarmMs: number;
}

interface HotSample {
  buildQueryMs: number;
  queryPostMs: number;
  queryBytes: number;
  responseBytes: number;
  extractMs: number;
  totalMs: number;
}

interface DecodedParams {
  wireSchemaVersion: number;
  crsBincode: Uint8Array;
  shardConfigBincode: Uint8Array;
  inspireParamsBincode: Uint8Array;
  entrySize: number;
  variant: string;
  epoch: bigint;
}

const wasm = wasmPkg as unknown as {
  init_panic_hook?: () => void;
  build_instance_params_blob: (
    inspireParamsBincode: Uint8Array,
    shardConfigBincode: Uint8Array,
  ) => Uint8Array;
  build_client_session: (
    paramsBundleBincode: Uint8Array,
    crsBincode: Uint8Array,
  ) => { free(): void };
  build_seeded_query: (
    session: { free(): void },
    shardConfigBincode: Uint8Array,
    targetIdx: bigint,
  ) => Uint8Array;
  extract_response: (
    session: { free(): void },
    crsBincode: Uint8Array,
    clientStateBincode: Uint8Array,
    responseBytes: Uint8Array,
    entrySize: number,
  ) => Uint8Array;
  serialize_client_session?: (session: { free(): void }) => Uint8Array;
  deserialize_client_session?: (
    paramsBundleBincode: Uint8Array,
    crsBincode: Uint8Array,
    sessionBincode: Uint8Array,
  ) => { free(): void };
};

if (typeof wasm.init_panic_hook === "function") {
  wasm.init_panic_hook();
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
    throw new Error(`readByteVec: truncated (need ${end}, have ${buf.length})`);
  }
  return { value: new Uint8Array(buf.subarray(start, end)), next: end };
}

function readString(buf: Uint8Array, offset: number): { value: string; next: number } {
  const inner = readByteVec(buf, offset);
  return { value: new TextDecoder().decode(inner.value), next: inner.next };
}

/**
 * Mirrors `raven-railgun-http::InstanceParams` envelope:
 *   [u16 BE schema][u16 LE wire][u64 crs.len, crs][u64 shard.len, shard]
 *   [u64 inspire.len, inspire][u64 entry_size][u64 variant.len, variant]
 *   [u64 epoch]
 */
function decodeInstanceParams(buf: Uint8Array): DecodedParams {
  if (buf.length < 4) throw new Error(`/params body too short: ${buf.length}`);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const envelope = (view.getUint8(0) << 8) | view.getUint8(1);
  if (envelope !== 1) throw new Error(`unexpected envelope=${envelope}`);
  let off = 2;
  const wireSchemaVersion = view.getUint16(off, true);
  off += 2;
  const crs = readByteVec(buf, off); off = crs.next;
  const shard = readByteVec(buf, off); off = shard.next;
  const inspire = readByteVec(buf, off); off = inspire.next;
  const entrySize = readU64LE(view, off); off += 8;
  const variant = readString(buf, off); off = variant.next;
  const epochLo = view.getUint32(off, true);
  const epochHi = view.getUint32(off + 4, true);
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

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

function pct(arr: number[], p: number): number {
  if (arr.length === 0) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

function fmt(n: number, digits = 1): string {
  return n.toFixed(digits);
}

function summary(label: string, samples: number[]): string {
  if (samples.length === 0) return `${label}: no samples`;
  const min = Math.min(...samples);
  const max = Math.max(...samples);
  const mean = samples.reduce((a, b) => a + b, 0) / samples.length;
  return (
    `${label.padEnd(22)} n=${samples.length}  ` +
    `min=${fmt(min)}  p50=${fmt(pct(samples, 50))}  mean=${fmt(mean)}  ` +
    `p95=${fmt(pct(samples, 95))}  p99=${fmt(pct(samples, 99))}  max=${fmt(max)}  ms`
  );
}

liveDescribe("live latency bench", () => {
  let cold: ColdTimings;
  const hotSamples: HotSample[] = [];
  let warm: WarmTimings | null = null;
  let bandwidthMbps = 0;
  let variantLabel = "";
  let entrySize = 0;

  it(
    `cold + ${HOT_QUERIES} hot against ${INSTANCE}`,
    async () => {
      // ---------- COLD 1: GET /params ----------
      const t0 = performance.now();
      const res = await fetchWithTimeout(
        `${LIVE_URL}/v1/instance/${encodeURIComponent(INSTANCE)}/params`,
        { headers: { authorization: `Bearer ${LIVE_TOKEN}` } },
        PARAMS_TIMEOUT_MS,
      );
      if (!res.ok) throw new Error(`GET /params: HTTP ${res.status}`);
      const paramsBody = new Uint8Array(await res.arrayBuffer());
      const t1 = performance.now();
      const paramsFetchMs = t1 - t0;
      bandwidthMbps = (paramsBody.length * 8) / 1e6 / (paramsFetchMs / 1e3);

      // ---------- COLD 2: decode envelope ----------
      const t2 = performance.now();
      const decoded = decodeInstanceParams(paramsBody);
      const t3 = performance.now();
      const envelopeDecodeMs = t3 - t2;
      variantLabel = decoded.variant;
      entrySize = decoded.entrySize;

      // ---------- COLD 3: build_client_session ----------
      const t4 = performance.now();
      const paramsBundle = wasm.build_instance_params_blob(
        decoded.inspireParamsBincode,
        decoded.shardConfigBincode,
      );
      const session = wasm.build_client_session(paramsBundle, decoded.crsBincode);
      const t5 = performance.now();
      const buildSessionMs = t5 - t4;

      cold = {
        paramsFetchMs,
        paramsBodyBytes: paramsBody.length,
        envelopeDecodeMs,
        buildSessionMs,
      };

      // ---------- HOT (reuse session) ----------
      for (let i = 0; i < HOT_QUERIES; i += 1) {
        const targetIdx = (TARGET_IDX + i) % 65_536;

        const h0 = performance.now();
        const queryBundle = decodeClientPirQueryBundle(
          wasm.build_seeded_query(session, decoded.shardConfigBincode, BigInt(targetIdx)),
        );
        const h1 = performance.now();
        const buildQueryMs = h1 - h0;

        const wireBody = new Uint8Array(2 + queryBundle.queryBytes.length);
        wireBody[0] = 0;
        wireBody[1] = 1;
        wireBody.set(queryBundle.queryBytes, 2);

        const h2 = performance.now();
        const queryRes = await fetchWithTimeout(
          `${LIVE_URL}/v1/instance/${encodeURIComponent(INSTANCE)}/query`,
          {
            method: "POST",
            headers: {
              "content-type": "application/octet-stream",
              authorization: `Bearer ${LIVE_TOKEN}`,
            },
            body: wireBody as unknown as BodyInit,
          },
          QUERY_TIMEOUT_MS,
        );
        if (!queryRes.ok) throw new Error(`POST /query iter=${i}: HTTP ${queryRes.status}`);
        const enveloped = new Uint8Array(await queryRes.arrayBuffer());
        const h3 = performance.now();
        const queryPostMs = h3 - h2;

        if (enveloped.length < 2 || ((enveloped[0] << 8) | enveloped[1]) !== 1) {
          throw new Error(`bad response envelope iter=${i}`);
        }
        const responseBytes = enveloped.subarray(2);

        const h4 = performance.now();
        const plaintext = wasm.extract_response(
          session,
          decoded.crsBincode,
          queryBundle.clientStateBincode,
          responseBytes,
          decoded.entrySize,
        );
        const h5 = performance.now();
        const extractMs = h5 - h4;

        if (plaintext.length < 32) throw new Error(`plaintext short iter=${i}: ${plaintext.length}`);

        hotSamples.push({
          buildQueryMs,
          queryPostMs,
          queryBytes: wireBody.length,
          responseBytes: enveloped.length,
          extractMs,
          totalMs: buildQueryMs + queryPostMs + extractMs,
        });
      }

      // ---------- WARM (cache hit re-use of build_client_session) ----------
      //
      // After the cold + hot sweeps are complete, exercise the new
      // serialize/deserialize_client_session pair to capture the
      // wall-time cost a wallet pays on its second page load (when
      // IndexedDB has a cached blob keyed by `(instanceId,
      // sha256(crsBincode))`). The warm path replaces COLD step 3
      // (`build_client_session` -> ~12.6 s on production-cell d=2048)
      // with `deserialize_client_session` -> a few hundred ms.
      //
      // Skipped when the WASM build does not export the new symbols
      // (older pin pre-`s036-client-session-serde`).
      if (
        typeof wasm.serialize_client_session === "function" &&
        typeof wasm.deserialize_client_session === "function"
      ) {
        const w0 = performance.now();
        const sessionBlob = wasm.serialize_client_session(session);
        const w1 = performance.now();
        const serializeMs = w1 - w0;

        const w2 = performance.now();
        const warmSession = wasm.deserialize_client_session(
          paramsBundle,
          decoded.crsBincode,
          sessionBlob,
        );
        const w3 = performance.now();
        const deserializeMs = w3 - w2;

        warm = {
          serializeMs,
          serializedBlobBytes: sessionBlob.length,
          deserializeMs,
          totalWarmMs: deserializeMs,
        };

        // Sanity: a one-off warm-path query must extract correctly.
        const warmTargetIdx = (TARGET_IDX + HOT_QUERIES) % 65_536;
        const warmQueryBundle = decodeClientPirQueryBundle(
          wasm.build_seeded_query(warmSession, decoded.shardConfigBincode, BigInt(warmTargetIdx)),
        );
        const warmWireBody = new Uint8Array(2 + warmQueryBundle.queryBytes.length);
        warmWireBody[0] = 0;
        warmWireBody[1] = 1;
        warmWireBody.set(warmQueryBundle.queryBytes, 2);
        const warmRes = await fetchWithTimeout(
          `${LIVE_URL}/v1/instance/${encodeURIComponent(INSTANCE)}/query`,
          {
            method: "POST",
            headers: {
              "content-type": "application/octet-stream",
              authorization: `Bearer ${LIVE_TOKEN}`,
            },
            body: warmWireBody as unknown as BodyInit,
          },
          QUERY_TIMEOUT_MS,
        );
        if (!warmRes.ok) throw new Error(`POST /query warm: HTTP ${warmRes.status}`);
        const warmEnveloped = new Uint8Array(await warmRes.arrayBuffer());
        if (
          warmEnveloped.length < 2 ||
          ((warmEnveloped[0] << 8) | warmEnveloped[1]) !== 1
        ) {
          throw new Error("bad response envelope on warm-path sanity query");
        }
        const warmResponseBytes = warmEnveloped.subarray(2);
        const warmPlaintext = wasm.extract_response(
          warmSession,
          decoded.crsBincode,
          warmQueryBundle.clientStateBincode,
          warmResponseBytes,
          decoded.entrySize,
        );
        if (warmPlaintext.length < 32) {
          throw new Error(`warm-path plaintext short: ${warmPlaintext.length}`);
        }

        warmSession.free();
        // Load-bearing assertion: per-warm-load deserialize must
        // complete under 700 ms at production-cell d=2048. Empirical
        // floor is ~524 ms (200 MB bincode parse + memcpy of NTT-
        // domain packing keys); 700 ms reserves comfort margin for
        // host noise + slower devices. Vs the ~11.6 s cold-path
        // build_client_session this is a 16-22x warm-path speedup.
        expect(warm.totalWarmMs).toBeLessThan(700);
      }

      session.free();
      expect(hotSamples.length).toBe(HOT_QUERIES);
    },
    { timeout: 1_800_000 },
  );

  afterAll(() => {
    if (!cold || hotSamples.length === 0) return;

    const lines: string[] = [];
    lines.push(`# Live Latency Bench`);
    lines.push("");
    lines.push(`- URL: ${LIVE_URL}`);
    lines.push(`- Instance: ${INSTANCE}`);
    lines.push(`- Variant: ${variantLabel}, entry_size=${entrySize}`);
    lines.push(`- Hot queries: ${HOT_QUERIES}`);
    lines.push(`- Run at: ${new Date().toISOString()}`);
    lines.push(`- Node: ${process.version}, platform: ${process.platform}`);
    lines.push("");
    lines.push("## COLD path (one-time per session boot)");
    lines.push("");
    lines.push("| Stage | Wall (ms) | Notes |");
    lines.push("|---|---|---|");
    lines.push(
      `| 1. GET /params | ${fmt(cold.paramsFetchMs)} | ${(cold.paramsBodyBytes / 1e6).toFixed(1)} MB body, ${fmt(bandwidthMbps)} Mbps effective |`,
    );
    lines.push(`| 2. decode envelope | ${fmt(cold.envelopeDecodeMs, 2)} | bincode parse |`);
    lines.push(
      `| 3. build_client_session | ${fmt(cold.buildSessionMs)} | WASM + automorph-table |`,
    );
    const coldTotal = cold.paramsFetchMs + cold.envelopeDecodeMs + cold.buildSessionMs;
    lines.push(`| **TOTAL COLD** | **${fmt(coldTotal)}** | paid once per wallet session |`);
    lines.push("");
    if (warm) {
      lines.push("## WARM path (cache-hit, second + subsequent boots)");
      lines.push("");
      lines.push("| Stage | Wall (ms) | Notes |");
      lines.push("|---|---|---|");
      lines.push(
        `| serialize_client_session | ${fmt(warm.serializeMs)} | ${(warm.serializedBlobBytes / 1e6).toFixed(2)} MB cached blob |`,
      );
      lines.push(`| deserialize_client_session | ${fmt(warm.deserializeMs)} | reseeds packing keys |`);
      lines.push(`| **TOTAL WARM** | **${fmt(warm.totalWarmMs)}** | replaces ${fmt(cold.buildSessionMs)} ms cold-path |`);
      lines.push("");
    }
    lines.push("## HOT path (per query)");
    lines.push("");
    const buildQ = hotSamples.map((s) => s.buildQueryMs);
    const postQ = hotSamples.map((s) => s.queryPostMs);
    const extQ = hotSamples.map((s) => s.extractMs);
    const totQ = hotSamples.map((s) => s.totalMs);
    lines.push("```");
    lines.push(summary("build_seeded_query", buildQ));
    lines.push(summary("POST /query", postQ));
    lines.push(summary("extract_response", extQ));
    lines.push(summary("TOTAL per query", totQ));
    lines.push("```");
    lines.push("");
    lines.push(
      `Wire bytes: ~${(hotSamples[0].queryBytes / 1024).toFixed(1)} KiB up, ~${(hotSamples[0].responseBytes / 1024).toFixed(1)} KiB down`,
    );
    lines.push("");
    lines.push("## Per-iteration table");
    lines.push("");
    lines.push("| # | build (ms) | POST (ms) | extract (ms) | total (ms) |");
    lines.push("|---|---|---|---|---|");
    hotSamples.forEach((s, i) => {
      lines.push(
        `| ${i} | ${fmt(s.buildQueryMs)} | ${fmt(s.queryPostMs)} | ${fmt(s.extractMs)} | ${fmt(s.totalMs)} |`,
      );
    });

    const out = lines.join("\n") + "\n";
    mkdirSync(FINDINGS_DIR, { recursive: true });
    const target = resolve(FINDINGS_DIR, `${INSTANCE.replace(/[^A-Za-z0-9_-]/g, "_")}.md`);
    writeFileSync(target, out);
    process.stdout.write("\n" + out + "\n");
  });
});
