/**
 * The PPOI acceptance smoke: a wallet's two POI calls against a Raven node, each answer checked
 * against the upstream aggregator, which produced neither the node's rows nor its paths.
 *
 * The known commitment sits at the last leaf of block 0 of the OFAC list. That block is full, so
 * its commitment, its path and its root can never change; the harness still re-reads the event
 * from upstream and refuses if it moved. The unlisted commitment is there because the status tier
 * serves membership: a member reads Valid and anything else reads Missing, so a smoke over one
 * member could only ever see one value and would prove nothing about status.
 *
 * Bytes are HTTP body bytes in each direction; headers and TLS are not counted.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";

import {
  ImtCache,
  LEAVES_PER_PPOI_BLOCK,
  RavenError,
  RavenPOINodeInterface,
  UpstreamPinResolver,
  foldMerkleRoot,
  loadClientPirContext,
  type BlindedCommitmentType,
  type Chain,
  type ClientPirContext,
  type MerkleProof,
  type RavenInspireWasm,
} from "../../src/index";
import { bearerHeaders } from "../../src/bearer-auth";
import { decodeInstanceParams } from "./live_wire";
import { assertNoCommitmentsAnywhere } from "./private_wire";

function normalize(hex: string): string {
  return (hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex).toLowerCase();
}

// The expected values are upstream's own answers, saved verbatim when they were read, not
// constants typed in here.
const RECORDED = new URL("../fixtures/ppoi-aggregator/", import.meta.url);

function recorded<T>(name: string): T {
  return (JSON.parse(readFileSync(new URL(name, RECORDED), "utf8")) as { result: T }).result;
}

const RECORDED_EVENT = recorded<
  [{ signedPOIEvent: { index: number; blindedCommitment: string }; validatedMerkleroot: string }]
>("01-ppoi_poi_events.response.json")[0];
const RECORDED_PROOF = recorded<[{ leaf: string; elements: string[]; root: string }]>(
  "08-ppoi_merkle_proofs.response.json",
)[0];

export const OFAC_LIST_KEY = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";
export const TXID_VERSION = "V2_PoseidonMerkle";
export const KNOWN_INDEX = RECORDED_EVENT.signedPOIEvent.index;
export const KNOWN_BC = normalize(RECORDED_EVENT.signedPOIEvent.blindedCommitment);
export const KNOWN_BLOCK_ROOT = normalize(RECORDED_EVENT.validatedMerkleroot);
/** Upstream's `ppoi_merkle_proofs` answer for `KNOWN_BC`, level 0 first. */
export const KNOWN_SIBLINGS: readonly string[] = RECORDED_PROOF.elements.map(normalize);
export const KNOWN_PROOF_LEAF = normalize(RECORDED_PROOF.leaf);
export const KNOWN_PROOF_ROOT = normalize(RECORDED_PROOF.root);

export const UNLISTED_PHRASE = "raven ppoi smoke: a commitment on no list";
/** On no list: the SHA-256 of `UNLISTED_PHRASE` cut to 252 bits, so a field element nobody chose. */
export const UNLISTED_BC = (() => {
  const digest = createHash("sha256").update(UNLISTED_PHRASE).digest();
  digest[0] &= 0x0f;
  return digest.toString("hex");
})();

export const MEMBERSHIP_STATEMENT =
  "The status tier answers list membership: Valid for a member, Missing otherwise. " +
  "ShieldBlocked and ProofSubmitted describe commitments with no list index, which it cannot express.";

type Party = "node" | "aggregator" | "other";

export interface MeteredRequest {
  readonly phase: string;
  readonly party: Party;
  readonly route: string;
  readonly method: string;
  readonly url: string;
  /** Where fetch ended up after redirects. Another origin than `url` makes it a third-party contact. */
  readonly finalUrl: string;
  readonly body: Uint8Array;
  readonly up: number;
  readonly down: number;
  readonly status: number;
  readonly ms: number;
  /** The response's `content-encoding`. `down` is the decoded body, so it overstates an encoded one. */
  readonly encoding: string | null;
}

export interface PhaseTotals {
  readonly phase: string;
  readonly requests: number;
  readonly up: number;
  readonly down: number;
  readonly ms: number;
  readonly byRoute: Readonly<Record<string, { requests: number; up: number; down: number }>>;
}

export interface PpoiSmokeReport {
  readonly node: string;
  readonly aggregator: string;
  readonly startedAt: string;
  readonly listKey: string;
  readonly knownIndex: number;
  readonly knownBc: string;
  readonly unlistedBc: string;
  readonly membership: string;
  readonly params: Readonly<Record<string, { wireSchema: number; entrySize: number; variant: string; epoch: string; bytes: number }>>;
  readonly status: {
    readonly listed: { readonly node: string; readonly oracle: string };
    readonly unlisted: { readonly node: string; readonly oracle: string };
  };
  readonly path: {
    readonly block: number;
    readonly leafIndex: number;
    readonly root: string;
    readonly oracleEventRoot: string;
    readonly resolverRoots: readonly string[];
    readonly resolverWindow: string;
  };
  readonly index: {
    readonly total: number;
    readonly candidates: readonly number[];
    /** Empty on an honest node. A prefix twin puts a row here and costs the refusal a PIR query. */
    readonly unlistedCandidates: readonly number[];
  };
  readonly statusHeader: { readonly blocked: number; readonly pending: number };
  readonly jsonIndex: { readonly served: false } | { readonly served: true; readonly rows: number };
  readonly phases: readonly PhaseTotals[];
  readonly totals: Readonly<Record<Party, { requests: number; up: number; down: number }>>;
  /** Responses that arrived content-encoded; nonzero means `down` is above the wire figure. */
  readonly encodedResponses: number;
  readonly wallClockMs: number;
}

export interface PpoiSmokeOptions {
  readonly node: string;
  readonly aggregator: string;
  readonly wasm: RavenInspireWasm;
  readonly statusInstance: string;
  readonly pathInstanceForBlock: (block: number) => string;
  readonly fetchImpl?: typeof fetch;
  readonly chainId?: number;
  /** For a node that still gates reads. Sent to the node only, never to the aggregator. */
  readonly bearerToken?: string;
  /**
   * Block roots the SDK is handed as pins, keyed `<chainId>:<listKey>:<block>`. A pin outranks the
   * aggregator inside the SDK, so a wrong one makes the SDK accept a path upstream would not; the
   * smoke's own upstream check is what still catches it.
   */
  readonly sdkPinnedRoots?: ReadonlyMap<string, string>;
  /**
   * Test only: stands a faulty SDK in front of the real one, so each check on the SDK's own output
   * is shown to catch one. `fetch` is the metered fetch, so what the fault sends is scanned as SDK
   * traffic.
   */
  readonly wrapSdk?: (sdk: SmokeSdk, fetch: typeof globalThis.fetch) => SmokeSdk;
}

/** The SDK calls the smoke makes. */
export type SmokeSdk = Pick<
  RavenPOINodeInterface,
  | "syncPoiListIndex"
  | "poiListIndexCandidates"
  | "fetchStatusHeader"
  | "fetchBcToIdxMap"
  | "getPOIsPerList"
  | "getPOIMerkleProofs"
>;

function originOf(url: string): string {
  return new URL(url).origin;
}

async function sizeBody(body: BodyInit | null | undefined): Promise<Uint8Array> {
  if (body === undefined || body === null) return new Uint8Array();
  if (typeof body === "string") return new TextEncoder().encode(body);
  if (body instanceof Blob) return new Uint8Array(await body.arrayBuffer());
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (ArrayBuffer.isView(body)) {
    return new Uint8Array(body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength));
  }
  throw new Error(`meter: cannot size a ${Object.prototype.toString.call(body)} request body`);
}

function routeOf(party: Party, url: string, body: Uint8Array): string {
  if (party === "aggregator") {
    try {
      const method = (JSON.parse(new TextDecoder().decode(body)) as { method?: unknown }).method;
      return typeof method === "string" ? method : "rpc";
    } catch {
      return "rpc";
    }
  }
  const path = new URL(url).pathname;
  const match = /\/(params|session|batch|query|fanout|bc-prefixes|bc-to-idx-map|status-header)$/.exec(path);
  return match ? match[1] : path;
}

const NULL_BODY_STATUSES = new Set([101, 204, 205, 304]);

/** Every request either party sees, sized in both directions and attributed to a harness phase. */
class Meter {
  phase = "setup";
  readonly log: MeteredRequest[] = [];

  constructor(
    private readonly nodeOrigin: string,
    private readonly aggregatorOrigin: string,
    private readonly inner: typeof fetch,
  ) {}

  readonly fetch: typeof fetch = async (input, init) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const body = await sizeBody(init?.body);
    const phase = this.phase;
    const started = performance.now();
    const res = await this.inner(input, init);
    const payload = new Uint8Array(await res.arrayBuffer());
    const finalUrl = res.url === "" ? url : res.url;
    const origin = originOf(url);
    const party: Party =
      originOf(finalUrl) !== origin
        ? "other"
        : origin === this.nodeOrigin
          ? "node"
          : origin === this.aggregatorOrigin
            ? "aggregator"
            : "other";
    this.log.push({
      phase,
      party,
      route: routeOf(party, finalUrl, body),
      method: init?.method ?? "GET",
      url,
      finalUrl,
      body,
      up: body.length,
      down: payload.length,
      status: res.status,
      ms: performance.now() - started,
      encoding: res.headers.get("content-encoding"),
    });
    return new Response(NULL_BODY_STATUSES.has(res.status) ? null : payload, {
      status: res.status,
      statusText: res.statusText,
      headers: res.headers,
    });
  };
}

async function oracleRpc(
  meter: Meter,
  aggregator: string,
  method: string,
  params: Record<string, unknown>,
): Promise<unknown> {
  const res = await meter.fetch(aggregator, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", method, params, id: 1 }),
    signal: AbortSignal.timeout(60_000),
  });
  const decoded = (await res.json()) as { result?: unknown; error?: unknown };
  if (decoded.error !== undefined && decoded.error !== null) {
    throw new Error(`oracle ${method}: ${JSON.stringify(decoded.error)}`);
  }
  if (!res.ok) throw new Error(`oracle ${method}: HTTP ${res.status}`);
  return decoded.result;
}

interface OracleEvent {
  readonly spelling: string;
  readonly type: BlindedCommitmentType;
  readonly root: string;
}

async function oracleEventAt(meter: Meter, aggregator: string, chainId: number): Promise<OracleEvent> {
  const rows = await oracleRpc(meter, aggregator, "ppoi_poi_events", {
    chainType: "0",
    chainID: String(chainId),
    txidVersion: TXID_VERSION,
    listKey: OFAC_LIST_KEY,
    startIndex: KNOWN_INDEX,
    endIndex: KNOWN_INDEX,
  });
  if (!Array.isArray(rows) || rows.length !== 1) {
    throw new Error(`oracle: expected one event at index ${KNOWN_INDEX}, got ${JSON.stringify(rows)}`);
  }
  const row = rows[0] as {
    signedPOIEvent?: { index?: unknown; blindedCommitment?: unknown; type?: unknown };
    validatedMerkleroot?: unknown;
  };
  const event = row.signedPOIEvent;
  if (
    event?.index !== KNOWN_INDEX ||
    typeof event.blindedCommitment !== "string" ||
    typeof row.validatedMerkleroot !== "string"
  ) {
    throw new Error(`oracle: malformed event at index ${KNOWN_INDEX}: ${JSON.stringify(row)}`);
  }
  if (normalize(event.blindedCommitment) !== KNOWN_BC) {
    throw new Error(
      `oracle: upstream's commitment at index ${KNOWN_INDEX} is ${event.blindedCommitment}, ` +
        `recorded as ${KNOWN_BC}; a frozen block does not change, so this is the finding`,
    );
  }
  if (normalize(row.validatedMerkleroot) !== KNOWN_BLOCK_ROOT) {
    throw new Error(
      `oracle: upstream's root at index ${KNOWN_INDEX} is ${row.validatedMerkleroot}, ` +
        `recorded as ${KNOWN_BLOCK_ROOT}`,
    );
  }
  const type = event.type;
  if (type !== "Shield" && type !== "Transact" && type !== "Unshield") {
    throw new Error(`oracle: event type ${String(type)} is not a wallet commitment type`);
  }
  return { spelling: event.blindedCommitment, type, root: normalize(row.validatedMerkleroot) };
}

async function oracleStatuses(
  meter: Meter,
  aggregator: string,
  chainId: number,
  datas: readonly { blindedCommitment: string; type: BlindedCommitmentType }[],
): Promise<string[]> {
  const result = (await oracleRpc(meter, aggregator, "ppoi_pois_per_list", {
    chainType: "0",
    chainID: String(chainId),
    txidVersion: TXID_VERSION,
    listKeys: [OFAC_LIST_KEY],
    blindedCommitmentDatas: datas,
  })) as Record<string, Record<string, unknown> | undefined> | null;
  return datas.map(({ blindedCommitment }) => {
    const status = result?.[blindedCommitment]?.[OFAC_LIST_KEY];
    if (typeof status !== "string") {
      throw new Error(`oracle: ppoi_pois_per_list has no status for ${blindedCommitment}`);
    }
    return status;
  });
}

async function loadContext(
  meter: Meter,
  options: PpoiSmokeOptions,
  instanceId: string,
): Promise<{ context: ClientPirContext; summary: PpoiSmokeReport["params"][string] }> {
  const res = await meter.fetch(
    `${options.node}/v1/instance/${encodeURIComponent(instanceId)}/params`,
    { headers: bearerHeaders(options.bearerToken), signal: AbortSignal.timeout(600_000) },
  );
  if (!res.ok) throw new Error(`params ${instanceId}: HTTP ${res.status}`);
  const body = new Uint8Array(await res.arrayBuffer());
  const params = decodeInstanceParams(body);
  const { context } = await loadClientPirContext({
    wasm: options.wasm,
    instanceId,
    crsBincode: params.crsBincode,
    shardConfigBincode: params.shardConfigBincode,
    inspireParamsBincode: params.inspireParamsBincode,
    entrySize: params.entrySize,
  });
  return {
    context,
    summary: {
      wireSchema: params.wireSchemaVersion,
      entrySize: params.entrySize,
      variant: params.variant,
      epoch: params.epoch.toString(),
      bytes: body.length,
    },
  };
}

function totalsByPhase(log: readonly MeteredRequest[], ms: ReadonlyMap<string, number>): PhaseTotals[] {
  const out: PhaseTotals[] = [];
  for (const [phase, elapsed] of ms) {
    const rows = log.filter((r) => r.phase === phase);
    const byRoute: Record<string, { requests: number; up: number; down: number }> = {};
    for (const r of rows) {
      const key = `${r.party}:${r.route}`;
      const slot = (byRoute[key] ??= { requests: 0, up: 0, down: 0 });
      slot.requests += 1;
      slot.up += r.up;
      slot.down += r.down;
    }
    out.push({
      phase,
      requests: rows.length,
      up: rows.reduce((s, r) => s + r.up, 0),
      down: rows.reduce((s, r) => s + r.down, 0),
      ms: elapsed,
      byRoute,
    });
  }
  return out;
}

/**
 * Runs the smoke and returns its evidence, or throws at the first check that fails. Phases whose
 * name starts `oracle` are the harness asking upstream directly; everything else is the SDK, and
 * none of what the SDK sends may carry either commitment.
 */
export async function runPpoiSmoke(options: PpoiSmokeOptions): Promise<PpoiSmokeReport> {
  const chainId = options.chainId ?? 1;
  const chain: Chain = { type: 0, id: chainId };
  const block = Math.floor(KNOWN_INDEX / LEAVES_PER_PPOI_BLOCK);
  const localIndex = KNOWN_INDEX - block * LEAVES_PER_PPOI_BLOCK;
  const meter = new Meter(
    originOf(options.node),
    originOf(options.aggregator),
    options.fetchImpl ?? fetch,
  );
  const phaseMs = new Map<string, number>();
  const phase = async <T>(name: string, body: () => Promise<T>): Promise<T> => {
    meter.phase = name;
    const started = performance.now();
    try {
      return await body();
    } finally {
      phaseMs.set(name, (phaseMs.get(name) ?? 0) + performance.now() - started);
    }
  };
  const startedAt = new Date().toISOString();
  const started = performance.now();

  const pathInstance = options.pathInstanceForBlock(block);
  const { status: statusLoad, path: pathLoad } = await phase("params", async () => ({
    status: await loadContext(meter, options, options.statusInstance),
    path: await loadContext(meter, options, pathInstance),
  }));

  const event = await phase("oracle-event", () => oracleEventAt(meter, options.aggregator, chainId));
  const listed = { blindedCommitment: event.spelling, type: event.type };
  const unlisted = { blindedCommitment: `0x${UNLISTED_BC}`, type: event.type };
  const [oracleListed, oracleUnlisted] = await phase("oracle-status", () =>
    oracleStatuses(meter, options.aggregator, chainId, [listed, unlisted]),
  );
  if (oracleListed === oracleUnlisted) {
    throw new Error(
      `oracle: upstream answers ${oracleListed} for both the member and the non-member, so the ` +
        "status half of this smoke could not tell a right answer from a wrong one",
    );
  }

  const real = new RavenPOINodeInterface({
    endpoint: options.node,
    chainId,
    useClientPir: true,
    clientPirContexts: new Map([
      [`t1Status:${chainId}:${OFAC_LIST_KEY}`, statusLoad.context],
      [`t2Path:${chainId}:${OFAC_LIST_KEY}`, pathLoad.context],
    ]),
    clientPirInstanceLabels: new Map([
      [`t1Status:${chainId}:${OFAC_LIST_KEY}`, options.statusInstance],
      [`t2Path:${chainId}:${OFAC_LIST_KEY}:${block}`, pathInstance],
    ]),
    pinUpstream: options.aggregator,
    ppoiPinnedRoots: options.sdkPinnedRoots === undefined ? undefined : new Map(options.sdkPinnedRoots),
    bearerToken: options.bearerToken,
    poiListIndexStore: false,
    imtCache: new ImtCache({ disableIndexedDb: true }),
    fetchImpl: meter.fetch,
  });
  const sdk: SmokeSdk = options.wrapSdk?.(real, meter.fetch) ?? real;

  const index = await phase("index", async () => {
    const synced = await sdk.syncPoiListIndex(OFAC_LIST_KEY);
    const known = await sdk.poiListIndexCandidates(OFAC_LIST_KEY, KNOWN_BC);
    const unlisted = await sdk.poiListIndexCandidates(OFAC_LIST_KEY, UNLISTED_BC);
    return {
      total: synced.total,
      candidates: known.candidates,
      unlistedCandidates: unlisted.candidates,
    };
  });
  if (!index.candidates.includes(KNOWN_INDEX)) {
    throw new Error(
      `index: the node's list of ${index.total} rows gives ${KNOWN_BC} candidates ` +
        `[${index.candidates.join(", ")}], not the upstream index ${KNOWN_INDEX}`,
    );
  }

  const header = await phase("status-header", () => sdk.fetchStatusHeader(OFAC_LIST_KEY));
  if (normalize(header.listKey) !== OFAC_LIST_KEY) {
    throw new Error(`status-header: answered for list ${header.listKey}`);
  }

  const jsonIndex = await phase("json-index", async (): Promise<PpoiSmokeReport["jsonIndex"]> => {
    let body;
    try {
      body = await sdk.fetchBcToIdxMap(OFAC_LIST_KEY);
    } catch (e) {
      if (RavenError.is(e, "ServerError") && e.context.status === 404) return { served: false };
      throw e;
    }
    const row = body.entries[KNOWN_INDEX];
    if (row === undefined || normalize(row.bc) !== KNOWN_BC) {
      throw new Error(
        `bc-to-idx-map: row ${KNOWN_INDEX} of ${body.rows} is ${row?.bc}, upstream says ${KNOWN_BC}`,
      );
    }
    return { served: true, rows: body.rows };
  });

  const verdicts = (await phase("status", () =>
    sdk.getPOIsPerList(TXID_VERSION, chain, [OFAC_LIST_KEY], [listed, unlisted]),
  )) as Record<string, Record<string, string> | undefined>;
  const nodeListed = verdicts[listed.blindedCommitment]?.[OFAC_LIST_KEY];
  const nodeUnlisted = verdicts[unlisted.blindedCommitment]?.[OFAC_LIST_KEY];
  if (nodeListed !== oracleListed || nodeUnlisted !== oracleUnlisted) {
    throw new Error(
      `status: the node answers listed=${nodeListed} unlisted=${nodeUnlisted}, ` +
        `upstream answers listed=${oracleListed} unlisted=${oracleUnlisted}`,
    );
  }

  const proofs: MerkleProof[] = await phase("path", () =>
    sdk.getPOIMerkleProofs(TXID_VERSION, chain, OFAC_LIST_KEY, [listed.blindedCommitment]),
  );
  const proof = proofs[0];
  if (proofs.length !== 1 || proof === undefined || normalize(proof.leaf) !== KNOWN_BC) {
    throw new Error(`path: expected one proof for ${KNOWN_BC}, got ${JSON.stringify(proofs)}`);
  }
  const provedLeaf = BigInt(`0x${normalize(proof.indices)}`);
  if (provedLeaf !== BigInt(localIndex)) {
    throw new Error(`path: proof is for leaf ${provedLeaf}, not ${localIndex}`);
  }
  const folded = foldMerkleRoot(KNOWN_BC, proof.elements, BigInt(localIndex));
  if (folded !== normalize(proof.root)) {
    throw new Error(`path: siblings fold to ${folded}, the proof claims ${proof.root}`);
  }

  await phase("path-unlisted", async () => {
    let refused: unknown;
    try {
      await sdk.getPOIMerkleProofs(TXID_VERSION, chain, OFAC_LIST_KEY, [unlisted.blindedCommitment]);
    } catch (e) {
      refused = e;
    }
    // Any other InvalidQuery, a row past an instance's capacity say, means the node's index held it.
    if (
      !RavenError.is(refused, "InvalidQuery") ||
      !refused.message.includes(`BC ${UNLISTED_BC} not present in list`)
    ) {
      throw new Error(`path: a commitment on no list was not refused as absent: ${String(refused)}`);
    }
  });
  const unlistedQueries = meter.log.filter(
    (r) => r.phase === "path-unlisted" && r.party === "node" && r.route === "batch",
  );
  if (unlistedQueries.length !== 0) {
    throw new Error(
      `path: the unlisted commitment sent ${unlistedQueries.length} PIR batch(es) before its ` +
        `refusal; the node's index gives it candidates [${index.unlistedCandidates.join(", ")}]`,
    );
  }

  const resolved = await phase("oracle-root", () =>
    new UpstreamPinResolver({
      endpoint: options.aggregator,
      fetchImpl: meter.fetch,
      chainType: 0,
      chainId,
      txidVersion: TXID_VERSION,
    }).resolve(OFAC_LIST_KEY, block),
  );
  // The SDK already checked the fold against a pin or the aggregator. This asks upstream again,
  // outside the SDK, so a pin the SDK trusted cannot vouch for its own path.
  if (!resolved.roots.has(folded)) {
    throw new Error(
      `path: siblings fold to ${folded}, which is not among the ${resolved.roots.size} root(s) ` +
        `upstream certifies for block ${block}`,
    );
  }
  // The resolver is SDK code, so a fault in how it reads upstream would pass the SDK's own check
  // and the one above alike. This root was read by the harness.
  if (folded !== event.root) {
    throw new Error(
      `path: siblings fold to ${folded}, which upstream certifies now, but its event at index ` +
        `${KNOWN_INDEX} recorded ${event.root}`,
    );
  }

  const strangers = meter.log.filter((r) => r.party === "other");
  if (strangers.length !== 0) {
    throw new Error(
      `the SDK contacted a third party: ${strangers
        .map((r) => (r.finalUrl === r.url ? r.url : `${r.url} -> ${r.finalUrl}`))
        .join(", ")}`,
    );
  }
  const sentBySdk = meter.log.filter((r) => !r.phase.startsWith("oracle"));
  assertNoCommitmentsAnywhere(sentBySdk, [KNOWN_BC, UNLISTED_BC]);
  for (const r of sentBySdk) {
    const url = r.url.toLowerCase();
    if (url.includes(KNOWN_BC) || url.includes(UNLISTED_BC)) {
      throw new Error(`the SDK put a commitment in a URL: ${r.url}`);
    }
  }

  const totals = { node: { requests: 0, up: 0, down: 0 }, aggregator: { requests: 0, up: 0, down: 0 }, other: { requests: 0, up: 0, down: 0 } };
  for (const r of meter.log) {
    totals[r.party].requests += 1;
    totals[r.party].up += r.up;
    totals[r.party].down += r.down;
  }

  return {
    node: options.node,
    aggregator: options.aggregator,
    startedAt,
    listKey: OFAC_LIST_KEY,
    knownIndex: KNOWN_INDEX,
    knownBc: KNOWN_BC,
    unlistedBc: UNLISTED_BC,
    membership: MEMBERSHIP_STATEMENT,
    params: { [options.statusInstance]: statusLoad.summary, [pathInstance]: pathLoad.summary },
    status: {
      listed: { node: nodeListed, oracle: oracleListed },
      unlisted: { node: nodeUnlisted ?? "", oracle: oracleUnlisted },
    },
    path: {
      block,
      leafIndex: localIndex,
      root: folded,
      oracleEventRoot: event.root,
      resolverRoots: Array.from(resolved.roots),
      resolverWindow:
        `${resolved.window.startIndex}..${resolved.window.endIndex} ` +
        `(${resolved.window.frozen ? "frozen" : "filling"})`,
    },
    index,
    statusHeader: { blocked: header.blockedBcs.length, pending: header.pendingBcs.length },
    jsonIndex,
    phases: totalsByPhase(meter.log, phaseMs),
    totals,
    encodedResponses: meter.log.filter((r) => r.encoding !== null && r.encoding !== "identity").length,
    wallClockMs: performance.now() - started,
  };
}
