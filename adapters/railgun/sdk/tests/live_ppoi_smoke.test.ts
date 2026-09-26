// The PPOI acceptance smoke. The live case skips unless RAVEN_LIVE_URL names a Raven node and
// RAVEN_PIN_UPSTREAM names a PPOI aggregator, so CI makes no network calls. The rest runs the
// same harness against an in-process node and aggregator, so the harness itself is exercised on
// every run and cannot rot the way the live tier's wire literals did.
//
// Live, alone: `vitest run --config tests/vitest.config.ts tests/live_ppoi_smoke.test.ts` with
// those two set. RAVEN_LIVE_TOKEN is sent to the node when set. RAVEN_LIVE_PPOI_STATUS_INSTANCE
// and RAVEN_LIVE_PPOI_PATH_INSTANCE_PREFIX name the instances when the deployment's ids differ
// from the shipped example's. The report lands in RAVEN_BENCH_FINDINGS_DIR as ppoi-smoke.json.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  BC_INDEX_PREFIX_BYTES,
  LEAVES_PER_PPOI_BLOCK,
  RavenError,
  decodeClientPirQueryBundle,
  foldMerkleRoot,
  installPanicHook,
  type BlindedCommitmentData,
  type Chain,
  type MerkleProof,
  type RavenInspireWasm,
} from "../src/index";
import { encodeBatchResponseNodes } from "./helpers/auth_path_stub";
import {
  LIVE_AGGREGATOR,
  LIVE_TOKEN,
  LIVE_URL,
  PPOI_STATUS_INSTANCE,
  decodeBatchResponse,
  decodeInstanceParams,
  encodeInstanceParams,
  ppoiPathInstance,
  stripVersionedResponse,
  versionedBatchBody,
  versionedQueryBody,
} from "./helpers/live_wire";
import {
  readJsonRpcRequest,
  startMockServer,
  writeBinary,
  writeJson,
  writeJsonRpcResult,
  type MockServer,
} from "./helpers/mock_server";
import { path10Slot } from "./helpers/path10_row";
import {
  KNOWN_BC,
  KNOWN_BLOCK_ROOT,
  KNOWN_INDEX,
  KNOWN_PROOF_LEAF,
  KNOWN_PROOF_ROOT,
  KNOWN_SIBLINGS,
  OFAC_LIST_KEY,
  UNLISTED_BC,
  UNLISTED_PHRASE,
  runPpoiSmoke,
  type PpoiSmokeOptions,
  type PpoiSmokeReport,
  type SmokeSdk,
} from "./helpers/ppoi_smoke";
import {
  batchTargets,
  commitmentAt,
  mountPrefixChannel,
  statusRow,
  targetNamingCtx,
  type MockList,
} from "./helpers/prefix_channel";
import { shardConfigBincode } from "./helpers/shard_config";
import { EXPECTED_WIRE_SCHEMA_VERSION } from "./helpers/wire_schema";

const liveIt = LIVE_URL !== undefined && LIVE_AGGREGATOR !== undefined ? it : it.skip;

const HERE = dirname(fileURLToPath(import.meta.url));
const FINDINGS_DIR =
  process.env.RAVEN_BENCH_FINDINGS_DIR ?? resolve(HERE, "..", "..", "..", "target", "bench-findings");

const LIST_ROWS = KNOWN_INDEX + 5;
const STATUS_ROWS = 131_072;
const PATH_ROWS = 65_536;
const PATH_ENTRY_BYTES = 512;
const PATH_SLOT_BYTES = PATH_ENTRY_BYTES + 160;
const STUB_QUERY_BYTES = 64;
const STATUS_BYTE_MISSING = 3;

/** Upstream's list. The node serves it too unless a fault says otherwise. */
const UPSTREAM_LIST: readonly string[] = Array.from({ length: LIST_ROWS }, (_u, i) =>
  i === KNOWN_INDEX ? KNOWN_BC : commitmentAt(i),
);
const MEMBERS = new Set(UPSTREAM_LIST);
/** Shares the unlisted commitment's index prefix and nothing after it. */
const UNLISTED_TWIN =
  UNLISTED_BC.slice(0, 2 * BC_INDEX_PREFIX_BYTES) + "cd".repeat(32 - BC_INDEX_PREFIX_BYTES);
const OTHER_LIST_KEY = "ab".repeat(32);
const MOVED = "11".repeat(32);
const HEADER_PATH = `/v1/poi/${OFAC_LIST_KEY}/status-header`;

interface RigFaults {
  /** Wire schema the node's params envelope declares; the body's own field follows it. */
  readonly schema?: number;
  /** Wire schema the params body declares, when it differs from the envelope. */
  readonly innerSchema?: number;
  /** Rows where the node's list departs from upstream's. */
  readonly nodeRows?: Readonly<Record<number, string>>;
  /** Status bytes the node serves by row; Valid (0) everywhere else. */
  readonly statusBytes?: Readonly<Record<number, number>>;
  /** A sibling level the node corrupts in every path it serves. */
  readonly forgedLevel?: number;
  readonly headerListKey?: string;
  /** The node sends the status header's request on to another origin. */
  readonly redirectHeader?: boolean;
  readonly jsonIndex?: "unserved" | "wrong-row";
  /** The aggregator answers Valid for every commitment. */
  readonly oracleAnswersValid?: boolean;
  /** The aggregator's event at the known index differs from the recorded one in this field. */
  readonly movedEvent?: "blindedCommitment" | "validatedMerkleroot";
  readonly eventType?: string;
  /** Every event read after the first answers this root. */
  readonly laterRoot?: string;
}

function hexBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function statusHeaderBody(listKey: string): unknown {
  return { epoch: 0, listKey, blockedBcs: [], pendingBcs: [] };
}

function mountNode(node: MockServer, stranger: MockServer, faults: RigFaults): void {
  const list: MockList = { commitments: [...UPSTREAM_LIST] };
  for (const [row, bc] of Object.entries(faults.nodeRows ?? {})) list.commitments[Number(row)] = bc;
  const siblings = KNOWN_SIBLINGS.map(hexBytes);
  if (faults.forgedLevel !== undefined) siblings[faults.forgedLevel][31] ^= 1;

  node.route(
    (req) => req.method === "GET" && /^\/v1\/instance\/[^/]+\/params$/.test(req.url ?? ""),
    (req, _body, res) => {
      const id = decodeURIComponent(/^\/v1\/instance\/([^/]+)\/params$/.exec(req.url ?? "")?.[1] ?? "");
      const shape =
        id === "ppoi-status-ofac"
          ? { rows: STATUS_ROWS, entry: 32 }
          : id === "ppoi-paths-ofac-0"
            ? { rows: PATH_ROWS, entry: PATH_ENTRY_BYTES }
            : undefined;
      if (shape === undefined) return false;
      const body = encodeInstanceParams(
        {
          crsBincode: new Uint8Array([1, 2, 3]),
          shardConfigBincode: shardConfigBincode(shape.rows, shape.entry),
          inspireParamsBincode: new Uint8Array([4, 5]),
          entrySize: shape.entry,
          variant: "InspiRING",
          epoch: 1n,
        },
        faults.schema,
        faults.innerSchema,
      );
      writeBinary(res, body);
      return true;
    },
  );
  node.route(
    (req) => req.url === "/v1/instance/ppoi-status-ofac/batch",
    (_req, body, res) => {
      const rows = batchTargets(body).map((target) =>
        target < list.commitments.length
          ? statusRow(faults.statusBytes?.[target] ?? 0, list.commitments[target])
          : new Uint8Array(32),
      );
      writeBinary(res, encodeBatchResponseNodes(rows));
      return true;
    },
  );
  node.route(
    (req) => req.url === "/v1/instance/ppoi-paths-ofac-0/batch",
    (_req, body, res) => {
      const slots = batchTargets(body).map((target) =>
        target < list.commitments.length
          ? path10Slot({ bcHex: list.commitments[target], nodes: siblings })
          : new Uint8Array(PATH_SLOT_BYTES),
      );
      writeBinary(res, encodeBatchResponseNodes(slots));
      return true;
    },
  );
  mountPrefixChannel(node, OFAC_LIST_KEY, list);
  node.route(
    (req) => req.url === HEADER_PATH,
    (_req, _body, res) => {
      if (faults.redirectHeader === true) {
        res.writeHead(307, { location: `${stranger.url}${HEADER_PATH}` });
        res.end();
      } else {
        writeJson(res, statusHeaderBody(faults.headerListKey ?? OFAC_LIST_KEY));
      }
      return true;
    },
  );
  stranger.route(
    (req) => req.url === HEADER_PATH,
    (_req, _body, res) => {
      writeJson(res, statusHeaderBody(OFAC_LIST_KEY));
      return true;
    },
  );
  node.route(
    (req) => req.url === `/v1/poi/${OFAC_LIST_KEY}/bc-to-idx-map`,
    (_req, _body, res) => {
      if (faults.jsonIndex === "unserved") return false;
      writeJson(res, {
        epoch: 0,
        listKey: OFAC_LIST_KEY,
        entries: list.commitments.map((bc, idx) => ({
          bc: faults.jsonIndex === "wrong-row" && idx === KNOWN_INDEX ? commitmentAt(idx) : bc,
          idx,
        })),
      });
      return true;
    },
  );
}

function mountAggregator(aggregator: MockServer, faults: RigFaults): void {
  let eventReads = 0;
  aggregator.route(
    (req) => req.method === "POST",
    (_req, body, res) => {
      const { method, params } = readJsonRpcRequest(body);
      if (method === "ppoi_poi_events") {
        eventReads += 1;
        const start = Number(params.startIndex);
        const end = Number(params.endIndex);
        const root =
          eventReads > 1 && faults.laterRoot !== undefined
            ? faults.laterRoot
            : faults.movedEvent === "validatedMerkleroot"
              ? MOVED
              : KNOWN_BLOCK_ROOT;
        const rows =
          params.listKey === OFAC_LIST_KEY && start <= KNOWN_INDEX && KNOWN_INDEX <= end
            ? [
                {
                  signedPOIEvent: {
                    index: KNOWN_INDEX,
                    blindedCommitment: `0x${faults.movedEvent === "blindedCommitment" ? MOVED : KNOWN_BC}`,
                    signature: "00".repeat(64),
                    type: faults.eventType ?? "Transact",
                  },
                  validatedMerkleroot: root,
                },
              ]
            : [];
        writeJsonRpcResult(body, res, rows);
        return true;
      }
      if (method === "ppoi_pois_per_list") {
        const datas = params.blindedCommitmentDatas as { blindedCommitment: string }[];
        const result: Record<string, Record<string, string>> = {};
        for (const { blindedCommitment } of datas) {
          const member = MEMBERS.has(blindedCommitment.replace(/^0x/, "").toLowerCase());
          result[blindedCommitment] = {
            [OFAC_LIST_KEY]: member || faults.oracleAnswersValid === true ? "Valid" : "Missing",
          };
        }
        writeJsonRpcResult(body, res, result);
        return true;
      }
      return false;
    },
  );
}

type WrapSdk = NonNullable<PpoiSmokeOptions["wrapSdk"]>;

/** The real SDK with some of its calls replaced, playing an SDK with a defect. */
function faultySdk(
  overrides: (sdk: SmokeSdk, meteredFetch: typeof fetch) => Partial<SmokeSdk>,
): WrapSdk {
  return (sdk, meteredFetch) => ({
    syncPoiListIndex: sdk.syncPoiListIndex.bind(sdk),
    poiListIndexCandidates: sdk.poiListIndexCandidates.bind(sdk),
    fetchStatusHeader: sdk.fetchStatusHeader.bind(sdk),
    fetchBcToIdxMap: sdk.fetchBcToIdxMap.bind(sdk),
    getPOIsPerList: sdk.getPOIsPerList.bind(sdk),
    getPOIMerkleProofs: sdk.getPOIMerkleProofs.bind(sdk),
    ...overrides(sdk, meteredFetch),
  });
}

function editedProofs(edit: (proof: MerkleProof) => MerkleProof): WrapSdk {
  return faultySdk((sdk) => ({
    getPOIMerkleProofs: (async (txidVersion: string, chain: Chain, listKey: string, bcs: string[]) =>
      (await sdk.getPOIMerkleProofs(txidVersion, chain, listKey, bcs)).map(edit)) as SmokeSdk["getPOIMerkleProofs"],
  }));
}

function forgedRootAtLevel(level: number): string {
  const forged = KNOWN_SIBLINGS.map(hexBytes);
  forged[level][31] ^= 1;
  return foldMerkleRoot(
    KNOWN_BC,
    forged.map((b) => Buffer.from(b).toString("hex")),
    BigInt(KNOWN_INDEX),
  );
}

describe("PPOI acceptance smoke against a local node and aggregator", () => {
  let node: MockServer;
  let aggregator: MockServer;
  let stranger: MockServer;

  beforeAll(async () => {
    node = await startMockServer();
    aggregator = await startMockServer();
    stranger = await startMockServer();
  });
  afterAll(async () => {
    await node.close();
    await aggregator.close();
    await stranger.close();
  });
  afterEach(() => {
    node.reset();
    aggregator.reset();
    stranger.reset();
  });

  function smoke(
    faults: RigFaults = {},
    fetchImpl?: typeof fetch,
    extra: Pick<PpoiSmokeOptions, "bearerToken" | "sdkPinnedRoots" | "wrapSdk"> = {},
  ): Promise<PpoiSmokeReport> {
    mountNode(node, stranger, faults);
    mountAggregator(aggregator, faults);
    return runPpoiSmoke({
      node: node.url,
      aggregator: aggregator.url,
      wasm: targetNamingCtx().wasm,
      statusInstance: "ppoi-status-ofac",
      pathInstanceForBlock: (block) => `ppoi-paths-ofac-${block}`,
      fetchImpl,
      ...extra,
    });
  }

  it("the recorded capture is the last leaf of block 0 and its path folds to its root", () => {
    const request = JSON.parse(
      readFileSync(new URL("./fixtures/ppoi-aggregator/01-ppoi_poi_events.request.json", import.meta.url), "utf8"),
    ) as { params: { listKey: string; startIndex: number; endIndex: number } };
    expect(request.params).toMatchObject({ listKey: OFAC_LIST_KEY, startIndex: KNOWN_INDEX, endIndex: KNOWN_INDEX });
    expect(KNOWN_INDEX).toBe(LEAVES_PER_PPOI_BLOCK - 1);
    expect(KNOWN_PROOF_LEAF).toBe(KNOWN_BC);
    expect(KNOWN_PROOF_ROOT).toBe(KNOWN_BLOCK_ROOT);
    expect(KNOWN_SIBLINGS).toHaveLength(16);
    expect(foldMerkleRoot(KNOWN_BC, [...KNOWN_SIBLINGS], BigInt(KNOWN_INDEX))).toBe(KNOWN_BLOCK_ROOT);
  });

  it("derives the unlisted commitment from its phrase, inside the field", () => {
    expect(UNLISTED_PHRASE).toBe("raven ppoi smoke: a commitment on no list");
    expect(UNLISTED_BC).toMatch(/^0[0-9a-f]{63}$/);
    expect(MEMBERS.has(UNLISTED_BC)).toBe(false);
  });

  it("passes against an honest pair, recording bytes and wall clock per phase", async () => {
    const sent: { url: string; body: Uint8Array }[] = [];
    const recording: typeof fetch = async (input, init) => {
      const body = init?.body instanceof Blob ? new Uint8Array(await init.body.arrayBuffer()) : new Uint8Array();
      sent.push({ url: String(input), body });
      return fetch(input, init);
    };

    const report = await smoke({}, recording);

    expect(report.status.listed).toEqual({ node: "Valid", oracle: "Valid" });
    expect(report.status.unlisted).toEqual({ node: "Missing", oracle: "Missing" });
    expect(report.path.root).toBe(KNOWN_BLOCK_ROOT);
    expect(report.path.oracleEventRoot).toBe(KNOWN_BLOCK_ROOT);
    expect(report.path.resolverRoots).toEqual([KNOWN_BLOCK_ROOT]);
    expect(report.path.resolverWindow).toBe(`${KNOWN_INDEX}..${KNOWN_INDEX} (frozen)`);
    expect(report.index).toEqual({ total: LIST_ROWS, candidates: [KNOWN_INDEX], unlistedCandidates: [] });
    expect(report.jsonIndex).toEqual({ served: true, rows: LIST_ROWS });
    expect(report.statusHeader).toEqual({ blocked: 0, pending: 0 });
    for (const summary of Object.values(report.params)) {
      expect(summary.wireSchema).toBe(EXPECTED_WIRE_SCHEMA_VERSION);
    }
    expect(report.totals.other.requests).toBe(0);
    expect(report.encodedResponses).toBe(0);
    expect(report.wallClockMs).toBeGreaterThan(0);
    for (const r of node.requests) expect(r.headers.authorization, r.url).toBeUndefined();
    expect(stranger.requests).toHaveLength(0);
    expect(report.phases.map((p) => p.phase)).toEqual([
      "params",
      "oracle-event",
      "oracle-status",
      "index",
      "status-header",
      "json-index",
      "status",
      "path",
      "path-unlisted",
      "oracle-root",
    ]);

    // The traffic a live run is authorized for: one prefix request per started block (two here),
    // again before the JSON map it checks, a frontier re-read per later SDK call, one packing-key
    // upload per PIR instance.
    const requestsByPhase = Object.fromEntries(
      report.phases.map((p) => [
        p.phase,
        Object.fromEntries(Object.entries(p.byRoute).map(([route, t]) => [route, t.requests])),
      ]),
    );
    expect(requestsByPhase).toEqual({
      params: { "node:params": 2 },
      "oracle-event": { "aggregator:ppoi_poi_events": 1 },
      "oracle-status": { "aggregator:ppoi_pois_per_list": 1 },
      index: { "node:bc-prefixes": 2 },
      "status-header": { "node:status-header": 1 },
      "json-index": { "node:bc-to-idx-map": 1, "node:bc-prefixes": 2 },
      status: { "node:bc-prefixes": 1, "node:session": 1, "node:batch": 1 },
      path: {
        "node:bc-prefixes": 1,
        "node:session": 1,
        "node:batch": 1,
        "aggregator:ppoi_poi_events": 1,
      },
      "path-unlisted": { "node:bc-prefixes": 1 },
      "oracle-root": { "aggregator:ppoi_poi_events": 1 },
    });
    expect(report.totals.node.requests).toBe(15);
    expect(report.totals.aggregator.requests).toBe(4);

    // One stub query up, one 672-byte slot down, each inside the versioned batch frame.
    const path = report.phases.find((p) => p.phase === "path");
    expect(path?.byRoute["node:batch"]).toEqual({ requests: 1, up: 2 + 8 + STUB_QUERY_BYTES, down: 2 + 8 + 8 + PATH_SLOT_BYTES });
    const status = report.phases.find((p) => p.phase === "status");
    expect(status?.byRoute["node:batch"]).toEqual({ requests: 1, up: 2 + 8 + STUB_QUERY_BYTES, down: 2 + 8 + 8 + 32 });

    // The live tier frames its hand-rolled batches with this helper; it must match the SDK's frame.
    const wasm = targetNamingCtx().wasm;
    const query = decodeClientPirQueryBundle(
      wasm.build_seeded_query({ free: () => undefined }, new Uint8Array(), BigInt(KNOWN_INDEX)),
    ).queryBytes;
    const pathBatch = sent.find((r) => r.url.endsWith("/v1/instance/ppoi-paths-ofac-0/batch"));
    expect(pathBatch?.body).toEqual(versionedBatchBody([query]));
  });

  it("refuses a node on another wire schema before asking the aggregator anything", async () => {
    await expect(smoke({ schema: EXPECTED_WIRE_SCHEMA_VERSION - 1 })).rejects.toThrow(
      `envelope is wire schema ${EXPECTED_WIRE_SCHEMA_VERSION - 1}, this client speaks ${EXPECTED_WIRE_SCHEMA_VERSION}`,
    );
    expect(aggregator.requests).toHaveLength(0);
  });

  it("refuses params whose body declares another wire schema than their envelope", async () => {
    await expect(smoke({ innerSchema: EXPECTED_WIRE_SCHEMA_VERSION - 1 })).rejects.toThrow(
      `instance params: body declares wire schema ${EXPECTED_WIRE_SCHEMA_VERSION - 1}, ` +
        `this client speaks ${EXPECTED_WIRE_SCHEMA_VERSION}`,
    );
    expect(aggregator.requests).toHaveLength(0);
  });

  it.each([
    [{ movedEvent: "blindedCommitment" }, `upstream's commitment at index ${KNOWN_INDEX} is 0x${MOVED}, recorded as ${KNOWN_BC}`],
    [{ movedEvent: "validatedMerkleroot" }, `upstream's root at index ${KNOWN_INDEX} is ${MOVED}, recorded as ${KNOWN_BLOCK_ROOT}`],
    [{ eventType: "Bogus" }, "oracle: event type Bogus is not a wallet commitment type"],
  ] as const)("refuses an upstream event that is not the recorded one (%o), before the SDK runs", async (faults, message) => {
    await expect(smoke(faults)).rejects.toThrow(message);
    expect(node.requests.filter((r) => !r.url.endsWith("/params"))).toHaveLength(0);
  });

  it("catches a status the node serves that the aggregator does not", async () => {
    await expect(smoke({ statusBytes: { [KNOWN_INDEX]: 1 } })).rejects.toThrow(
      "status: the node answers listed=ShieldBlocked unlisted=Missing, upstream answers listed=Valid unlisted=Missing",
    );
  });

  it("catches a node that answers Valid for a commitment upstream does not list", async () => {
    await expect(smoke({ nodeRows: { [KNOWN_INDEX - 1]: UNLISTED_BC } })).rejects.toThrow(
      "status: the node answers listed=Valid unlisted=Valid, upstream answers listed=Valid unlisted=Missing",
    );
  });

  it("refuses an oracle that answers a member and a non-member alike", async () => {
    await expect(smoke({ oracleAnswersValid: true })).rejects.toThrow(
      "upstream answers Valid for both the member and the non-member",
    );
  });

  it("catches a node whose index holds the known commitment at another row", async () => {
    await expect(
      smoke({ nodeRows: { [KNOWN_INDEX]: commitmentAt(KNOWN_INDEX), [KNOWN_INDEX - 2]: KNOWN_BC } }),
    ).rejects.toThrow(
      `index: the node's list of ${LIST_ROWS} rows gives ${KNOWN_BC} candidates [${KNOWN_INDEX - 2}], ` +
        `not the upstream index ${KNOWN_INDEX}`,
    );
  });

  it("catches a JSON index row that names another commitment", async () => {
    await expect(smoke({ jsonIndex: "wrong-row" })).rejects.toThrow(
      `bc-to-idx-map: row ${KNOWN_INDEX} differs from the node's prefix channel`,
    );
  });

  it("passes against a node built without the JSON index, and says it was not served", async () => {
    const report = await smoke({ jsonIndex: "unserved" });
    expect(report.jsonIndex).toEqual({ served: false });
  });

  it("catches a status header answered for another list", async () => {
    await expect(smoke({ headerListKey: OTHER_LIST_KEY })).rejects.toThrow(
      `status-header: answered for list ${OTHER_LIST_KEY}`,
    );
  });

  it("refuses a served path that does not fold to the aggregator's root", async () => {
    let thrown: unknown;
    try {
      await smoke({ forgedLevel: 7 });
    } catch (e) {
      thrown = e;
    }
    expect(RavenError.is(thrown, "DecodeError"), String(thrown)).toBe(true);
    expect(String((thrown as Error).message)).toContain(`${KNOWN_INDEX}..${KNOWN_INDEX} (frozen block)`);
  });

  it("sends the node's credential to the node and never to the aggregator", async () => {
    const token = "live-smoke-read-token";
    await smoke({}, undefined, { bearerToken: token });
    expect(node.requests.length).toBeGreaterThan(0);
    for (const r of node.requests) {
      expect(r.headers.authorization, r.url).toBe(`Bearer ${token}`);
    }
    expect(aggregator.requests.length).toBeGreaterThan(0);
    for (const r of aggregator.requests) {
      expect(r.headers.authorization, r.url).toBeUndefined();
    }
  });

  it("catches a path the SDK accepted on a wrong pin, by its own upstream check", async () => {
    const forgedRoot = forgedRootAtLevel(7);
    expect(forgedRoot).not.toBe(KNOWN_BLOCK_ROOT);
    await expect(
      smoke({ forgedLevel: 7 }, undefined, {
        sdkPinnedRoots: new Map([[`1:${OFAC_LIST_KEY}:0`, forgedRoot]]),
      }),
    ).rejects.toThrow(
      `path: siblings fold to ${forgedRoot}, which is not among the 1 root(s) upstream certifies for block 0`,
    );
  });

  it("catches an upstream that certifies a root its own recorded event did not", async () => {
    const forgedRoot = forgedRootAtLevel(7);
    await expect(smoke({ forgedLevel: 7, laterRoot: forgedRoot })).rejects.toThrow(
      `path: siblings fold to ${forgedRoot}, which upstream certifies now, but its event at index ` +
        `${KNOWN_INDEX} recorded ${KNOWN_BLOCK_ROOT}`,
    );
  });

  it("catches an unlisted commitment the node's list holds in block 0, which the SDK then queries", async () => {
    await expect(
      smoke({
        nodeRows: { [KNOWN_INDEX - 1]: UNLISTED_BC },
        statusBytes: { [KNOWN_INDEX - 1]: STATUS_BYTE_MISSING },
      }),
    ).rejects.toThrow(/not refused as absent: .*folded root is not among the 1 root\(s\) upstream certifies/);
  });

  it("catches an unlisted commitment refused for a reason other than its absence", async () => {
    await expect(
      smoke({
        nodeRows: { [KNOWN_INDEX + 1]: UNLISTED_BC },
        statusBytes: { [KNOWN_INDEX + 1]: STATUS_BYTE_MISSING },
      }),
    ).rejects.toThrow(/not refused as absent: .*past the instance's capacity/);
  });

  it("catches an unlisted commitment whose refusal cost a PIR query, from a prefix twin on the list", async () => {
    expect(UNLISTED_TWIN.slice(0, 2 * BC_INDEX_PREFIX_BYTES)).toBe(UNLISTED_BC.slice(0, 2 * BC_INDEX_PREFIX_BYTES));
    expect(UNLISTED_TWIN).not.toBe(UNLISTED_BC);
    await expect(smoke({ nodeRows: { [KNOWN_INDEX - 1]: UNLISTED_TWIN } })).rejects.toThrow(
      `path: the unlisted commitment sent 1 PIR batch(es) before its refusal; the node's index ` +
        `gives it candidates [${KNOWN_INDEX - 1}]`,
    );
  });

  it.each([
    [
      "for another commitment",
      (p: MerkleProof) => ({ ...p, leaf: UNLISTED_BC }),
      `path: expected one proof for ${KNOWN_BC}, got `,
    ],
    [
      "for another leaf position",
      (p: MerkleProof) => ({ ...p, indices: "00".repeat(32) }),
      `path: proof is for leaf 0, not ${KNOWN_INDEX}`,
    ],
    [
      "whose root is not its own fold",
      (p: MerkleProof) => ({ ...p, root: MOVED }),
      `path: siblings fold to ${KNOWN_BLOCK_ROOT}, the proof claims ${MOVED}`,
    ],
  ] as const)("catches an SDK proof %s", async (_what, edit, message) => {
    await expect(smoke({}, undefined, { wrapSdk: editedProofs(edit) })).rejects.toThrow(message);
  });

  it("catches an SDK that sends a commitment in a request body", async () => {
    const leaky = faultySdk((sdk, meteredFetch) => ({
      getPOIsPerList: (async (txidVersion: string, chain: Chain, listKeys: string[], datas: BlindedCommitmentData[]) => {
        await meteredFetch(`${node.url}/v1/poi/pois-per-list`, { method: "POST", body: JSON.stringify(datas) });
        return sdk.getPOIsPerList(txidVersion, chain, listKeys, datas);
      }) as SmokeSdk["getPOIsPerList"],
    }));
    await expect(smoke({}, undefined, { wrapSdk: leaky })).rejects.toThrow(
      `contains 0x-prefixed ASCII blinded commitment ${KNOWN_BC}`,
    );
  });

  it("catches an SDK that puts a commitment in a URL", async () => {
    const leaky = faultySdk((sdk, meteredFetch) => ({
      fetchStatusHeader: async (listKey: string) => {
        await meteredFetch(`${node.url}/v1/poi/${listKey}/${KNOWN_BC}`);
        return sdk.fetchStatusHeader(listKey);
      },
    }));
    await expect(smoke({}, undefined, { wrapSdk: leaky })).rejects.toThrow(
      `the SDK put a commitment in a URL: ${node.url}/v1/poi/${OFAC_LIST_KEY}/${KNOWN_BC}`,
    );
  });

  it("catches a node that redirects the SDK to a third party", async () => {
    await expect(smoke({ redirectHeader: true })).rejects.toThrow(
      `the SDK contacted a third party: ${node.url}${HEADER_PATH} -> ${stranger.url}${HEADER_PATH}`,
    );
    expect(stranger.requests).toHaveLength(1);
  });

  it("frames and unframes the live tier's hand-rolled requests at the pinned schema", () => {
    const nodes = [hexBytes(KNOWN_BC), hexBytes(UNLISTED_BC)];
    expect(decodeBatchResponse(encodeBatchResponseNodes(nodes), "batch")).toEqual(nodes);
    const query = versionedQueryBody(new Uint8Array([9, 9]));
    expect(Array.from(query)).toEqual([EXPECTED_WIRE_SCHEMA_VERSION >>> 8, EXPECTED_WIRE_SCHEMA_VERSION & 0xff, 9, 9]);
    expect(stripVersionedResponse(query, "query")).toEqual(new Uint8Array([9, 9]));
    const stale = new Uint8Array(query);
    stale[1] -= 1;
    expect(() => stripVersionedResponse(stale, "query")).toThrow(
      `response is wire schema ${EXPECTED_WIRE_SCHEMA_VERSION - 1}`,
    );
    const params = encodeInstanceParams({
      crsBincode: new Uint8Array([7]),
      shardConfigBincode: shardConfigBincode(),
      inspireParamsBincode: new Uint8Array(),
      entrySize: 32,
      variant: "InspiRING",
      epoch: 2n ** 40n + 3n,
    });
    const decoded = decodeInstanceParams(params);
    expect(decoded.epoch).toBe(2n ** 40n + 3n);
    expect(decoded.variant).toBe("InspiRING");
    expect(() => decodeInstanceParams(params.subarray(0, params.length - 1))).toThrow("epoch must end the body");
  });
});

describe("PPOI acceptance smoke against the real deployment", () => {
  liveIt(
    "a known commitment's status and path, each verified against the aggregator",
    async () => {
      const wasm = (await import("raven-inspire-client-wasm")) as unknown as RavenInspireWasm;
      installPanicHook(wasm);
      const report = await runPpoiSmoke({
        node: LIVE_URL as string,
        aggregator: LIVE_AGGREGATOR as string,
        wasm,
        statusInstance: PPOI_STATUS_INSTANCE,
        pathInstanceForBlock: ppoiPathInstance,
        bearerToken: LIVE_TOKEN,
      });
      mkdirSync(FINDINGS_DIR, { recursive: true });
      const out = join(FINDINGS_DIR, "ppoi-smoke.json");
      writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);
      process.stderr.write(`\n[ppoi-smoke] ${report.membership}\n`);
      for (const p of report.phases) {
        process.stderr.write(
          `[ppoi-smoke] ${p.phase.padEnd(14)} requests=${p.requests} up=${p.up}B down=${p.down}B ms=${p.ms.toFixed(1)}\n`,
        );
      }
      if (report.encodedResponses > 0) {
        process.stderr.write(
          `[ppoi-smoke] ${report.encodedResponses} response(s) arrived content-encoded; down bytes are decoded sizes\n`,
        );
      }
      process.stderr.write(`[ppoi-smoke] wall clock ${report.wallClockMs.toFixed(1)} ms; report at ${out}\n`);
    },
    1_800_000,
  );
});
