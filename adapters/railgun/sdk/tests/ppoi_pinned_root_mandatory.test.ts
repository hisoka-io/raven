// The pinned root is the ONLY thing standing between a PIR-served path-10 row and a
// forged merkle proof: the siblings arrive from the server, the fold is local, and a
// wrong sibling set folds to a wrong root that still looks like a proof. Before this
// file the guard was keyed on the chain-less label `t2Path:<lk>:<block>` while
// `instanceLabel()` resolves the chain-aware `t2Path:<chainId>:<lk>:<block>` FIRST --
// so in the primary configuration the guard never fired and an unverified proof was
// returned `Ok`. That is this codebase's signature defect (AGENTS.md:39) and its
// eighth recorded recurrence of "guard keyed on one thing, routing on another".

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  LEAVES_PER_PPOI_BLOCK,
  PIN_TAIL_WINDOW,
  RavenError,
  RavenPOINodeInterface,
  UpstreamPinResolver,
  ppoiNetworkName,
  type ClientPirContext,
  type RavenErrorKind,
} from "../src/index";
import { encodeBatchResponseNodes, stubCtx as nodeStubCtx } from "./helpers/auth_path_stub";
import {
  readJsonRpcRequest,
  startMockServer,
  writeJsonRpcResult,
  type MockServer,
} from "./helpers/mock_server";
import { foldMerkleRoot } from "../src/poseidon";
import { assertNoCommitmentsAnywhere } from "./helpers/private_wire";

const TOKEN = "test-token-padded-long-enough-1234";
const MAINNET = 1;
const POLYGON = 137;
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";
const BC_HEX = "9f3c17aa04e1b28d6605c9713fe82b40d1a7c35e96280bf4517ade0c2b6d8391";
const GLOBAL_INDEX = 65_536 + 7; // block 1, local leaf 7 -- exercises the non-zero block.
const BLOCK = Math.floor(GLOBAL_INDEX / 65_536);
const LOCAL_INDEX = GLOBAL_INDEX % 65_536;
const ROW_BYTES = 512;
const ADDENDUM_BYTES = 160;

/** Sixteen deterministic siblings, distinct per level so a dropped level changes the root. */
function siblings(marker: number): Uint8Array[] {
  return Array.from({ length: 16 }, (_unused, level) => {
    const node = new Uint8Array(32);
    node[0] = marker;
    node[31] = level + 1;
    return node;
  });
}

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

/**
 * One served slot exactly as the Rust encoder lays it out: a 512 B path-10 row
 * (`RVP2` magic, levels 0..10) with the 160 B levels-11..15 addendum appended, which
 * `runClientPirQueryBatch` splits off the tail.
 */
function servedSlot(nodes: Uint8Array[]): Uint8Array {
  const row = new Uint8Array(ROW_BYTES);
  row.set(Buffer.from(BC_HEX, "hex"), 0);
  row[32] = 0; // status
  row[33] = 0; // event type
  row.set(new TextEncoder().encode("RVP2"), 34);
  for (let level = 0; level < 11; level += 1) {
    row.set(nodes[level], 38 + level * 32);
  }
  const addendum = new Uint8Array(ADDENDUM_BYTES);
  for (let level = 0; level < 5; level += 1) {
    addendum.set(nodes[11 + level], level * 32);
  }
  const slot = new Uint8Array(ROW_BYTES + ADDENDUM_BYTES);
  slot.set(row, 0);
  slot.set(addendum, ROW_BYTES);
  return slot;
}

function mountRowRoute(server: MockServer, nodes: Uint8Array[]): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, _body, res) => {
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "x-raven-epoch": "1",
        "x-raven-schema-version": "7",
        "x-raven-freshness": "lag_blocks=0 applied_height=0 epoch=1 confidence=1",
      });
      res.end(Buffer.from(encodeBatchResponseNodes([servedSlot(nodes)])));
      return true;
    },
  );
}

function pathCtx(): ClientPirContext {
  return { ...nodeStubCtx(), entrySize: ROW_BYTES };
}

interface Options {
  readonly chainId?: number;
  readonly labels?: [string, string][];
  readonly pinnedRoots?: [string, string][];
  readonly pinUpstream?: string | false;
}

function makeSdk(server: MockServer, options: Options): RavenPOINodeInterface {
  return new RavenPOINodeInterface({
    endpoint: server.url,
    bearerToken: TOKEN,
    useClientPir: true,
    chainId: options.chainId ?? MAINNET,
    clientPirContexts: new Map([[`t2Path:${LIST_KEY_HEX}`, pathCtx()]]),
    clientPirInstanceLabels: new Map(options.labels ?? []),
    ppoiPinnedRoots: new Map(options.pinnedRoots ?? []),
    bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_HEX, GLOBAL_INDEX]])]]),
    ...(options.pinUpstream === undefined ? {} : { pinUpstream: options.pinUpstream }),
  });
}

async function expectRejectsWith(
  promise: Promise<unknown>,
  kind: RavenErrorKind,
): Promise<void> {
  let thrown: unknown;
  let resolved = false;
  try {
    await promise;
    resolved = true;
  } catch (e) {
    thrown = e;
  }
  expect(resolved, `expected a ${kind} refusal, but the call returned a proof`).toBe(false);
  expect(RavenError.is(thrown, kind), `expected ${kind}, got ${String(thrown)}`).toBe(true);
}

describe("the PPOI path-10 pinned root is mandatory and chain-scoped", () => {
  let server: MockServer;
  const nodes = siblings(0xab);
  const trueRoot = foldMerkleRoot(BC_HEX, nodes.map(toHex), BigInt(LOCAL_INDEX));

  beforeAll(async () => {
    server = await startMockServer();
  });
  afterAll(async () => {
    await server.close();
  });
  afterEach(() => {
    server.reset();
  });

  // THE DEFECT. The chain-aware label is what `instanceLabel()` routes on, so the
  // chain-less `has()` gate was false and the missing pin was never noticed.
  it("refuses when the routing label is chain-aware and no root is pinned", async () => {
    mountRowRoute(server, nodes);
    const sdk = makeSdk(server, {
      labels: [[`t2Path:${MAINNET}:${LIST_KEY_HEX}:${BLOCK}`, "ppoi-paths-ofac-1"]],
      pinnedRoots: [],
    });
    await expectRejectsWith(sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]), "InvalidQuery");
  });

  it("refuses when the routing label is chain-less and no root is pinned", async () => {
    mountRowRoute(server, nodes);
    const sdk = makeSdk(server, {
      labels: [[`t2Path:${LIST_KEY_HEX}:${BLOCK}`, "ppoi-paths-ofac-1"]],
      pinnedRoots: [],
    });
    await expectRejectsWith(sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]), "InvalidQuery");
  });

  // No label registered at all still folds a server-supplied path: the absence of a
  // label is not evidence that the root is trustworthy.
  it("refuses when no label is registered and no root is pinned", async () => {
    mountRowRoute(server, nodes);
    const sdk = makeSdk(server, { labels: [], pinnedRoots: [] });
    await expectRejectsWith(sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]), "InvalidQuery");
  });

  it("accepts a root pinned under the chain-aware key", async () => {
    mountRowRoute(server, nodes);
    const sdk = makeSdk(server, {
      labels: [[`t2Path:${MAINNET}:${LIST_KEY_HEX}:${BLOCK}`, "ppoi-paths-ofac-1"]],
      pinnedRoots: [[`${MAINNET}:${LIST_KEY_HEX}:${BLOCK}`, trueRoot]],
    });
    const [proof] = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
    expect(proof.root).toBe(trueRoot);
  });

  // An unpadded 32-byte root reads as tampering unless width is checked first: the fold
  // always yields 64 chars, so a 63-char pin can never equal it however honest the server.
  it("names an unpadded pin as malformed rather than reporting a root mismatch", async () => {
    mountRowRoute(server, nodes);
    // 63 chars: what a 32-byte root looks like when its leading zero nibble was dropped.
    const unpadded = trueRoot.slice(1);
    expect(unpadded).toHaveLength(63);
    const sdk = makeSdk(server, {
      labels: [[`t2Path:${MAINNET}:${LIST_KEY_HEX}:${BLOCK}`, "ppoi-paths-ofac-1"]],
      pinnedRoots: [[`${MAINNET}:${LIST_KEY_HEX}:${BLOCK}`, unpadded]],
    });
    await expectRejectsWith(sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]), "InvalidQuery");
  });

  it("accepts a root pinned under the legacy chain-less key", async () => {
    mountRowRoute(server, nodes);
    const sdk = makeSdk(server, {
      labels: [[`t2Path:${MAINNET}:${LIST_KEY_HEX}:${BLOCK}`, "ppoi-paths-ofac-1"]],
      pinnedRoots: [[`${LIST_KEY_HEX}:${BLOCK}`, trueRoot]],
    });
    const [proof] = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
    expect(proof.root).toBe(trueRoot);
  });

  // Forged siblings: the server swaps one level and the fold lands somewhere else.
  it("refuses a forged sibling set against the pinned root", async () => {
    mountRowRoute(server, siblings(0xcd));
    const sdk = makeSdk(server, {
      labels: [[`t2Path:${MAINNET}:${LIST_KEY_HEX}:${BLOCK}`, "ppoi-paths-ofac-1"]],
      pinnedRoots: [[`${MAINNET}:${LIST_KEY_HEX}:${BLOCK}`, trueRoot]],
    });
    await expectRejectsWith(sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]), "DecodeError");
  });

  // The chain-aware pin must not be readable from another chain: the same list key and
  // block exist on both chains with different roots.
  it("does not let one chain's pinned root satisfy another chain's fold", async () => {
    mountRowRoute(server, nodes);
    const sdk = makeSdk(server, {
      chainId: POLYGON,
      labels: [[`t2Path:${POLYGON}:${LIST_KEY_HEX}:${BLOCK}`, "ppoi-paths-ofac-1"]],
      pinnedRoots: [[`${MAINNET}:${LIST_KEY_HEX}:${BLOCK}`, trueRoot]],
    });
    await expectRejectsWith(sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]), "InvalidQuery");
  });
});

// Nothing in the repo mints a pin, so the verified path above was unreachable for a real
// wallet: an integrator would ship the unverified fallback instead. These cover the second
// rung -- the root read from the UPSTREAM aggregator, never from the node that served the
// siblings. Raven's block is upstream's tree byte for byte (65,536 leaves, depth 16, same
// zero value), so the root written immediately after global leaf `B*65536+65535` is the
// root of full tree `B` and never changes again.

const BLOCK_LAST_INDEX = BLOCK * 65_536 + 65_535;

interface EventRow {
  readonly index: number;
  readonly root: string;
}

interface UpstreamScript {
  /** Rows the node answers `ppoi_poi_events` with; receives the range it was asked for. */
  readonly rows?: (startIndex: number, endIndex: number) => EventRow[];
  /** `historicalMerklerootsLength`, i.e. one more than the latest global leaf index. */
  readonly merklerootsLength?: number;
}

/** Rows a well-behaved node returns: everything it holds inside the requested range. */
function inRange(all: readonly EventRow[]) {
  return (startIndex: number, endIndex: number): EventRow[] =>
    all.filter((r) => r.index >= startIndex && r.index <= endIndex);
}

function mountUpstream(server: MockServer, script: UpstreamScript): void {
  server.route(
    (req) => req.method === "POST",
    (_req, body, res) => {
      const rpc = readJsonRpcRequest(body);
      if (rpc.method === "ppoi_node_status") {
        writeJsonRpcResult(body, res, {
          forNetwork: {
            Ethereum: {
              listStatuses: {
                [LIST_KEY_HEX]: {
                  historicalMerklerootsLength: script.merklerootsLength ?? 0,
                },
              },
            },
          },
          listKeys: [LIST_KEY_HEX],
        });
        return true;
      }
      if (rpc.method === "ppoi_poi_events") {
        const start = rpc.params.startIndex as number;
        const end = rpc.params.endIndex as number;
        const rows = script.rows ? script.rows(start, end) : [];
        writeJsonRpcResult(
          body,
          res,
          rows.map((r) => ({
            signedPOIEvent: {
              index: r.index,
              blindedCommitment: BC_HEX,
              signature: "00",
              type: "Transact",
            },
            validatedMerkleroot: r.root,
          })),
        );
        return true;
      }
      writeJsonRpcResult(body, res, null);
      return true;
    },
  );
}

function eventRanges(server: MockServer): { startIndex: number; endIndex: number }[] {
  return server.requests
    .map((r) => readJsonRpcRequest(r.body))
    .filter((rpc) => rpc.method === "ppoi_poi_events")
    .map((rpc) => ({
      startIndex: rpc.params.startIndex as number,
      endIndex: rpc.params.endIndex as number,
    }));
}

describe("an unpinned PPOI path-10 fold is verified against the upstream aggregator", () => {
  let adapter: MockServer;
  let upstream: MockServer;
  const nodes = siblings(0xab);
  const trueRoot = foldMerkleRoot(BC_HEX, nodes.map(toHex), BigInt(LOCAL_INDEX));
  const otherRoot = `${"cd".repeat(31)}ef`;

  beforeAll(async () => {
    adapter = await startMockServer();
    upstream = await startMockServer();
  });
  afterAll(async () => {
    await adapter.close();
    await upstream.close();
  });
  afterEach(() => {
    adapter.reset();
    upstream.reset();
  });

  function sdkWithResolver(): RavenPOINodeInterface {
    mountRowRoute(adapter, nodes);
    return makeSdk(adapter, {
      labels: [[`t2Path:${MAINNET}:${LIST_KEY_HEX}:${BLOCK}`, "ppoi-paths-ofac-1"]],
      pinnedRoots: [],
      pinUpstream: upstream.url,
    });
  }

  // An empty pin is a configuration mistake, not an absent pin. Falling through to upstream
  // would silently verify against a different party than the caller asked for, so the
  // interesting assertion is not that it throws but that it never reached the network.
  it("refuses an empty caller pin instead of silently resolving upstream", async () => {
    mountRowRoute(adapter, nodes);
    mountUpstream(upstream, {
      rows: inRange([{ index: BLOCK_LAST_INDEX, root: trueRoot }]),
    });
    const sdk = makeSdk(adapter, {
      labels: [[`t2Path:${MAINNET}:${LIST_KEY_HEX}:${BLOCK}`, "ppoi-paths-ofac-1"]],
      pinnedRoots: [[`${MAINNET}:${LIST_KEY_HEX}:${BLOCK}`, ""]],
      pinUpstream: upstream.url,
    });

    await expectRejectsWith(sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]), "InvalidQuery");
    expect(upstream.requests).toHaveLength(0);
  });

  it("accepts a frozen block's fold against the root upstream wrote at the last leaf", async () => {
    mountUpstream(upstream, {
      rows: inRange([{ index: BLOCK_LAST_INDEX, root: trueRoot }]),
    });
    const [proof] = await sdkWithResolver().getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
    expect(proof.root).toBe(trueRoot);
    // A full tree's root is one zero-width point query; no status call is needed to find it.
    expect(eventRanges(upstream)).toEqual([
      { startIndex: BLOCK_LAST_INDEX, endIndex: BLOCK_LAST_INDEX },
    ]);
  });

  it("refuses a frozen block whose upstream root differs, naming the window it checked", async () => {
    mountUpstream(upstream, {
      rows: inRange([{ index: BLOCK_LAST_INDEX, root: otherRoot }]),
    });
    let thrown: unknown;
    try {
      await sdkWithResolver().getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
    } catch (e) {
      thrown = e;
    }
    expect(RavenError.is(thrown, "DecodeError"), `got ${String(thrown)}`).toBe(true);
    expect(String((thrown as Error).message)).toContain(
      `${BLOCK_LAST_INDEX}..${BLOCK_LAST_INDEX}`,
    );
    expect(String((thrown as Error).message)).toContain("frozen");
  });

  // The filling block has no final root, so the fold is matched against a window of the
  // most recent roots -- one per leaf inserted.
  it("accepts a filling block's fold against a root inside the tip window", async () => {
    mountUpstream(upstream, {
      merklerootsLength: GLOBAL_INDEX + 1,
      rows: inRange([
        { index: GLOBAL_INDEX - 1, root: otherRoot },
        { index: GLOBAL_INDEX, root: trueRoot },
      ]),
    });
    const [proof] = await sdkWithResolver().getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
    expect(proof.root).toBe(trueRoot);
    // Point query first (empty, so the block is still filling), then the clamped window:
    // `max(tailBlock*65536, L-63)`, which must not reach back into the previous tree.
    expect(eventRanges(upstream)).toEqual([
      { startIndex: BLOCK_LAST_INDEX, endIndex: BLOCK_LAST_INDEX },
      { startIndex: BLOCK * 65_536, endIndex: GLOBAL_INDEX },
    ]);
  });

  it("refuses a filling-block fold whose root has fallen out of the tip window", async () => {
    const tip = BLOCK * 65_536 + 200;
    mountUpstream(upstream, {
      merklerootsLength: tip + 1,
      rows: inRange([
        { index: GLOBAL_INDEX, root: trueRoot },
        { index: tip, root: otherRoot },
      ]),
    });
    let thrown: unknown;
    try {
      await sdkWithResolver().getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
    } catch (e) {
      thrown = e;
    }
    expect(RavenError.is(thrown, "DecodeError"), `got ${String(thrown)}`).toBe(true);
    // The window is what tells an operator "this node is lagging" apart from "this node
    // forged the siblings", so the refusal has to name it.
    expect(String((thrown as Error).message)).toContain(`${tip - 63}..${tip}`);
    expect(String((thrown as Error).message)).toContain("filling");
  });

  // The clamp keeps the REQUEST inside one tree; the index filter is what protects against
  // a node that answers outside the range it was asked for. Here the fold's root is real
  // but belongs to the PREVIOUS tree, where it certifies a different set of leaves.
  it("does not admit a neighbouring tree's root from a window spanning the boundary", async () => {
    const tip = BLOCK * 65_536 + 3;
    mountUpstream(upstream, {
      merklerootsLength: tip + 1,
      // Ignores the requested range on purpose.
      rows: () => [
        { index: BLOCK * 65_536 - 1, root: trueRoot },
        { index: tip, root: otherRoot },
      ],
    });
    let thrown: unknown;
    try {
      await sdkWithResolver().getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
    } catch (e) {
      thrown = e;
    }
    expect(RavenError.is(thrown, "DecodeError"), `got ${String(thrown)}`).toBe(true);
    expect(String((thrown as Error).message)).toContain("1 root(s)");
  });

  // A pin the caller loaded themselves is the strongest claim available and still wins;
  // the resolver is not consulted at all, so an offline wallet keeps working.
  it("prefers a caller-supplied pin and never calls upstream", async () => {
    mountUpstream(upstream, { rows: inRange([{ index: BLOCK_LAST_INDEX, root: otherRoot }]) });
    mountRowRoute(adapter, nodes);
    const sdk = makeSdk(adapter, {
      labels: [[`t2Path:${MAINNET}:${LIST_KEY_HEX}:${BLOCK}`, "ppoi-paths-ofac-1"]],
      pinnedRoots: [[`${MAINNET}:${LIST_KEY_HEX}:${BLOCK}`, trueRoot]],
      pinUpstream: upstream.url,
    });
    const [proof] = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
    expect(proof.root).toBe(trueRoot);
    expect(upstream.requests).toHaveLength(0);
  });

  // Asking the node that served the siblings for the root that checks them is circular.
  it("refuses at construction when the pin source is the endpoint being verified", () => {
    let thrown: unknown;
    try {
      makeSdk(adapter, { pinUpstream: adapter.url });
    } catch (e) {
      thrown = e;
    }
    expect(RavenError.is(thrown, "InvalidQuery"), `got ${String(thrown)}`).toBe(true);
    expect(String((thrown as Error).message)).toMatch(
      /must not be the endpoint whose auth paths it verifies/,
    );
    expect(adapter.requests).toHaveLength(0);
  });

  // `upstreamFallbackEndpoint` is also the passthrough target, where one process serving
  // both roles is legitimate, so an INHERITED pin source aimed at this node cannot fail
  // construction. It goes inert instead, and the fold-time refusal says why.
  it("stays inert, not fatal, when the inherited pin source is this node", async () => {
    mountRowRoute(adapter, nodes);
    const sdk = new RavenPOINodeInterface({
      endpoint: adapter.url,
      bearerToken: TOKEN,
      useClientPir: true,
      upstreamFallbackEndpoint: adapter.url,
      clientPirContexts: new Map([[`t2Path:${LIST_KEY_HEX}`, pathCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_HEX, GLOBAL_INDEX]])]]),
    });
    let thrown: unknown;
    try {
      await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
    } catch (e) {
      thrown = e;
    }
    expect(RavenError.is(thrown, "InvalidQuery"), `got ${String(thrown)}`).toBe(true);
    expect(String((thrown as Error).message)).toContain("no usable upstream pin source");
  });

  // `pinUpstream: false` restores the bare refusal for a wallet that will only ever
  // trust roots it pinned itself.
  it("refuses with the disabled message when the resolver is turned off", async () => {
    mountRowRoute(adapter, nodes);
    const sdk = makeSdk(adapter, { pinnedRoots: [], pinUpstream: false });
    let thrown: unknown;
    try {
      await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
    } catch (e) {
      thrown = e;
    }
    expect(RavenError.is(thrown, "InvalidQuery"), `got ${String(thrown)}`).toBe(true);
    expect(String((thrown as Error).message)).toContain("no usable upstream pin source");
  });

  // Every byte of both pin requests is a function of public state: the list key, a block
  // number, and upstream's own tip. The blinded commitment must not appear in either.
  it("sends no blinded-commitment bytes to the pin source", async () => {
    mountUpstream(upstream, {
      merklerootsLength: GLOBAL_INDEX + 1,
      rows: inRange([{ index: GLOBAL_INDEX, root: trueRoot }]),
    });
    await sdkWithResolver().getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
    expect(upstream.requests.length).toBeGreaterThan(0);
    for (const request of upstream.requests) {
      expect(new TextDecoder().decode(request.body)).not.toContain(BC_HEX);
    }
  });
});

// The resolver is public API, so it is exercised directly and not only through the
// interface: an integrator can pre-warm pins or drive it themselves, and a public symbol
// reachable only via one caller is one refactor away from being untested.
describe("the pin resolver as public API", () => {
  let upstream: MockServer;

  beforeAll(async () => {
    upstream = await startMockServer();
  });
  afterAll(async () => {
    await upstream.close();
  });
  afterEach(() => {
    upstream.reset();
  });

  function resolver(): UpstreamPinResolver {
    return new UpstreamPinResolver({
      endpoint: upstream.url,
      fetchImpl: fetch,
      chainType: 0,
      chainId: MAINNET,
      txidVersion: "V2_PoseidonMerkle",
    });
  }

  // A wrong network name reads another chain's tip, so an unknown pair must say so rather
  // than fall back to mainnet.
  it("names the upstream network for known chains and refuses to guess otherwise", () => {
    expect(ppoiNetworkName(0, 1)).toBe("Ethereum");
    expect(ppoiNetworkName(0, 137)).toBe("Polygon");
    expect(ppoiNetworkName(0, 999_999)).toBeUndefined();
    expect(ppoiNetworkName(9, 1)).toBeUndefined();
  });

  // The point query's index IS the constant: asking one short returns the root of a tree
  // with a leaf missing, which folds to something else entirely.
  it("asks for a frozen block's last leaf and returns that root", async () => {
    const root = "aa".repeat(32);
    const lastIndex = BLOCK * LEAVES_PER_PPOI_BLOCK + (LEAVES_PER_PPOI_BLOCK - 1);
    mountUpstream(upstream, { rows: inRange([{ index: lastIndex, root }]) });

    const resolved = await resolver().resolve(LIST_KEY_HEX, BLOCK);

    expect(eventRanges(upstream)).toEqual([{ startIndex: lastIndex, endIndex: lastIndex }]);
    expect(resolved.window.frozen).toBe(true);
    expect([...resolved.roots]).toEqual([root]);
  });

  // The window is a privacy and cost bound, not decoration: unbounded it would pull the
  // whole tail every proof.
  it("bounds a filling block's window by the exported window size", async () => {
    const latest = BLOCK * LEAVES_PER_PPOI_BLOCK + 900;
    mountUpstream(upstream, {
      merklerootsLength: latest + 1,
      rows: inRange([{ index: latest, root: "bb".repeat(32) }]),
    });

    const resolved = await resolver().resolve(LIST_KEY_HEX, BLOCK);

    expect(resolved.window.frozen).toBe(false);
    const width = resolved.window.endIndex - resolved.window.startIndex + 1;
    expect(width).toBeLessThanOrEqual(PIN_TAIL_WINDOW);
    expect(resolved.window.endIndex).toBe(latest);
  });

  // The whole product is a private read, so the pin fetch must not undo it. Checked with the
  // whole-request helper, because the PIR harness narrows to the instance paths and would
  // filter these out -- a leak here would otherwise be invisible to every privacy test.
  it("puts nothing that identifies the commitment on the wire", async () => {
    const latest = BLOCK * LEAVES_PER_PPOI_BLOCK + 12;
    mountUpstream(upstream, {
      merklerootsLength: latest + 1,
      rows: inRange([{ index: latest, root: "cc".repeat(32) }]),
    });

    await resolver().resolve(LIST_KEY_HEX, BLOCK);

    expect(upstream.requests.length).toBeGreaterThan(0);
    assertNoCommitmentsAnywhere(upstream.requests, [BC_HEX]);

    // The assertion must be able to fail, or the check above proves nothing.
    expect(() =>
      assertNoCommitmentsAnywhere(
        [{ url: "http://x/", method: "POST", body: new TextEncoder().encode(BC_HEX) }],
        [BC_HEX],
      ),
    ).toThrow(/blinded commitment/);
  });

  it("refuses a list key that is not 64 hex chars", async () => {
    await expectRejectsWith(resolver().resolve("abcd", BLOCK), "InvalidQuery");
  });
});
