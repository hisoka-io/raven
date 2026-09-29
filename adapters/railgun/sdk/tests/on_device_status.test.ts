// Status is answered on the device from the list's prefix index: Valid when the commitment's
// prefix is among the rows synced in the call, ProofSubmitted when this device submitted a proof
// covering it that has not reached the list, Missing otherwise. The engine-shaped call leaves a
// commitment out rather than guess, and no request names a commitment, a list index or a shard.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  RavenError,
  RavenPOINodeInterface,
  type BlindedCommitmentData,
  type Chain,
  type Proof,
  type SubmittedProofStore,
} from "../src/index";
import { forestConfig } from "./helpers/forest";
import {
  readJsonRpcRequest,
  startMockServer,
  writeJson,
  writeJsonRpcResult,
  type MockServer,
} from "./helpers/mock_server";
import { encodeBatchResponseNodes } from "./helpers/auth_path_stub";
import {
  PATH10_ROW_BYTES,
  mountPath10Route,
  path10Root,
  path10Siblings,
  path10Slot,
} from "./helpers/path10_row";
import {
  commitmentAt,
  listHolding,
  mountPrefixChannel,
  prefixTwinOf,
  targetNamingCtx,
  type MockList,
} from "./helpers/prefix_channel";
import { assertNoCommitmentsAnywhere } from "./helpers/private_wire";

const TXID = "V2_PoseidonMerkle";
const MAINNET: Chain = { type: 0, id: 1 };
const LIST = "ab".repeat(32);
const OTHER_LIST = "cd".repeat(32);
const PROOF: Proof = { pi_a: ["1", "2"], pi_b: [["3", "4"], ["5", "6"]], pi_c: ["7", "8"] };

function shield(blindedCommitment: string): BlindedCommitmentData {
  return { blindedCommitment, type: "Shield" };
}

function transact(blindedCommitment: string): BlindedCommitmentData {
  return { blindedCommitment, type: "Transact" };
}

class MemoryStore implements SubmittedProofStore {
  readonly records = new Map<string, Uint8Array>();
  failLoads = false;

  async load(key: string): Promise<Uint8Array | undefined> {
    if (this.failLoads) throw new Error("store unreadable");
    return this.records.get(key);
  }

  async save(key: string, record: Uint8Array): Promise<void> {
    this.records.set(key, new Uint8Array(record));
  }
}

describe("on-device status", () => {
  let node: MockServer;
  let upstream: MockServer;
  let upstreamMethods: string[];

  beforeAll(async () => {
    node = await startMockServer();
    upstream = await startMockServer();
  });
  afterAll(async () => {
    await node.close();
    await upstream.close();
  });
  afterEach(() => {
    node.reset();
    upstream.reset();
  });

  function serve(list: MockList, listKey = LIST): MockList {
    mountPrefixChannel(node, listKey, list);
    return list;
  }

  function mountUpstream(refuse = false): void {
    upstreamMethods = [];
    upstream.route(
      () => true,
      (_req, body, res) => {
        const request = readJsonRpcRequest(body);
        upstreamMethods.push(request.method);
        if (refuse) {
          writeJson(res, {
            jsonrpc: "2.0",
            id: request.id,
            error: { code: -32000, message: "proof refused" },
          });
        } else {
          writeJsonRpcResult(body, res, null);
        }
        return true;
      },
    );
  }

  function device(store?: SubmittedProofStore, endpoint = node.url): RavenPOINodeInterface {
    return new RavenPOINodeInterface({
      ...forestConfig({ endpoint, listKeyHex: LIST, ctx: targetNamingCtx() }),
      upstreamFallbackEndpoint: upstream.url,
      submittedProofStore: store,
    });
  }

  async function submit(sdk: RavenPOINodeInterface, outputs: string[], unshield = "0x00") {
    await sdk.submitPOI(TXID, MAINNET, LIST, PROOF, [], "00".repeat(32), 0, outputs, unshield);
  }

  it("answers Valid, ProofSubmitted and Missing, keyed by the caller's exact strings", async () => {
    serve({ commitments: [commitmentAt(0), commitmentAt(1), commitmentAt(2)] });
    mountUpstream();
    const sdk = device();
    const submitted = commitmentAt(9);
    await submit(sdk, [`0x${submitted}`]);

    const member = `0x${commitmentAt(1).toUpperCase()}`;
    const absent = commitmentAt(7);
    const got = await sdk.getPOIsPerList(TXID, MAINNET, [LIST], [
      shield(member),
      transact(`0x${submitted}`),
      shield(absent),
    ]);

    expect(got).toStrictEqual({
      [member]: { [LIST]: "Valid" },
      [`0x${submitted}`]: { [LIST]: "ProofSubmitted" },
      [absent]: { [LIST]: "Missing" },
    });
    expect(upstreamMethods).toEqual(["ppoi_submit_transact_proof"]);
  });

  it("reads a commitment spelled without its leading zero digits as the value it spells", async () => {
    const zeroLed = `007c${"ab".repeat(30)}`;
    const oneZero = `0d${"cd".repeat(31)}`;
    serve({ commitments: [commitmentAt(0), zeroLed, oneZero] });
    const sdk = device();
    const stripped = zeroLed.slice(2);
    const strippedOne = `0x${oneZero.slice(1)}`;
    const absent = `5e${"ef".repeat(30)}`;
    expect([stripped.length, strippedOne.length - 2, absent.length]).toEqual([62, 63, 62]);

    await expect(
      sdk.getPOIsPerList(TXID, MAINNET, [LIST], [
        shield(stripped),
        shield(strippedOne),
        shield(absent),
      ]),
    ).resolves.toStrictEqual({
      [stripped]: { [LIST]: "Valid" },
      [strippedOne]: { [LIST]: "Valid" },
      [absent]: { [LIST]: "Missing" },
    });
    await expect(sdk.getPOIsPerList([LIST], [shield(stripped)])).resolves.toStrictEqual({
      [stripped]: { [LIST]: "Valid" },
    });
    await expect(sdk.getPOIsPerList([LIST], [shield("1".repeat(65))])).rejects.toSatisfy(
      (error: unknown) => RavenError.is(error, "InvalidQuery"),
    );
  });

  it("proves and indexes a commitment spelled without its leading zero digits", async () => {
    const zeroLed = `007c${"ab".repeat(30)}`;
    const stripped = zeroLed.slice(2);
    const nodes = path10Siblings(0x5c);
    serve({ commitments: listHolding([[zeroLed, 3]]) });
    mountPath10Route(node, { bcHex: zeroLed, nodes });
    const sdk = new RavenPOINodeInterface(
      forestConfig({
        endpoint: node.url,
        listKeyHex: LIST,
        ctx: { ...targetNamingCtx(), entrySize: PATH10_ROW_BYTES },
        pins: new Map([[0, path10Root(zeroLed, nodes, 3)]]),
      }),
    );

    const [proof] = await sdk.getPOIMerkleProofs(LIST, [`0x${stripped}`]);
    expect([proof.leaf, BigInt(`0x${proof.indices}`)]).toEqual([zeroLed, 3n]);
    await sdk.syncPoiListIndex(LIST);
    await expect(sdk.poiListIndexCandidates(LIST, stripped)).resolves.toStrictEqual({
      rows: 4,
      candidates: [3],
    });
  });

  it("sends nothing that names a commitment, a list index or a shard", async () => {
    serve({ commitments: Array.from({ length: 2_050 }, (_u, row) => commitmentAt(row)) });
    const asked = (bcs: string[]): Promise<unknown> =>
      device().getPOIsPerList(TXID, MAINNET, [LIST], bcs.map(shield));

    const first = [commitmentAt(3), commitmentAt(2_049)];
    await asked(first);
    const firstRequests = node.requests.map((r) => `${r.method} ${r.url} ${r.body.length}`);
    node.requests.length = 0;
    const second = [commitmentAt(1_000), commitmentAt(0x5_0000)];
    await asked(second);
    const secondRequests = node.requests.map((r) => `${r.method} ${r.url} ${r.body.length}`);

    // The same requests whatever is asked: a function of the list alone.
    expect(firstRequests).toEqual(secondRequests);
    expect(firstRequests).toEqual([`GET /v1/poi/${LIST}/bc-prefixes?since=0 0`]);
    assertNoCommitmentsAnywhere(node.requests, [...first, ...second]);
  });

  it("sends the same aligned cursor whichever commitment a synced device asks about", async () => {
    serve({ commitments: Array.from({ length: 2_050 }, (_u, row) => commitmentAt(row)) });
    const sdk = device();
    await sdk.syncPoiListIndex(LIST);
    node.requests.length = 0;

    await sdk.getPOIsPerList(TXID, MAINNET, [LIST], [shield(commitmentAt(5))]);
    await sdk.getPOIsPerList(TXID, MAINNET, [LIST], [shield(commitmentAt(2_049))]);

    expect(node.requests.map((r) => r.url)).toEqual([
      `/v1/poi/${LIST}/bc-prefixes?since=2048`,
      `/v1/poi/${LIST}/bc-prefixes?since=2048`,
    ]);
    expect(node.requests.some((r) => r.url.includes("/v1/instance/"))).toBe(false);
  });

  it("leaves every commitment out when the index cannot be synced, and never throws", async () => {
    const list = serve({ commitments: [commitmentAt(0), commitmentAt(1)] });
    const sdk = device();
    await sdk.syncPoiListIndex(LIST);
    list.failStatus = 503;

    const got = await sdk.getPOIsPerList(TXID, MAINNET, [LIST], [
      shield(commitmentAt(0)),
      shield(commitmentAt(5)),
    ]);
    expect(got).toStrictEqual({});

    const unreachable = device(undefined, "http://127.0.0.1:1");
    await expect(
      unreachable.getPOIsPerList(TXID, MAINNET, [LIST], [shield(commitmentAt(0))]),
    ).resolves.toStrictEqual({});
  });

  it("raises the sync's own error kind on the two-argument call", async () => {
    const list = serve({ commitments: [commitmentAt(0)], failStatus: 503 });
    await expect(device().getPOIsPerList([LIST], [shield(commitmentAt(0))])).rejects.toSatisfy(
      (error: unknown) => RavenError.is(error, "ServerError"),
    );
    list.failStatus = undefined;
    const unreachable = device(undefined, "http://127.0.0.1:1");
    await expect(unreachable.getPOIsPerList([LIST], [shield(commitmentAt(0))])).rejects.toSatisfy(
      (error: unknown) => RavenError.is(error, "Network"),
    );
  });

  it("leaves a list it does not serve out of every map, as the stock node does", async () => {
    serve({ commitments: [commitmentAt(0)] });
    const sdk = device();
    const got = await sdk.getPOIsPerList(TXID, MAINNET, [LIST, OTHER_LIST], [
      shield(commitmentAt(0)),
      shield(commitmentAt(4)),
    ]);
    expect(got).toStrictEqual({
      [commitmentAt(0)]: { [LIST]: "Valid" },
      [commitmentAt(4)]: { [LIST]: "Missing" },
    });
    await expect(
      sdk.getPOIsPerList(TXID, MAINNET, [OTHER_LIST], [shield(commitmentAt(0))]),
    ).resolves.toStrictEqual({});
    expect(node.requests.every((r) => !r.url.includes(OTHER_LIST))).toBe(true);
  });

  it("refuses a list it does not serve on the two-argument call before any request", async () => {
    serve({ commitments: [commitmentAt(0)] });
    await expect(
      device().getPOIsPerList([LIST, OTHER_LIST], [shield(commitmentAt(0))]),
    ).rejects.toSatisfy(
      (error: unknown) =>
        RavenError.is(error, "InvalidQuery") && /does not serve/.test((error as Error).message),
    );
    expect(node.requests).toHaveLength(0);
  });

  // A six-byte prefix is not a commitment: status fetches no row, so a note whose prefix a listed
  // one shares reads Valid, and the proof it needs to spend is where all 32 bytes are compared.
  it("reads a prefix twin Valid, and refuses the twin's proof", async () => {
    serve({ commitments: [prefixTwinOf(5)] });
    node.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, _body, res) => {
        res.writeHead(200, {
          "content-type": "application/octet-stream",
          "x-raven-freshness": "lag_blocks=0 applied_height=0 epoch=1 confidence=1",
        });
        const slot = path10Slot({ bcHex: prefixTwinOf(5), nodes: path10Siblings() });
        res.end(Buffer.from(encodeBatchResponseNodes([slot])));
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      ...forestConfig({
        endpoint: node.url,
        listKeyHex: LIST,
        ctx: { ...targetNamingCtx(), entrySize: PATH10_ROW_BYTES },
      }),
    });

    const got = await sdk.getPOIsPerList([LIST], [shield(commitmentAt(5))]);
    expect(got[commitmentAt(5)][LIST]).toBe("Valid");
    await expect(sdk.getPOIMerkleProofs(LIST, [commitmentAt(5)])).rejects.toThrow(
      /not present in list/,
    );
  });

  it("answers a shield that is not on the list Missing, never ShieldBlocked", async () => {
    serve({ commitments: [commitmentAt(0)] });
    const got = await device().getPOIsPerList(TXID, MAINNET, [LIST], [shield(commitmentAt(3))]);
    expect(got[commitmentAt(3)][LIST]).toBe("Missing");
  });

  it("holds ProofSubmitted until the commitment reaches the index, then answers Valid and forgets it", async () => {
    const list = serve({ commitments: [commitmentAt(0)] });
    mountUpstream();
    const store = new MemoryStore();
    const sdk = device(store);
    const output = commitmentAt(0x42);
    await submit(sdk, [output]);

    expect((await sdk.getPOIsPerList([LIST], [transact(output)]))[output][LIST]).toBe(
      "ProofSubmitted",
    );
    list.commitments.push(output);
    expect((await sdk.getPOIsPerList([LIST], [transact(output)]))[output][LIST]).toBe("Valid");

    // Another node whose list lacks the commitment: the entry is gone, so it reads Missing.
    const elsewhere = await startMockServer();
    try {
      mountPrefixChannel(elsewhere, LIST, { commitments: [commitmentAt(0)] });
      const restarted = device(store, elsewhere.url);
      expect((await restarted.getPOIsPerList([LIST], [transact(output)]))[output][LIST]).toBe(
        "Missing",
      );
    } finally {
      await elsewhere.close();
    }
  });

  it("keeps a submission through a restart when the store persists it", async () => {
    serve({ commitments: [commitmentAt(0)] });
    mountUpstream();
    const store = new MemoryStore();
    const output = commitmentAt(0x43);
    await submit(device(store), [output]);

    const restarted = device(store);
    const got = await restarted.getPOIsPerList(TXID, MAINNET, [LIST], [transact(output)]);
    expect(got[output][LIST]).toBe("ProofSubmitted");
    expect(store.records.size).toBe(1);
  });

  it("records an unshield and legacy submissions, and no zero commitment", async () => {
    serve({ commitments: [commitmentAt(0)] });
    mountUpstream();
    const sdk = device();
    const unshield = `0x${commitmentAt(0x51)}`;
    const legacy = commitmentAt(0x52);
    await submit(sdk, ["0x00", `0x${"00".repeat(32)}`], unshield);
    await sdk.submitLegacyTransactProofs(TXID, MAINNET, [LIST], [
      { txidIndex: "1", npk: "2", value: "3", tokenHash: "4", blindedCommitment: `0x${legacy}` },
    ]);

    const got = await sdk.getPOIsPerList([LIST], [
      { blindedCommitment: unshield, type: "Unshield" },
      transact(legacy),
      transact("00".repeat(32)),
    ]);
    expect(got[unshield][LIST]).toBe("ProofSubmitted");
    expect(got[legacy][LIST]).toBe("ProofSubmitted");
    expect(got["00".repeat(32)][LIST]).toBe("Missing");
    expect(upstreamMethods).toEqual([
      "ppoi_submit_transact_proof",
      "ppoi_submit_legacy_transact_proofs",
    ]);
  });

  it("does not record a proof upstream refused", async () => {
    serve({ commitments: [commitmentAt(0)] });
    mountUpstream(true);
    const sdk = device();
    const output = commitmentAt(0x44);
    await expect(submit(sdk, [output])).rejects.toThrow(/proof refused/);
    expect((await sdk.getPOIsPerList([LIST], [transact(output)]))[output][LIST]).toBe("Missing");
  });

  it("does not record a legacy batch upstream refused, on either call shape", async () => {
    serve({ commitments: [commitmentAt(0)] });
    mountUpstream(true);
    const sdk = device();
    const engineShaped = commitmentAt(0x46);
    const twoArgument = commitmentAt(0x47);
    const proof = (bc: string) => ({
      txidIndex: "1",
      npk: "2",
      value: "3",
      tokenHash: "4",
      blindedCommitment: bc,
    });

    await expect(
      sdk.submitLegacyTransactProofs(TXID, MAINNET, [LIST], [proof(engineShaped)]),
    ).resolves.toBeUndefined();
    await expect(sdk.submitLegacyTransactProofs([LIST], [proof(twoArgument)])).rejects.toThrow(
      /proof refused/,
    );

    const got = await sdk.getPOIsPerList([LIST], [transact(engineShaped), transact(twoArgument)]);
    expect(got[engineShaped][LIST]).toBe("Missing");
    expect(got[twoArgument][LIST]).toBe("Missing");
    expect(upstreamMethods).toEqual([
      "ppoi_submit_legacy_transact_proofs",
      "ppoi_submit_legacy_transact_proofs",
    ]);
  });

  it("keeps a submission to the chain it was made on, even through a shared store", async () => {
    serve({ commitments: [commitmentAt(0)] });
    mountUpstream();
    const store = new MemoryStore();
    const polygon = new RavenPOINodeInterface({
      ...forestConfig({ endpoint: node.url, listKeyHex: LIST, ctx: targetNamingCtx(), chainId: 137 }),
      upstreamFallbackEndpoint: upstream.url,
      submittedProofStore: store,
    });
    const output = commitmentAt(0x48);
    await polygon.submitPOI(TXID, { type: 0, id: 137 }, LIST, PROOF, [], "00".repeat(32), 0, [
      output,
    ], "0x00");

    const mainnet = device(store);
    expect((await mainnet.getPOIsPerList([LIST], [transact(output)]))[output][LIST]).toBe(
      "Missing",
    );
    expect(
      (await polygon.getPOIsPerList(TXID, { type: 0, id: 137 }, [LIST], [transact(output)]))[
        output
      ][LIST],
    ).toBe("ProofSubmitted");
  });

  // Engine refreshes every active txidVersion from a promise it does not await, so a rejection
  // there is unhandled; a call this interface does not serve gets no answer and sends nothing.
  it("answers a txidVersion or chain it does not serve with nothing, sending nothing", async () => {
    serve({ commitments: [commitmentAt(0)] });
    mountUpstream();
    const sdk = device();
    const asked = [shield(commitmentAt(0))];
    const legacy = [
      { txidIndex: "1", npk: "2", value: "3", tokenHash: "4", blindedCommitment: commitmentAt(9) },
    ];

    await expect(
      sdk.getPOIsPerList("V3_PoseidonMerkle", MAINNET, [LIST], asked),
    ).resolves.toStrictEqual({});
    await expect(sdk.getPOIsPerList(TXID, { type: 0, id: 137 }, [LIST], asked)).resolves.toStrictEqual(
      {},
    );
    await expect(sdk.getPOIsPerList(TXID, { type: 1, id: 1 }, [LIST], asked)).resolves.toStrictEqual(
      {},
    );
    await expect(
      sdk.submitLegacyTransactProofs("V3_PoseidonMerkle", MAINNET, [LIST], legacy),
    ).resolves.toBeUndefined();
    await expect(
      sdk.submitLegacyTransactProofs(TXID, { type: 0, id: 137 }, [LIST], legacy),
    ).resolves.toBeUndefined();

    expect(node.requests).toHaveLength(0);
    expect(upstreamMethods).toEqual([]);
    expect((await sdk.getPOIsPerList([LIST], [transact(commitmentAt(9))]))[commitmentAt(9)][LIST])
      .toBe("Missing");
  });

  it("answers members but leaves absences out while the submitted-proof store cannot be read", async () => {
    serve({ commitments: [commitmentAt(0)] });
    const store = new MemoryStore();
    store.failLoads = true;
    const sdk = device(store);

    const got = await sdk.getPOIsPerList(TXID, MAINNET, [LIST], [
      shield(commitmentAt(0)),
      transact(commitmentAt(0x45)),
    ]);
    expect(got).toStrictEqual({ [commitmentAt(0)]: { [LIST]: "Valid" } });
    await expect(sdk.getPOIsPerList([LIST], [transact(commitmentAt(0x45))])).rejects.toSatisfy(
      (error: unknown) => RavenError.is(error, "Storage"),
    );
  });
});
