// The engine emits `0x`-prefixed blinded commitments (`blinded-commitment.ts:4-6`) and looks the
// result up with a bare object index (`abstract-wallet.ts:1420`), where a miss is an unlogged
// `continue`. So if the adapter re-keys the response, every status is dropped in silence and the
// integration is a no-op that re-queues 1,000 BCs on every refresh forever.
//
// The contract is the stock one: `TestPOINodeInterface.getPOIsPerList` keys by
// `blindedCommitmentData.blindedCommitment` VERBATIM, and each inner map by the list key it was
// asked for. Normalization is for internal lookup only.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenPOINodeInterface, type Proof } from "../src/index";
import { forestConfig } from "./helpers/forest";
import { startMockServer, writeJsonRpcResult, type MockServer } from "./helpers/mock_server";
import { commitmentAt, mountPrefixChannel, targetNamingCtx } from "./helpers/prefix_channel";

const TOKEN = "test-token-padded-long-enough-1234";
const TXID = "V2_PoseidonMerkle";
const CHAIN = { type: 0, id: 1 };
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";
const BC_BARE = commitmentAt(0x10);
/** The only shape the engine ever produces. */
const BC_PREFIXED = `0x${BC_BARE}`;
const PROOF: Proof = { pi_a: ["1", "2"], pi_b: [["3", "4"], ["5", "6"]], pi_c: ["7", "8"] };

/**
 * The stock contract, copied from `engine/src/test/test-poi-node-interface.test.ts`: the outer key
 * is the caller's string, untouched. Any adapter that satisfies the interface must agree with this.
 */
function stockContractKeys(listKeys: string[], bcs: string[]): Record<string, Record<string, string>> {
  const out: Record<string, Record<string, string>> = {};
  for (const bc of bcs) {
    out[bc] ??= {};
    for (const lk of listKeys) out[bc][lk] = "Valid";
  }
  return out;
}

describe("the key format the wallet looks up with is the key format the adapter emits", () => {
  let server: MockServer;
  let upstream: MockServer;
  beforeAll(async () => {
    server = await startMockServer();
    upstream = await startMockServer();
  });
  afterAll(async () => {
    await server.close();
    await upstream.close();
  });
  afterEach(() => {
    server.reset();
    upstream.reset();
  });

  function sdk(members: string[] = [BC_BARE]): RavenPOINodeInterface {
    // The prefix channel is published BARE, so the internal lookup must still normalize.
    mountPrefixChannel(server, LIST_KEY_HEX, { commitments: members });
    return new RavenPOINodeInterface({
      ...forestConfig({ endpoint: server.url, listKeyHex: LIST_KEY_HEX, ctx: targetNamingCtx() }),
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: upstream.url,
    });
  }

  it("returns the caller's exact string as the outer key", async () => {
    const got = await sdk().getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_PREFIXED, type: "Shield" }],
    );
    expect(Object.keys(got)).toStrictEqual([BC_PREFIXED]);
    expect(got[BC_PREFIXED][LIST_KEY_HEX]).toBe("Valid");
  });

  it("agrees with the stock contract's keying for the same input, engine-shaped", async () => {
    const got = await sdk().getPOIsPerList(TXID, CHAIN, [LIST_KEY_HEX], [
      { blindedCommitment: BC_PREFIXED, type: "Shield" },
    ]);
    const oracle = stockContractKeys([LIST_KEY_HEX], [BC_PREFIXED]);
    expect(Object.keys(got).sort()).toStrictEqual(Object.keys(oracle).sort());
    expect(Object.keys(got[BC_PREFIXED]).sort()).toStrictEqual(
      Object.keys(oracle[BC_PREFIXED]).sort(),
    );
  });

  it("keeps the caller's string on the Missing arm", async () => {
    const got = await sdk([commitmentAt(0)]).getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_PREFIXED, type: "Shield" }],
    );
    expect(Object.keys(got)).toStrictEqual([BC_PREFIXED]);
    expect(got[BC_PREFIXED][LIST_KEY_HEX]).toBe("Missing");
  });

  it("finds a submission recorded bare under a prefixed lookup, and keys it the caller's way", async () => {
    upstream.route(
      () => true,
      (_req, body, res) => {
        writeJsonRpcResult(body, res, null);
        return true;
      },
    );
    const client = sdk([commitmentAt(0)]);
    await client.submitPOI(TXID, CHAIN, LIST_KEY_HEX, PROOF, [], "00".repeat(32), 0, [BC_BARE], "0x00");
    const got = await client.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_PREFIXED, type: "Transact" }],
    );
    expect(Object.keys(got)).toStrictEqual([BC_PREFIXED]);
    expect(got[BC_PREFIXED][LIST_KEY_HEX]).toBe("ProofSubmitted");
  });

  it("keys the inner map by the list key exactly as the caller spelled it", async () => {
    const spelled = `0x${LIST_KEY_HEX.toUpperCase()}`;
    const got = await sdk().getPOIsPerList(TXID, CHAIN, [spelled], [
      { blindedCommitment: BC_BARE, type: "Shield" },
    ]);
    expect(got).toStrictEqual({ [BC_BARE]: { [spelled]: "Valid" } });
  });

  it("a bare-hex caller still gets a bare-hex key back", async () => {
    const got = await sdk().getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_BARE, type: "Shield" }],
    );
    expect(Object.keys(got)).toStrictEqual([BC_BARE]);
  });
});
