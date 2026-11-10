// The calls a wallet makes, run the same way in Node, in a bundled page and in an extension's
// service worker; the driver compares the three results.
import { RavenHowlSource, bigintField, fetchTransport } from "@hisoka-io/raven-howl-client";

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/**
 * @param {unknown} wasm one of the three wasm builds, initialised
 * @param {{ nodeUrl: string, tags: string[], owned: { leafIndex: number, commitment: string }[] }} input
 */
export async function smoke(wasm, input) {
  const source = new RavenHowlSource({ transport: fetchTransport(input.nodeUrl), wasm, field: bigintField, keyMode: "session" });
  const synced = await source.sync();
  const positions = [...new Set(source.matches(input.tags.map((t) => BigInt(t))).map((m) => m.position))].sort((a, b) => a - b);
  const records = await source.fetchNotes(positions);
  const confirmed = [];
  for (const note of input.owned) {
    const record = records.find((r) => r.leafIndex === note.leafIndex);
    confirmed.push(record === undefined ? "not read" : await source.confirmNote(record, BigInt(note.commitment)));
  }
  const witness = await source.merkleWitness(input.owned[0].leafIndex);
  // a service worker stops between events: the snapshot alone must resume the source
  const resumed = new RavenHowlSource({ transport: fetchTransport(input.nodeUrl), wasm, field: bigintField, snapshot: source.snapshot() });
  const again = await resumed.sync();
  source.close();
  resumed.close();
  return {
    leafCount: synced.leafCount,
    root: hex(synced.root),
    positions,
    records: records.map((r) => [r.leafIndex, hex(r.commitmentPrefix)]),
    confirmed,
    witness: { leafIndex: witness.leafIndex, leafCount: witness.leafCount, root: witness.root.toString(16), siblings: witness.siblings.length },
    resumed: { leafCount: again.leafCount, rowsAdded: again.rowsAdded },
    globals: { Buffer: typeof globalThis.Buffer, process: typeof globalThis.process },
  };
}
