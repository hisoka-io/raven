/**
 * Howl's wallet ports over a {@link RavenHowlSource}, typed structurally so this package needs
 * no dependency on Howl's own: `discoverySource` answers its `DiscoverySource`, and
 * `witnessSource` its `MerkleWitnessSource`, keyed by the note's commitment.
 */
import { HowlError } from "./errors.js";
import type { FieldCodec, HowlNoteRecord } from "./record.js";
import type { FirstOccurrence, MerkleWitness, OccurrenceRequest } from "./source.js";

/** The source calls the discovery port makes. */
export interface DiscoveryReads<F> {
  probeFirst(tags: readonly F[]): Promise<FirstOccurrence<F>[]>;
  fetchOccurrences(requests: readonly OccurrenceRequest<F>[]): Promise<(HowlNoteRecord<F> | null)[]>;
  fetchLeafBlock(blockIndex: number): Promise<F[]>;
}

/** Howl's `DiscoverySource`: round 1, round 2 and the leaf block. */
export interface HowlDiscoverySource<F> {
  probeFirst(tags: readonly F[]): Promise<readonly FirstOccurrence<F>[]>;
  fetchOccurrences(requests: readonly OccurrenceRequest<F>[]): Promise<readonly (HowlNoteRecord<F> | null)[]>;
  fetchLeafBlock(blockIndex: number): Promise<readonly F[]>;
}

/**
 * Howl's `DiscoverySource` over `source`. A tag with no feed match gets the source's well-formed
 * miss record, which Howl's scanner and its self-mint preflight both accept.
 */
export function discoverySource<F>(source: DiscoveryReads<F>): HowlDiscoverySource<F> {
  return {
    probeFirst: (tags) => source.probeFirst(tags),
    fetchOccurrences: (requests) => source.fetchOccurrences(requests),
    fetchLeafBlock: (blockIndex) => source.fetchLeafBlock(blockIndex),
  };
}

/** Howl's `MerkleWitnessSource`. */
export interface HowlWitnessSource<F> {
  witnessFor(commitment: F): Promise<{ readonly leafIndex: number; readonly siblings: readonly F[]; readonly root: F }>;
}

export interface WitnessSourceOptions<F> {
  readonly source: { merkleWitness(leafIndex: number, leafCount?: number): Promise<MerkleWitness<F>> };
  readonly field: FieldCodec<F>;
  /**
   * The leaf index of a note the wallet found, by its commitment; `undefined` for any other.
   * The witness is built from the verified tree at that index.
   */
  leafIndexOf(commitment: F): number | undefined | Promise<number | undefined>;
  /** The pool's `isKnownRoot`, read from the chain. */
  isKnownRoot(root: F): Promise<boolean>;
  /** Sees every witness built, with the pool's answer for its root, before it is accepted or refused. */
  observe?(witness: MerkleWitness<F>, knownRoot: boolean): void | Promise<void>;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/**
 * Howl's `MerkleWitnessSource` over `source`, for the wallet's own notes. It refuses a commitment
 * the wallet did not find, a tree leaf that is not that commitment, and a root the pool does not
 * know, so a proof is never built on any of them.
 */
export function witnessSource<F>(options: WitnessSourceOptions<F>): HowlWitnessSource<F> {
  const { source, field } = options;
  return {
    witnessFor: async (commitment) => {
      const leafIndex = await options.leafIndexOf(commitment);
      if (leafIndex === undefined) {
        throw new RangeError("the commitment is not a note this wallet found");
      }
      const witness = await source.merkleWitness(leafIndex);
      if (!sameBytes(field.toBytes(witness.leaf), field.toBytes(commitment))) {
        throw new HowlError("Protocol", `leaf ${leafIndex}: the verified tree holds another commitment`);
      }
      const knownRoot = await options.isKnownRoot(witness.root);
      await options.observe?.(witness, knownRoot);
      if (!knownRoot) {
        throw new HowlError("Protocol", `the root at ${witness.leafCount} leaves is not known to the pool`);
      }
      return { leafIndex: witness.leafIndex, siblings: witness.siblings, root: witness.root };
    },
  };
}
