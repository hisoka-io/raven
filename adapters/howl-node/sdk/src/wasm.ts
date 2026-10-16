/**
 * The part of `@hisoka-io/howl-client-wasm` this package calls, as a structural type, so a
 * wallet passes in whichever build of the wasm its bundler loads (node or web).
 */

/** A decoded plain answer; fields the route does not carry read as zero or empty. */
export interface HowlAnswerView {
  readonly kind: number;
  readonly leafCount: number;
  readonly block: number;
  readonly root: Uint8Array;
  readonly base: number;
  readonly next: number;
  readonly rows: Uint8Array;
  readonly upperBase: number;
  readonly upperNext: number;
  readonly upperNodes: Uint8Array;
  readonly blockIndex: number;
  readonly blockLeaves: Uint8Array;
  readonly ladderCap: number;
  readonly sessionTtlSecs: number;
  free(): void;
}

/** A built batch: the request body, and the per-slot state that stays in the wasm. */
export interface HowlBatchHandle {
  readonly body: Uint8Array;
  readonly slots: number;
  /** The row each slot reads, pads included. */
  readonly targets: Uint32Array;
  /** Slot of each requested position, in request order. */
  readonly realSlots: Uint32Array;
  free(): void;
}

/** Cells read privately, in request order, with the state they were read at. */
export interface HowlCellsView {
  readonly cells: Uint8Array;
  readonly leafCount: number;
  readonly block: number;
  readonly root: Uint8Array;
  free(): void;
}

/** One secret, drawn when the client is built, and the one packing key built under it. */
export interface HowlClientHandle {
  sessionBody(): Uint8Array;
  installSession(answer: Uint8Array): number;
  readonly hasSession: boolean;
  readonly ladderCap: number;
  buildBatch(positions: Uint32Array, leafCount: number): HowlBatchHandle;
  buildBatchAt(targets: Uint32Array, realSlots: Uint32Array, leafCount: number): HowlBatchHandle;
  openNotes(batch: HowlBatchHandle, answer: Uint8Array): HowlCellsView;
  free(): void;
}

/** The verified tree, kept level by level so a sync hashes only what is new. */
export interface HowlTreeHandle {
  readonly fullBlocks: number;
  readonly newestIndex: number;
  upperNodes(): Uint8Array;
  newestLeaves(): Uint8Array;
  appendUpper(nodes: Uint8Array): void;
  setNewest(index: number, leaves: Uint8Array): void;
  addBlock(index: number, leaves: Uint8Array): void;
  holdsBlock(index: number): boolean;
  leaf(index: number): Uint8Array;
  truncate(n: number): void;
  root(n: number): Uint8Array;
  path(index: number, n: number): Uint8Array;
  free(): void;
}

export interface HowlWasm {
  readonly HowlClient: new (paramsAnswer: Uint8Array) => HowlClientHandle;
  readonly HowlTree: new () => HowlTreeHandle;
  decodeAnswer(bytes: Uint8Array): HowlAnswerView;
  merklePath(
    index: number,
    n: number,
    upper: Uint8Array,
    tail: Uint8Array,
    noteBlock: Uint8Array,
  ): Uint8Array;
  treeRoot(n: number, upper: Uint8Array, tail: Uint8Array): Uint8Array;
  foldPath(leaf: Uint8Array, index: number, siblings: Uint8Array): Uint8Array;
  blockNode(leaves: Uint8Array): Uint8Array;
  initPanicHook?(): void;
}

/** Route ids in an answer header. */
export const KIND = {
  params: 1,
  prefixes: 2,
  block: 3,
  upper: 4,
  sync: 5,
  session: 6,
  notes: 7,
  stale: 8,
} as const;

/** A plain answer copied out of the wasm. */
export interface Answer {
  readonly kind: number;
  readonly leafCount: number;
  readonly block: number;
  readonly root: Uint8Array;
  readonly base: number;
  readonly next: number;
  readonly rows: Uint8Array;
  readonly upperBase: number;
  readonly upperNext: number;
  readonly upperNodes: Uint8Array;
  readonly blockIndex: number;
  readonly blockLeaves: Uint8Array;
  readonly ladderCap: number;
  readonly sessionTtlSecs: number;
}

export function decode(wasm: HowlWasm, bytes: Uint8Array): Answer {
  const view = wasm.decodeAnswer(bytes);
  try {
    return {
      kind: view.kind,
      leafCount: view.leafCount,
      block: view.block,
      root: view.root,
      base: view.base,
      next: view.next,
      rows: view.rows,
      upperBase: view.upperBase,
      upperNext: view.upperNext,
      upperNodes: view.upperNodes,
      blockIndex: view.blockIndex,
      blockLeaves: view.blockLeaves,
      ladderCap: view.ladderCap,
      sessionTtlSecs: view.sessionTtlSecs,
    };
  } finally {
    view.free();
  }
}
