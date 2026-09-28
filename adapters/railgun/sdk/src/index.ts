// Railgun POI facade and domain-shaped wire helpers.
export {
  RavenPOINodeInterface,
  type RavenConfig,
  type POIStatus,
  type PoisPerListResponse,
  type BlindedCommitmentType,
  type BlindedCommitmentData,
  type MerkleProof,
  type Chain,
  type Proof,
  type LegacyTransactProofData,
  type CapturedWireRequest,
  type PoiIndexCounters,
  containsByteSequence,
  hexToBytes,
  bytesToHex,
  TREE_DEPTH,
  PATH_RECORD_BYTES,
} from "./raven-poi-node-interface";

// One engine-wide interface that answers Raven's chains through Raven and every other through
// the stock interface.
export { PerChainPOINodeInterface } from "./per-chain-poi-node-interface";

export type { SubmittedProofStore } from "./submitted-proofs";

export { hashLeftRight, foldMerkleRoot } from "./poseidon";

// Independent PPOI block roots, so a wallet can verify a served auth path without a
// hand-preloaded pin.
export {
  LEAVES_PER_PPOI_BLOCK,
  PIN_TAIL_WINDOW,
  UpstreamPinResolver,
  ppoiNetworkName,
  type PinWindow,
  type PinRequestObserver,
  type ResolvedPins,
  type UpstreamPinResolverConfig,
} from "./pin-resolver";

// Generic PIR session bootstrap and query-bundle handling.
export type {
  ClientPirContext,
  RavenInspireWasm,
  RavenInspireClientSession,
  ClientPirQueryBundle,
  LoadClientPirContextInput,
  LoadClientPirContextResult,
} from "./client-pir";

export {
  decodeClientPirQueryBundle,
  installPanicHook,
  loadClientPirContext,
} from "./client-pir";

// Railgun POI validation.
export {
  validateBcHex,
  validateLeafIndex,
  validateListKeyHex,
} from "./poi-pir";

// Generic client-side session persistence.
export {
  idbGet,
  idbPut,
  idbClear,
  sha256Hex,
} from "./session-cache";

// Railgun deployment routing.
export { ChainRegistry, type ChainRegistryEntry } from "./chain-registry";

export {
  RavenError,
  type RavenErrorKind,
  type RavenErrorContext,
  type RavenErrorByKind,
  type StaleDataContext,
  type StaleDataError,
} from "./errors";

export {
  BATCH_SIZE_LADDER,
  MAX_BATCH_SIZE,
  isOnLadder,
  paddedBatchLength,
} from "./batch-ladder";

export {
  BC_INDEX_PREFIX_BYTES,
  BC_INDEX_RESUME_ALIGN_ROWS,
  fetchBcPrefixIndex,
  indexCandidatesFor,
  indexCandidatesForEach,
  resumeBcPrefixIndex,
  type BcPrefixIndex,
} from "./bc-prefix-index";

// Persistence for list indexes, so a restarted client resolves without re-walking the list.
export {
  indexedDbPoiListIndexStore,
  type IndexedDbPoiListIndexStoreConfig,
  type PoiListIndexStore,
} from "./poi-list-index-store";
