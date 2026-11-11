# Changelog

## 0.1.0-alpha.1

The first published release. It pairs with `@hisoka-io/howl-client-wasm`,
`@hisoka-io/howl-client-wasm-bundler` and `@hisoka-io/howl-client-wasm-web` `0.1.0-alpha.1`; any one
of the three is the peer.

- The public tag-prefix feed scanned on the device, private cell reads by PIR on parameter sets 1
  and 2, Merkle paths at a chosen leaf count, and the multisig scan and signing session.
- Three builds of the wasm: Node, `-bundler` for a bundled page, and `-web` with `initSync` for a
  Manifest V3 service worker. The package itself runs on `fetch`, `AbortSignal.timeout` and
  `TextDecoder`, with no Node built-in.
- `discoverySource(source)` answers Howl's `DiscoverySource`, and `witnessSource(options)` its
  `MerkleWitnessSource`, keyed by the note's commitment. A witness is refused for a commitment the
  wallet did not find, a tree leaf that is not that commitment, and a root the pool does not know.
- A sync reads a short tail of the feed and the newest block again (`SYNC_CURSOR_GRANULE`), at
  most 2,394 bytes more when nothing is new. The rows and leaves read again must match the ones
  held: other rows there are followed by a rewind. A node behind the held count is
  `Stale` when its tree agrees with the verified one, and a rewind otherwise.
- After a rewind, the cells read before are kept when the completed sync brings back every feed
  row and tree leaf held unchanged. Otherwise the next private read reads all of them again. One
  rewind costs at most two full re-reads and one sync, however far the chain moved.
- `fetchNotes` sends the same requests whatever the asked positions are against the count: a
  position at or past `state.leafCount` takes a slot and answers a record that opens to nothing
  (`missRecord(field, leafIndex)`, `commitmentPrefix` all zero). A source with no leaves yet syncs
  once before its first read.
- `sideEffects: false`; the package ships its LICENSE and this changelog.
