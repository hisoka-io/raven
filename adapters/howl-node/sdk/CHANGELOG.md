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
- A sync names its feed cursor and held leaf count rounded down to `SYNC_CURSOR_GRANULE` (64)
  leaves. The rows and leaves between the rounded cursor and the held count come again, at most
  2,394 bytes per sync, and must match the rows held: a node that now serves other rows there is
  followed by a rewind. A node behind the held count is `Stale` when its tree agrees with the
  verified one, and a rewind otherwise.
- `sideEffects: false`; the package ships its LICENSE and this changelog.
