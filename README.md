<p align="center">
  <img alt="Raven: a PIR framework for blockchain state" src="https://github.com/user-attachments/assets/c5cdc7c6-4d67-4ad3-a1a4-ba0009ca2d03" width="820" />
</p>

## Why

Hiding your IP (Tor, mixnets) doesn't hide _what_ you asked for. A shielded wallet still hands the
RPC server a leaf index or commitment hash on every read, and that pointer is enough to reconstruct
who you are.

Raven moves those reads to single-server private information retrieval (PIR). The wallet sends an
encrypted query, the server answers it over the whole shard without decrypting it, and the wallet
recovers the record locally. A query reveals the block and the 2,048-row shard it targets; the row
within that shard stays hidden. [SECURITY.md](./SECURITY.md) states what the server sees.

## What ships

- **The PIR framework** (`crates/`): [InsPIRe](https://eprint.iacr.org/2025/1352) with InspiRING
  packing (`crates/inspire`), the wasm-compatible client (`raven-client`), the server runtime and
  instance registry (`raven-server`), crash-consistent snapshots and WAL (`raven-storage`), and
  durable server sessions and packing-key caches (`raven-inspire-session`, `raven-inspire-cache`).
  `crates/` stays application-agnostic.
- **The Railgun PPOI adapter** (`adapters/railgun`). It mirrors a PPOI list from the upstream
  aggregator, verifies every row's Ed25519 signature and holds each row to the root upstream
  published with it, and serves the list as a forest: one InsPIRe instance per 65,536-leaf block,
  2,048-row shards, 512-byte rows carrying the leaf and its lower path levels. Status is answered
  on the device from a 6-byte prefix index; auth paths are fetched by PIR.
- **The client packages**: [`@hisoka-io/railgun-poi-node-interface`](./adapters/railgun/sdk/README.md),
  a `POINodeInterface` for the Railgun engine, and
  [`@hisoka-io/raven-inspire-client-wasm`](./adapters/railgun/client-wasm/README.md) (plus a
  `-bundler` build), the wasm PIR client it runs.

## Running a node

The operator binary is `raven-railgun serve-production --config <file>`. Example configs are in
`adapters/railgun/examples/` (`mainnet-ppoi.toml`, `sepolia-ppoi.toml`). The container image
builds from the repository root:

```bash
docker build -t raven-railgun -f adapters/railgun/Dockerfile .
```

`adapters/railgun/deploy/deploy.sh --help` installs or upgrades one node behind Caddy on a Docker
host.

## Build

`crates/inspire`, `adapters/howl` and `adapters/eth-state` are git submodules:

```bash
git clone --recursive https://github.com/hisoka-io/raven.git
# already cloned without --recursive:
git submodule update --init --recursive
```

```bash
cargo test --workspace
cargo check -p raven-client --target wasm32-unknown-unknown
cargo test --manifest-path adapters/railgun/Cargo.toml --profile ci-test
```

`--workspace` covers the root members only. `crates/inspire`, `adapters/railgun`,
`adapters/railgun/client-wasm`, `adapters/howl`, `adapters/eth-state`, `benches/b1-bench` and
`tools/bench-compare` are outside the root workspace; build each with its own `--manifest-path`.
The wasm target applies to the client path, not to server crates. The adapter's PIR tests need
the `ci-test` profile; a debug build is too slow for them.

## Toward v1

Hiding the shard within its block, unlinkable per-operation sessions, and a parameter set of at
least 128 bits.

## Contributing

Run `scripts/preflight.sh` before pushing: it runs every workspace's hygiene, format and lint
gate (`--fast` for hygiene and format only, `--with-tests` for the detached suites). A change is
ready when it builds with zero warnings, passes `cargo clippy --all-targets -- -D warnings` in
every workspace it touches, keeps client-path crates building for `wasm32-unknown-unknown`, and
carries tests for new logic (a known-answer test wherever cryptography is involved). Library code
returns typed errors rather than panicking. Application-specific code belongs in `adapters/`,
never in `crates/`. Open an issue before a change to public API, crate layout, dependencies or
cryptographic parameters. Report vulnerabilities privately, as [SECURITY.md](./SECURITY.md)
describes.

## License

[Apache-2.0](./LICENSE) © Hisoka.io
