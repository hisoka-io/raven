# raven-railgun-mock-ppoi

> **SYNTHETIC mock; NOT real OFAC data; NEVER deploy to production.**

Standalone axum binary that impersonates the upstream Railgun PPOI
surface so the adapter's PPOI mirror worker can populate empty PPOI
instances during the public demo.

## What this is

A minimal HTTP service that serves the same wire shape as the upstream
private-proof-of-innocence node, but with a deterministic synthetic
corpus instead of real list-provider data. The adapter does not
verify upstream signatures, which is what makes this stand-in
functionally adequate for the PIR pipeline; treating its output as
authoritative would conflate real-OFAC data with a synthetic corpus.

## Honest framing

- The corpus is generated from a seed, not collected from any list
  authority.
- The signing key is freshly generated at startup and discarded on
  shutdown. It signs nothing.
- The OFAC `list_key` default is reused only so the adapter's
  `mirror_endpoint` config parses without override, not because the
  data has any relation to real OFAC sanctions.
- Every deployment logs `raven-railgun-mock-ppoi: SYNTHETIC corpus, do
  not pass off as real OFAC` at INFO level on startup so the synthetic
  status is visible in operator logs.

## Wire surface

Exactly two endpoints are required by the adapter mirror; the other
two are convenience read-only endpoints:

- `POST /poi-events/{chainType}/{chainID}` - body
  `{txidVersion, listKey, startIndex, endIndex}` -> `Vec<POISyncedListEvent>`
- `POST /pois-per-blinded-commitment/{chainType}/{chainID}` - body
  `{txidVersion, listKey, blindedCommitmentDatas: [{blindedCommitment, type}]}`
  -> `{[bc]: POIStatus}`
- `GET /node-status-v2` - list of supported list keys
- `GET /node-status-v2/{listKey}` - synthetic status for a list

Schemas mirror upstream
`private-proof-of-innocence/packages/node/src/api/schemas.ts` and
`models/poi-types.ts`.

## CLI

```
raven-railgun-mock-ppoi serve \
  --bind 0.0.0.0:8088 \
  --list-key efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88 \
  --corpus-size 1000 \
  --corpus-seed deadbeefcafebabefacefeed0123456789abcdef0123456789abcdef00112233 \
  --blocked-bcs-csv /optional/path.csv
```

CSV format: one 64-char (or `0x`-prefixed 66-char) hex BC per line.
Lines starting with `#` are comments. Listed BCs are tagged
`ShieldBlocked` instead of the default `Valid`, enabling the
leak-vs-no-leak demo contrast against the same engine.
