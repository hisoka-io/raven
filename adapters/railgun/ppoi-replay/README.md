# raven-railgun-ppoi-replay

Serves a recorded capture of one Railgun PPOI list over the upstream PPOI node's JSON-RPC
methods, so tests, benchmarks and a local cold sync run against real list data without any
request reaching Railgun's aggregator.

The rows are the capture's own: every signature, `validatedMerkleroot` and wire string is what
upstream served. Nothing is generated and nothing is signed here. A response for a recorded
request is the recorded upstream body, byte for byte, apart from the fields listed under
[Byte-exactness](#byte-exactness).

## The capture folder

| File | Used for |
|---|---|
| `events.bin` | The rows. 64-byte header (`RVNPPOI1`, version 1, row size 133, count, first index 0, list key), then per row: `u32` LE index, `u8` type (0 Shield, 1 Transact, 2 Unshield, 3 LegacyTransact), 32-byte `blindedCommitment`, 32-byte `validatedMerkleroot`, 64-byte signature. Hashes are the big-endian bytes of the wire hex. |
| `noncanonical.jsonl` | Rows whose wire strings differ from the canonical rebuild (`"0x"` + lowercase hex for the commitment, bare lowercase hex for root and signature). Their strings are served verbatim. Each must decode to its row's bytes or the folder is refused. |
| `manifest.json` | `chain` (`chainType`, `chainID`, `network`, `txidVersion`); `n` and `list_key` must agree with `events.bin`. |
| `node-status-end.json` | A recorded `ppoi_node_status` response, served with this list's status following the served prefix. |

`read_events_bin` and `write_events_bin` are the reader and writer; tests build small lists with
the writer and never read a capture.

## Running it

```
raven-railgun-ppoi-replay --capture <folder> --bind 127.0.0.1:8088 \
    [--rows N] [--grow-rows K --grow-interval-secs S] [--node-status <file>]
```

Point a mirror or SDK endpoint at `http://127.0.0.1:8088`. `--rows` serves the first `N` rows
(default: all). With `--grow-rows`, the served count grows by `K` every `S` seconds until the whole
capture is served, so a mirror sees a catch-up and then growth. In code, `Replay::grow_to` does the
same. The list only grows: a smaller count is refused.

The container image (`adapters/railgun/Dockerfile.ppoi-replay`) holds the binary only. Mount a
capture folder at `/capture`.

## Methods

Only `POST /` is served. It is the one route Raven's clients call.

| Method | Caller | Answer |
|---|---|---|
| `ppoi_poi_events` | ppoi-mirror feed and preflight, SDK pin resolver | Upstream's `getPoiEvents`: rows with `startIndex <= index <= endIndex` among the served rows, in index order. `endIndex - startIndex` above 500 is refused with HTTP 500 and `{"code":-32603,"message":"Max event query range length is 500"}`, the aggregator's measured answer, so a page holds at most 501 rows. A negative span gets `Invalid query range` in the same shape. |
| `ppoi_node_status` | SDK pin resolver | The recorded body's `result`. For this network and list, `poiEventLengths`, `historicalMerklerootsLength` and `latestHistoricalMerkleroot` are computed from the served rows (`No merkleroot found` when none are). |
| `ppoi_validate_poi_merkleroots` | SDK | `true` if every root is the stored spelling (bare lowercase hex) of a served row's root. |
| `ppoi_submit_transact_proof`, `ppoi_submit_legacy_transact_proofs` | SDK | Refused: HTTP 500, `-32603`. A recording cannot take a submission, and answering success would claim an acceptance that did not happen. |

Every other method gets upstream's HTTP 404 `-32601 Method not found`. That includes
`ppoi_pois_per_blinded_commitment` and `ppoi_pois_per_list`: Raven never asks Railgun about an
individual commitment. A `listKey` other than the capture's gets upstream's HTTP 400
`{"code":-32602,"message":"Invalid params","data":"Invalid listKey"}`. The shared rules follow the
upstream node: `params` is checked against upstream's schema (`-32602` with ajv-style `data`), the
JSON-RPC `id` is echoed and left out when the request had none, and a body not declared
`application/json` is read as `{}`.

Where it differs from upstream:

- It serves one network and one list. Another known chain gets `No network info available.`
  (HTTP 500), another `txidVersion` an empty result.
- `ppoi_node_status` with a `listKey` gets `Cannot connect to listKey`, because upstream forwards
  that call to the list's own node and a replay has none.
- A body that is not JSON gets a JSON-RPC `-32700` error, not Express's HTML page.
- Missing `params` gets `-32602`. Upstream throws outside its handler and never answers.

## Byte-exactness

For each recorded `ppoi_poi_events` page, serving the capture at the row count it was recorded
at and replaying the request returns the recorded body byte for byte. Row order, member order,
the five unprefixed commitments and the repeated commitment all come out as recorded. Two kinds of
field differ:

- **Request echo:** the JSON-RPC `id`.
- **Time-varying, in `ppoi_node_status` only:** everything the list's rows do not determine, which
  is served as recorded: `txidStatus.*`, `blockedShields` and `pendingTransactProofs`, every other
  list's and network's status, `shieldQueueStatus` and `legacyTransactProofs`. A status recorded
  at another time differs from the recording being served in these fields only. This list's
  three derived fields match what upstream reported at every row count a status was recorded at.

## What this is not

- Not a list authority. Authenticity rests on the capture's own signatures and roots.
- Not a status source for a commitment, and not a proof mempool.
- Not live. When the list moves on, refresh the capture and restart.
