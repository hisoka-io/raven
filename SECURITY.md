# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately. Do not open a public issue, pull request or
discussion for an undisclosed vulnerability.

Use GitHub private vulnerability reporting on this repository: the "Security" tab, then "Report a
vulnerability". Reports filed there are visible only to the maintainers. If that is unavailable to
you, write to hello@hisoka.io, the address on the hisoka-io GitHub organisation profile; it is a
general inbox, so leave exploit detail out of the first message.

Include where practical a description and the impact you believe it has, the affected version or
commit, a minimal reproduction, and the configuration (scheme, parameters, deployment shape). Do
not include secret keys, query vectors or database rows.

We aim to acknowledge a report within a few business days and to agree a fix and disclosure
timeline with you. If a reported vulnerability is not resolved within 90 days of acknowledgement,
you are free to disclose it; we may ask for a short extension for a complex cryptographic fix.
Reporters are credited unless they ask not to be.

Only the latest release receives fixes. Until 1.0 the public API and wire formats may change
between releases.

## What v0 provides

**Parameters.** The shipped InsPIRe parameter set, `InspireParams::secure_128_d2048`, is ring
dimension 2,048, ciphertext modulus q = 2^60 - 2^14 + 1, plaintext modulus 65,537, Gaussian width
6.4 and gadget base 2^20. Its security is estimated at 121.5 bits with the lattice estimator
(binding attack: primal BDD); the preset's name predates that measurement. Before it derives a key,
the client refuses a served parameter set with a ring dimension outside 2,048 to 4,096, a larger
modulus, another error width, or gadgets longer than 3 digits.

**Shards.** A shard holds exactly as many rows as the ring dimension, 2,048 at the shipped
parameters; setup refuses any other shard height.

**What the server sees.** No request to a Raven node carries a commitment. For each proof query
the node sees the block it targets, the 2,048-row shard it targets, the padded size of its batch,
the session and client identifier it arrives with (which link one client's queries), the client's
network address and the timing. It does not see which row of the shard was queried. The five upper
Merkle levels of a path are the same for every row of a shard and are returned in the clear beside
the PIR response. PPOI status is answered on the device from a 6-byte prefix index, synced from
cursors aligned to 2,048 rows. Proof submission and root validation go to the upstream PPOI
aggregator as they do without Raven, and the root check for a served path asks upstream for the
block number unless the wallet preloads its roots.

**Integrity.** The node verifies every mirrored row's Ed25519 signature under the list provider's
key at ingest and holds each row to the root upstream published with it. The client folds every
served auth path and accepts it only against a root obtained independently of the node.

**Noise.** Decryption fails silently once noise passes the decode boundary, so the margin is
measured: `crates/inspire/benches/packing_noise_measurement.rs`, a benchmark run by hand, samples
1,000 served (mod-switched, 36-bit) responses per record width and finds a worst-case margin of
8.88 bits at 512-byte rows and 10.30 bits at 32-byte rows. This is a measurement, not an analytic
bound.

## Scope

In scope: the PIR primitives and their parameters, constant-time handling of client secrets, the
client and SDK, and the Railgun adapter in this repository.
