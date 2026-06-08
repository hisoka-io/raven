# Security Policy

Raven is a general-purpose Private Information Retrieval (PIR) framework. It is
pre-1.0 and under active development. This document states what is and is not
covered by the current security posture, two open items that materially affect
real-value deployments, and how to report a vulnerability.

## Supported Versions

Raven has not reached a stable 1.0 release. Only the latest published release on
the default branch receives security fixes. Pre-release versions (0.x, alpha,
beta) are provided for evaluation and integration testing; they carry NO
backward-compatibility or fix-backport guarantee.

| Version          | Supported              |
| ---------------- | ---------------------- |
| latest release   | yes                    |
| older 0.x / pre  | no (upgrade to latest) |

Until 1.0, the public API and on-wire formats may change between releases. Do
not pin a deployment to an unsupported version.

## Open Security Items (read before serving real value)

Two items are KNOWN, DOCUMENTED, and currently OPEN. Neither is a defect to be
quietly fixed later; both are honesty-as-credibility disclosures. Serving real
value on a Raven deployment is gated on resolving them as described.

### G6 - Unresolved noise-variance factor in parameter derivation

Location: crates/inspire/src/params.rs (get_variance, approximately lines
510-530).

An external review flagged a potentially missing (q~ / q)^2 factor in the
ring-LWE noise-variance computation (the get_variance derivation, cross-checked
against InsPIRe Theorem 7). The current implementation mirrors the upstream
Google private-membership InsPIRe reference verbatim; the factor, if it is
authoritatively required by the paper, may be absorbed upstream into
noise-budget slack. Under the current formula, sampled parameter cells satisfy
the noise budget with only a thin slack margin.

Status: GATED ON CRYPTOGRAPHER REVIEW. This item must be resolved by a direct
read of InsPIRe Theorem 7 against the implementation plus a noise-calibration
measurement before any deployment serves real value. A change here alters
shipping noise-budget assumptions, so it is not a routine code edit.

Why it is disclosed rather than silently patched: a wrong noise bound can turn
into a correctness failure or a privacy leak. We would rather state the open
question plainly than ship an unaudited "fix."

### G7 - Plaintext shard_id reduces the anonymity set to one shard

The client computes the target shard locally and addresses the query to a shard
by an explicit, PLAINTEXT shard identifier. PIR hides WHICH ENTRY within a shard
the client wants, but WHICH SHARD is in the clear. Consequently the anonymity
set is ONE SHARD (approximately 2048 entries with default parameters), NOT the
full database N.

Impact: an observer learns the shard partition the target entry lives in. For a
deployment with many shards this is a coarse-grained but real leak of where the
queried record resides.

Two proposed widenings (both planned, neither shipped):

1. One-shard-per-cell. Make "which shard" carry no information beyond "which
   cell," so the plaintext shard identifier reveals nothing finer than the cell
   boundary. This interacts with a cell-shape change and needs a re-bootstrap
   migration, so it must be sequenced deliberately.

2. Client decoy fan-out. The client fires k decoy queries alongside the real
   one, widening the anonymity set to k+1 shards; full fan-out reaches the full
   N at k times the server cost. All responses are consumed client-side so the
   choice of the real answer leaks no timing signal.

Status: DOCUMENTED AND ACCEPTED as a current tradeoff. Operators serving real
value must either accept the one-shard anonymity set explicitly or deploy one of
the widenings above.

## Reporting a Vulnerability

Please report suspected security vulnerabilities PRIVATELY. Do NOT open a public
issue, pull request, or discussion for an undisclosed vulnerability, and do not
disclose it on social channels before a fix is available.

Contact: [SECURITY_CONTACT]

In your report, please include where practical:

- A description of the issue and the security impact you believe it has.
- The affected version, commit, or release.
- A minimal reproduction or proof of concept.
- Any relevant configuration (scheme, parameters, deployment shape).

Do NOT include secret keys, private query vectors, raw database rows, or other
sensitive material in a report. Public parameters and request identifiers are
sufficient.

### Disclosure Process

- We aim to acknowledge a valid report within a few business days.
- We will work with you on a fix and a coordinated disclosure timeline.
- We follow a 90-DAY responsible-disclosure window: if a reported vulnerability
  is not resolved within 90 days of acknowledgement, the reporter is free to
  disclose publicly. We may request a short extension for complex cryptographic
  fixes, agreed with the reporter.
- Credit is given to reporters who follow this process, unless anonymity is
  requested.

## Scope Notes

Raven is the generic PIR framework only. Application-layer concerns
(chain indexing, application event schemas, deployment glue) live in separate
adapter repositories and are out of scope for this policy. Cryptographic safety,
correctness of the PIR primitives, constant-time handling of secret inputs, and
the two open items above are in scope.
