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

### G6 - InspiRING packing noise is not modelled by the variance formula

Location: crates/inspire/src/params.rs - get_variance and
InspireParams::for_scenario, which carry the disclosure in-source; the
measurement is crates/inspire/benches/packing_noise_measurement.rs.

This item previously disclosed TWO gaps. The first is resolved; the second is
open but now bounded by measurement rather than by prose.

RESOLVED - the (q~ / q)^2 factor. An external review flagged a potentially
missing (q~ / q)^2 factor against InsPIRe Theorem 7. A direct read of the
theorem on 2026-08-01 settled it: get_variance computes the PRE-mod-switch
variance, which is the correct object for sizing q, and required_q_log2 sizes q
rather than q~. The factor legitimately does not belong there. What IS absent
from the formula is the theorem's additive d*sigma_chi^2/4 mod-switch rounding
term - inert while nothing mod-switches, and load-bearing the moment response
modulus switching ships. params.rs carries this correction in-source.

OPEN - packing noise. The reproduced get_variance formula covers Spiral-family
LWE and gadget noise only; it does NOT model the additional noise that InspiRING
2-matrix packing introduces. The failure mode is SILENT: decryption produces
random-looking bytes once the packing noise crosses the Delta/2 = q/(2p) decode
boundary, with no error raised. Empirically the derived q ~= 2^53 is
insufficient for a 2^20 x 256 B cell under TwoPacking + InspiRING even though
the noise-budget gate reports approximately 0.093 bits of slack. The shipped
mitigation is InspireParams::for_scenario_with_crt with a wider 2-CRT pair
(typically 2 x 30-bit primes, q ~= 2^60); for_scenario is retained for scenarios
where the tree-packed extract path is the only one in use.

MEASURED, 2026-09-20. The packed-response noise is now sampled on the shipped
respond path at both production record widths, 1,000 responses each, and the
worst sample is asserted against the decode boundary. Against a boundary of
8,795,958,806,527:

  32 B records  (gamma 16):  worst sample  3,675,159,993  -  11.225 bits margin
  512 B records (gamma 256): worst sample 14,500,737,099  -   9.245 bits margin

The narrower margin is at the 512 B width, which is what the PPOI path records
ship at. The measurement is a test assertion, so a parameter or packing change
that erodes the margin fails rather than scrambling a response in production.

What this does NOT establish, stated plainly because the distinction is the
whole point of the disclosure: an empirical margin over 1,000 samples is not an
analytic bound. It shows the shipped cell is comfortably inside the boundary on
the sampled path; it does not model the term, and it does not bound the tail.
get_variance's own slack figure therefore remains unreliable as a predictor -
the number to trust is the measured margin, not the 0.093 bits the gate reports.

Consequence for operators: the formula's thin slack margin must not be read as a
passing margin. Read the measured margin above instead, and re-run the
measurement after any change to packing, noise sampling, parameters or the
mod-switch gate.

Status: the two conditions this disclosure set for itself - a direct read of
InsPIRe Theorem 7 against the implementation, and a noise-calibration
measurement - are both now met. What remains open is the modelling: get_variance
still does not include a packing term, and adding one alters shipping
noise-budget assumptions, so it is not a routine code edit.

Why it is disclosed rather than silently patched: a wrong noise bound can turn
into a correctness failure or a privacy leak. We would rather state the open
question plainly than ship an unaudited "fix."

### G7 - Plaintext shard_id reduces the anonymity set to one shard

The client computes the target shard locally and addresses the query to a shard
by an explicit, PLAINTEXT shard identifier. PIR hides WHICH ENTRY within a shard
the client wants, but WHICH SHARD is in the clear. Consequently the anonymity
set is ONE SHARD, NOT the full database N. Raven core ships no default shard
size; entries-per-shard is set by the deploying adapter, and that figure is what
an operator must reason about here.

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

Preferred channel: GitHub private vulnerability reporting on this repository -
the "Security" tab, then "Report a vulnerability". Reports filed there are
visible only to the maintainers.

Fallback, if private reporting is unavailable to you: hello@hisoka.io, published
on the hisoka-io GitHub organisation profile. It is a general inbox rather than a
dedicated security mailbox, so expect a slower first response than the timeline
below and do not include any exploit detail you would not want read by a
non-security recipient.

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
