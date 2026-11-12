#!/usr/bin/env bash
# Reads a cargo test log run with --show-output and settles its AVX-512 capability skips.
#
#   scripts/simd-skips.sh <log> <required: 0|1>
#
# required=1 (the runner carries the kernel's flags): any LOUD SKIP fails the step. The tests
# already panic on a skip under RAVEN_REQUIRE_AVX512=1; this holds the step even if a test's own
# guard is weakened. required=0: each skip becomes a warning annotation, so it is seen on the run
# page rather than buried in captured test output.
set -euo pipefail

log="${1:?log}"
required="${2:?required 0|1}"
[[ -s "$log" ]] || { echo "simd-skips: $log is empty or missing" >&2; exit 2; }
grep -q '^test result: ' "$log" || { echo "simd-skips: $log holds no test result" >&2; exit 2; }

skips="$(grep -o 'LOUD SKIP: .*' "$log" | sort -u || true)"
if [[ -z "$skips" ]]; then
  echo "simd-skips: no capability skip"
  exit 0
fi
if [[ "$required" == 1 ]]; then
  echo "simd-skips: this runner carries the kernel's flags, so these differentials were required:" >&2
  printf '%s\n' "$skips" >&2
  exit 1
fi
while IFS= read -r line; do
  echo "::warning title=AVX-512 differential skipped::${line}"
done <<< "$skips"
