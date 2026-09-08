#!/usr/bin/env bash
# Every VALUE symbol exported from the SDK's public surface (sdk/src/index.ts) must be
# referenced by at least one test file that actually runs in CI.
#
# Why this exists: the package has no coverage tooling at all, and an audit found three
# public exports with ZERO test references — one of them (subscribeRavenEvents) an entire
# 110-line module consuming untrusted server JSON. The three permanently env-gated
# live_*.test.ts files do NOT count as coverage: a symbol tested only there is untested
# in every CI run.
#
# Guards against its own vacuity: it refuses to pass if the export extraction or the
# test-file scan comes back implausibly empty, so a format change in index.ts fails the
# gate instead of silently emptying it. A reference is counted only outside import
# lines, in a file that contains at least one expect( — a file of imports with no
# assertions is not coverage.
set -uo pipefail

ADAPTER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK="${ADAPTER_ROOT}/sdk"
INDEX="${SDK}/src/index.ts"

if [[ ! -f "$INDEX" ]]; then
  echo "check-sdk-export-coverage: missing ${INDEX}" >&2
  exit 3
fi

# Value exports: identifiers inside `export { ... }` blocks — single-line or multi-line —
# minus `type X` entries and whole `export type { ... }` blocks.
symbols="$(awk '
  /^export type \{/ { skipblock = 1 }
  skipblock { if (/\}/) skipblock = 0; next }
  /^export \{.*\}/ {
    line = $0
    sub(/^export \{/, "", line)
    sub(/\}.*$/, "", line)
    n = split(line, parts, ",")
    for (i = 1; i <= n; i++) {
      p = parts[i]
      gsub(/^[ \t]+|[ \t]+$/, "", p)
      if (p ~ /^type /) continue
      if (p != "") print p
    }
    next
  }
  /^export \{/ { inblock = 1; next }
  inblock && /^\}/ { inblock = 0; next }
  inblock {
    line = $0
    gsub(/,/, "", line)
    gsub(/^[ \t]+|[ \t]+$/, "", line)
    if (line ~ /^type /) next
    if (line == "") next
    print line
  }
' "$INDEX" | sort -u)"

sym_count="$(printf '%s\n' "$symbols" | sed '/^$/d' | wc -l)"
if [[ "$sym_count" -lt 20 ]]; then
  echo "check-sdk-export-coverage: extracted only ${sym_count} value exports from index.ts — extraction is broken, refusing to pass vacuously" >&2
  exit 3
fi

# CI-run test files: everything except the env-gated live tier.
mapfile -t test_files < <(ls "${SDK}"/tests/*.test.ts | /usr/bin/grep -v '/live_')
if [[ "${#test_files[@]}" -lt 10 ]]; then
  echo "check-sdk-export-coverage: found only ${#test_files[@]} non-live test files — scan is broken, refusing to pass vacuously" >&2
  exit 3
fi

uncovered=()
covered=0
for sym in $symbols; do
  hit=0
  for f in "${test_files[@]}"; do
    # Reference outside import lines, in a file that asserts something. NO pipe into
    # `grep -q` here: under pipefail its early exit SIGPIPEs the producer and the
    # pipeline "fails" nondeterministically on a successful match.
    filtered="$(/usr/bin/grep -v -E '^\s*import|^\s*\} from|from "\.\./src' "$f" || true)"
    if /usr/bin/grep -q "\b${sym}\b" <<<"$filtered" \
      && /usr/bin/grep -q 'expect(' "$f"; then
      hit=1
      break
    fi
  done
  if [[ "$hit" -eq 1 ]]; then
    covered=$((covered + 1))
  else
    uncovered+=("$sym")
  fi
done

if [[ "$covered" -lt 5 ]]; then
  echo "check-sdk-export-coverage: only ${covered} symbols matched anywhere — the matcher is broken, refusing to pass vacuously" >&2
  exit 3
fi

if [[ "${#uncovered[@]}" -gt 0 ]]; then
  echo "check-sdk-export-coverage: public exports with ZERO references in any CI-run test:" >&2
  for sym in "${uncovered[@]}"; do
    echo "  ${sym}" >&2
  done
  echo "(${covered}/${sym_count} covered; live_*.test.ts never runs in CI and does not count)" >&2
  exit 1
fi

echo "check-sdk-export-coverage: all ${sym_count} public value exports are referenced by CI-run tests."
