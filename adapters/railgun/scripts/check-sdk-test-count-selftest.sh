#!/usr/bin/env bash
# Red-proof for check-sdk-test-count.sh. Runs the suite ONCE, then judges that one report against
# counts files one test off the truth in each direction, and requires the gate to refuse both:
#
#   grew-past-counts:  the suite passes one more test than the counts file says. A floor let this
#                      through, and it is how a deleted test hides behind two added ones.
#   fell-short:        the suite passes one fewer, a test that silently stopped running.
#
# The real counts file is never written to and no git command is run.
set -uo pipefail

ADAPTER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK="${ADAPTER_ROOT}/sdk"
GATE="${ADAPTER_ROOT}/scripts/check-sdk-test-count.sh"
COUNTS="${SDK}/tests/EXPECTED_COUNTS.json"

fail() { echo "check-sdk-test-count-selftest: $*" >&2; exit 1; }

[[ -d "${SDK}/node_modules" ]] || { echo "check-sdk-test-count-selftest: ${SDK}/node_modules missing - run pnpm install first" >&2; exit 3; }

owns_scratch=0
if [[ -n "${SDK_TEST_COUNT_SELFTEST_SCRATCH:-}" ]]; then
  mkdir -p "$SDK_TEST_COUNT_SELFTEST_SCRATCH"
  SCRATCH="$(cd "$SDK_TEST_COUNT_SELFTEST_SCRATCH" && pwd)"
else
  SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/sdk-test-count-selftest.XXXXXX")"
  owns_scratch=1
fi
cleanup() { if [[ "$owns_scratch" -eq 1 ]]; then rm -rf "$SCRATCH"; fi; }
trap cleanup EXIT

report="${SCRATCH}/report.json"
( cd "$SDK" && ./node_modules/.bin/vitest run --config tests/vitest.config.ts --reporter=json >"$report" 2>"${SCRATCH}/suite.err" ) \
  || { tail -n 20 "${SCRATCH}/suite.err" >&2; fail "the suite itself failed; fix that first"; }

judge() { # counts-file logfile
  SDK_TEST_COUNT_EXPECTED="$1" SDK_TEST_COUNT_REPORT="$report" "$GATE" >"$2" 2>&1
}

if ! judge "$COUNTS" "${SCRATCH}/truth.log"; then
  cat "${SCRATCH}/truth.log" >&2
  fail "the gate refuses the real counts file - the red-proof below would prove nothing"
fi
echo "  ok    the real counts file matches the suite"

expect_red() { # label passed-delta
  local label="$1" delta="$2" counts="${SCRATCH}/$1.json" log="${SCRATCH}/$1.log"
  node -e '
const fs = require("fs");
const counts = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
counts.passed += Number(process.argv[3]);
fs.writeFileSync(process.argv[2], JSON.stringify(counts, null, 2) + "\n");
' "$COUNTS" "$counts" "$delta" || exit 3
  if judge "$counts" "$log"; then
    fail "${label}: the gate PASSED a count it must refuse"
  fi
  /usr/bin/grep -q 'FAIL  passed (exact)' "$log" \
    || { cat "$log" >&2; fail "${label}: the gate failed, but not on the passed count"; }
  echo "  ok    ${label}: refused on the passed count"
}

expect_red grew-past-counts -1
expect_red fell-short 1

echo "check-sdk-test-count-selftest: the gate refuses a suite that grew past its counts and one that fell short."
