#!/usr/bin/env bash
# Red-proof for the sdk-tests lane: a green `pnpm test` is evidence only if the suite
# CAN go red. This workstream found four separate cannot-fail tests inside the SDK suite,
# so the lane's own greenness was not evidence of anything.
#
# Model: check-wasm-bundle-size-selftest.sh. Copies the SDK tree to a scratch dir OUTSIDE
# the repo (a fresh CI checkout has no writable scratch inside it, and nothing this script
# does should ever land in the working tree),
# deletes the schema-envelope version guard there (the exact mutation that once left the
# WHOLE suite green — M3, w4d-sdk — and is now killed by
# tests/t1_end_to_end_real_decode.test.ts), runs the suite in the copy, and FAILS if the
# suite comes back green. The real tree is never modified and no git command is run.
set -uo pipefail

ADAPTER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK="${ADAPTER_ROOT}/sdk"
REPO_ROOT="$(cd "${ADAPTER_ROOT}/../.." && pwd)"

# Scratch OUTSIDE the repo entirely, so a CI checkout gets no written-into directory and
# a local run cannot leave a copy of the tree behind. Overridable; a scratch that IS the
# repo root, the SDK, or inside the repo is refused rather than trusted.
owns_scratch=0
if [[ -n "${SDK_SELFTEST_SCRATCH:-}" ]]; then
  mkdir -p "$SDK_SELFTEST_SCRATCH"
  SCRATCH="$(cd "$SDK_SELFTEST_SCRATCH" && pwd)"
else
  SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/sdk-suite-selftest.XXXXXX")"
  owns_scratch=1
fi
if [[ -z "$SCRATCH" || "$SCRATCH" == "$REPO_ROOT" || "$SCRATCH" == "$SDK" || "$SCRATCH" == "$REPO_ROOT"/* ]]; then
  echo "check-sdk-suite-selftest: refusing to use ${SCRATCH} as scratch" >&2
  exit 3
fi

if [[ ! -d "${SDK}/node_modules" ]]; then
  echo "check-sdk-suite-selftest: ${SDK}/node_modules missing — run pnpm install first" >&2
  exit 3
fi

work="${SCRATCH}/copy-$$"
fanout_work="${SCRATCH}/fanout-copy-$$"
pristine_json="${SCRATCH}/pristine-$$.json"
pristine_err="${SCRATCH}/pristine-$$.err"
fanout_green_json="${SCRATCH}/fanout-green-$$.json"
fanout_green_err="${SCRATCH}/fanout-green-$$.err"
fanout_red_json="${SCRATCH}/fanout-red-$$.json"
fanout_red_err="${SCRATCH}/fanout-red-$$.err"
schema_json="${SCRATCH}/schema-red-$$.json"
schema_err="${SCRATCH}/schema-red-$$.err"
mkdir -p "$work"
cleanup() {
  rm -rf "$work" "$fanout_work" "${SCRATCH}/poseidon"
  rm -f "$pristine_json" "$pristine_err" "$fanout_green_json" "$fanout_green_err" \
    "$fanout_red_json" "$fanout_red_err" "$schema_json" "$schema_err"
  if [[ "$owns_scratch" -eq 1 ]]; then rm -rf "$SCRATCH"; fi
}
trap cleanup EXIT

# Copy every package file that affects `npm pack`. Keep node_modules local so the packed fanout
# probe can create its scratch directory without writing through a symlink into the real SDK.
cp -a "${SDK}/src" "${SDK}/tests" "${SDK}/tsconfig.json" "${SDK}/package.json" \
  "${SDK}/README.md" "${SDK}/pnpm-lock.yaml" "${SDK}/.gitignore" "$work/"
mkdir -p "$work/node_modules"
cp -as "${SDK}/node_modules/." "$work/node_modules/"

# tests/poseidon_parity.test.ts reads the Rust-emitted KAT from a SIBLING package,
# ../../poseidon/tests/fixtures/. Without it the copy reds with an ENOENT that has
# nothing to do with the mutation - a red for the wrong reason, which is the exact
# thing this script exists to refuse. Recreate that sibling beside the copy.
POSEIDON_FIXTURES="${ADAPTER_ROOT}/poseidon/tests/fixtures"
if [[ ! -d "$POSEIDON_FIXTURES" ]]; then
  echo "check-sdk-suite-selftest: missing ${POSEIDON_FIXTURES} — the copy would red for the wrong reason" >&2
  exit 3
fi
mkdir -p "${SCRATCH}/poseidon/tests"
cp -a "$POSEIDON_FIXTURES" "${SCRATCH}/poseidon/tests/"

json_line() { # report
  node -e '
const fs = require("fs");
const line = fs.readFileSync(process.argv[1], "utf8")
  .split("\n").find((candidate) => candidate.trimStart().startsWith("{"));
if (!line) process.exit(3);
process.stdout.write(line);
' "$1"
}

check_named_report() { # report title status failed_count
  local report="$1" title="$2" status="$3" failed_count="$4" raw
  raw="$(json_line "$report")" || {
    echo "check-sdk-suite-selftest: no JSON report in ${report}" >&2
    return 1
  }
  node -e '
const report = JSON.parse(process.argv[1]);
const title = process.argv[2];
const status = process.argv[3];
const failed = Number(process.argv[4]);
const assertions = (report.testResults ?? []).flatMap((file) => file.assertionResults ?? []);
const hits = assertions.filter((test) => test.title === title);
if (hits.length !== 1 || hits[0].status !== status || report.numFailedTests !== failed) {
  console.error(`named test mismatch: title=${title} hits=${hits.length} status=${hits[0]?.status} failed=${report.numFailedTests}`);
  process.exit(1);
}
' "$raw" "$title" "$status" "$failed_count"
}

echo "check-sdk-suite-selftest: verifying the unmutated scratch suite"
( cd "$work" && NO_COLOR=1 ./node_modules/.bin/vitest run \
    --config tests/vitest.config.ts --reporter=json >"$pristine_json" 2>"$pristine_err" )
pristine_exit=$?
if [[ "$pristine_exit" -ne 0 ]]; then
  echo "check-sdk-suite-selftest: unmutated scratch suite failed (exit ${pristine_exit})" >&2
  tail -n 20 -- "$pristine_err" "$pristine_json" >&2
  exit 1
fi
pristine_report="$(json_line "$pristine_json")" || {
  echo "check-sdk-suite-selftest: unmutated scratch emitted no JSON report" >&2
  exit 1
}
node -e '
const fs = require("fs");
const report = JSON.parse(process.argv[1]);
const expected = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const files = report.testResults ?? [];
const skipped = report.numPendingTests + (report.numTodoTests ?? 0);
const skippedFiles = files.filter((file) => {
  const tests = file.assertionResults ?? [];
  return tests.length > 0 && tests.every((test) => ["pending", "skipped", "todo"].includes(test.status));
}).length;
if (files.length !== expected.testFiles || skippedFiles !== expected.skippedFiles ||
    report.numPassedTests < expected.passed || skipped !== expected.skipped) {
  console.error(`unmutated scratch counts: passed=${report.numPassedTests} skipped=${skipped} files=${files.length} skipped_files=${skippedFiles}`);
  process.exit(1);
}
console.log(`  unmutated scratch: ${report.numPassedTests} passed / ${skipped} skipped across ${files.length} files`);
' "$pristine_report" "$work/tests/EXPECTED_COUNTS.json" || exit 1

fanout_title='refuses the packed deep import that can emit a real unretargeted query'
( cd "$work" && NO_COLOR=1 ./node_modules/.bin/vitest run \
    --config tests/vitest.config.ts tests/fanout_cover.test.ts -t "$fanout_title" \
    --reporter=json >"$fanout_green_json" 2>"$fanout_green_err" )
fanout_green_exit=$?
if [[ "$fanout_green_exit" -ne 0 ]] \
  || ! check_named_report "$fanout_green_json" "$fanout_title" passed 0; then
  echo "check-sdk-suite-selftest: packed fanout boundary is not live in the pristine scratch" >&2
  tail -n 20 -- "$fanout_green_err" "$fanout_green_json" >&2
  exit 1
fi
echo "  packed fanout boundary: named test passed in pristine scratch"

cp -a "$work" "$fanout_work"
python3 - "$fanout_work/src/fanout-cover.ts" <<'PYEOF'
import io, sys
p = sys.argv[1]
s = io.open(p, encoding="utf-8").read()
needle = "export function encodeFanoutRequest("
if needle in s:
    raise SystemExit("dummy fanout mutation already present")
s += """
export function encodeFanoutRequest(
  _queryBytes: Uint8Array,
  _plan: FanoutCoverPlan,
  _wireSchemaVersion: number,
): Uint8Array {
  return new Uint8Array();
}
"""
io.open(p, "w", encoding="utf-8").write(s)
PYEOF
/usr/bin/grep -q '^export function encodeFanoutRequest(' \
  "$fanout_work/src/fanout-cover.ts" || {
  echo "check-sdk-suite-selftest: dummy fanout export mutation did not apply" >&2
  exit 3
}
( cd "$fanout_work" && NO_COLOR=1 ./node_modules/.bin/vitest run \
    --config tests/vitest.config.ts tests/fanout_cover.test.ts -t "$fanout_title" \
    --reporter=json >"$fanout_red_json" 2>"$fanout_red_err" )
fanout_red_exit=$?
if [[ "$fanout_red_exit" -eq 0 ]] \
  || ! check_named_report "$fanout_red_json" "$fanout_title" failed 1; then
  echo "check-sdk-suite-selftest: packed fanout boundary did not reject a deep encoder export" >&2
  tail -n 20 -- "$fanout_red_err" "$fanout_red_json" >&2
  exit 1
fi
echo "  packed fanout boundary: dummy encoder export killed the named test"

MUT_FILE="$work/src/raven-poi-node-interface.ts"
NEEDLE='if (envelope !== WIRE_SCHEMA_VERSION) {'
count="$(/usr/bin/grep -c "$NEEDLE" "$MUT_FILE" || true)"
if [[ "$count" -ne 1 ]]; then
  echo "check-sdk-suite-selftest: expected exactly 1 envelope-guard site, found ${count} — the mutation no longer applies; update this selftest" >&2
  exit 3
fi

# Delete the guard block (5 lines starting at the needle) in the COPY only.
python3 - "$MUT_FILE" <<'PYEOF'
import io, sys
p = sys.argv[1]
s = io.open(p, encoding="utf-8").read()
needle = """  if (envelope !== WIRE_SCHEMA_VERSION) {
    throw RavenError.decodeError(
      `${label}: unexpected schema envelope version ${envelope}`,
    );
  }
"""
n = s.count(needle)
if n != 1:
    raise SystemExit(f"needle count {n} != 1 — mutation did not apply")
io.open(p, "w", encoding="utf-8").write(s.replace(needle, ""))
PYEOF
if ! /usr/bin/grep -q 'unexpected schema envelope version' "$MUT_FILE"; then
  echo "  mutation applied: schema-envelope version guard deleted in the copy"
else
  echo "check-sdk-suite-selftest: mutation failed to apply" >&2
  exit 3
fi

( cd "$work" && NO_COLOR=1 ./node_modules/.bin/vitest run \
    --config tests/vitest.config.ts --reporter=json >"$schema_json" 2>"$schema_err" )
suite_exit=$?

if [[ "$suite_exit" -eq 0 ]]; then
  echo "check-sdk-suite-selftest: FAILED - the suite stayed GREEN with the envelope guard deleted; the lane cannot detect the silent-wrong-bytes class it exists for." >&2
  tail -n 5 -- "$schema_err" "$schema_json" >&2
  exit 1
fi
schema_report="$(json_line "$schema_json")" || {
  echo "check-sdk-suite-selftest: schema mutation emitted no JSON report" >&2
  exit 1
}
node -e '
const fs = require("fs");
const report = JSON.parse(process.argv[1]);
const expected = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const fanoutTitle = process.argv[3];
const wantedFailures = new Set([
  "refuses an unknown schema envelope version instead of eating two payload bytes",
  "refuses a previous-schema prefix before WASM extraction",
]);
const files = report.testResults ?? [];
const assertions = files.flatMap((file) => file.assertionResults ?? []);
const failures = assertions.filter((test) => test.status === "failed");
const failureTitles = new Set(failures.map((test) => test.title));
const fanout = assertions.filter((test) => test.title === fanoutTitle);
const skipped = report.numPendingTests + (report.numTodoTests ?? 0);
if (failures.length !== 2 || report.numFailedTests !== 2 || failureTitles.size !== 2 ||
    [...wantedFailures].some((title) => !failureTitles.has(title)) ||
    fanout.length !== 1 || fanout[0].status !== "passed" ||
    files.length !== expected.testFiles || skipped !== expected.skipped ||
    report.numPassedTests + report.numFailedTests < expected.passed) {
  console.error(`schema mutation mismatch: failures=${failures.map((test) => test.title).join(" | ")} fanout=${fanout[0]?.status} passed=${report.numPassedTests} skipped=${skipped} files=${files.length}`);
  process.exit(1);
}
' "$schema_report" "$work/tests/EXPECTED_COUNTS.json" "$fanout_title" || {
  tail -n 20 -- "$schema_err" "$schema_json" >&2
  exit 1
}
echo "check-sdk-suite-selftest: schema guard deletion failed exactly both version tests; packed fanout stayed green."
