#!/usr/bin/env bash
# Red-proof for the sdk-tests lane: a green `pnpm test` is evidence only if the suite
# CAN go red. This workstream found four separate cannot-fail tests inside the SDK suite,
# so the lane's own greenness was not evidence of anything.
#
# Model: check-wasm-bundle-size-selftest.sh. Copies the SDK tree to a scratch dir OUTSIDE
# the repo (a fresh CI checkout has no writable scratch inside it, and nothing this script
# does should ever land in the working tree),
# deletes the schema-envelope version guard there (the exact mutation that once left the
# WHOLE suite green, now killed by tests/t2_batch_envelope.test.ts), runs the suite in the
# copy, and FAILS if the suite comes back green. The real tree is never modified and no git
# command is run.
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
pristine_json="${SCRATCH}/pristine-$$.json"
pristine_err="${SCRATCH}/pristine-$$.err"
schema_json="${SCRATCH}/schema-red-$$.json"
schema_err="${SCRATCH}/schema-red-$$.err"
mkdir -p "$work"
cleanup() {
  rm -rf "$work" "${SCRATCH}/poseidon"
  rm -f "$pristine_json" "$pristine_err" "$schema_json" "$schema_err"
  if [[ "$owns_scratch" -eq 1 ]]; then rm -rf "$SCRATCH"; fi
}
trap cleanup EXIT

# Copy every package file that affects `npm pack`. node_modules becomes real directories holding
# links, so a file the copy's suite creates there stays in the copy.
cp -a "${SDK}/src" "${SDK}/tests" "${SDK}/tsconfig.json" "${SDK}/package.json" \
  "${SDK}/README.md" "${SDK}/LICENSE" "${SDK}/pnpm-lock.yaml" "${SDK}/.gitignore" "$work/"
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

echo "check-sdk-suite-selftest: verifying the unmutated scratch suite"
( cd "$work" && NO_COLOR=1 ./node_modules/.bin/vitest run \
    --config tests/vitest.config.ts --reporter=json >"$pristine_json" 2>"$pristine_err" )
pristine_exit=$?
if [[ "$pristine_exit" -ne 0 ]]; then
  echo "check-sdk-suite-selftest: unmutated scratch suite failed (exit ${pristine_exit})" >&2
  tail -n 20 -- "$pristine_err" "$pristine_json" >&2
  exit 1
fi
json_line "$pristine_json" >/dev/null || {
  echo "check-sdk-suite-selftest: unmutated scratch emitted no JSON report" >&2
  exit 1
}
node -e '
const fs = require("fs");
const line = fs.readFileSync(process.argv[1], "utf8")
  .split("\n").find((candidate) => candidate.trimStart().startsWith("{"));
if (!line) process.exit(3);
const report = JSON.parse(line);
const expected = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const files = report.testResults ?? [];
const skipped = report.numPendingTests + (report.numTodoTests ?? 0);
const skippedFiles = files.filter((file) => {
  const tests = file.assertionResults ?? [];
  return tests.length > 0 && tests.every((test) => ["pending", "skipped", "todo"].includes(test.status));
}).length;
if (files.length !== expected.testFiles || skippedFiles !== expected.skippedFiles ||
    report.numPassedTests !== expected.passed || skipped !== expected.skipped) {
  console.error(`unmutated scratch counts: passed=${report.numPassedTests} skipped=${skipped} files=${files.length} skipped_files=${skippedFiles}`);
  process.exit(1);
}
console.log(`  unmutated scratch: ${report.numPassedTests} passed / ${skipped} skipped across ${files.length} files`);
' "$pristine_json" "$work/tests/EXPECTED_COUNTS.json" || exit 1

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
node -e '
const fs = require("fs");
const line = fs.readFileSync(process.argv[1], "utf8")
  .split("\n").find((candidate) => candidate.trimStart().startsWith("{"));
if (!line) { console.error("schema mutation emitted no JSON report"); process.exit(1); }
const report = JSON.parse(line);
const expected = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const wantedFailures = new Set([
  "refuses an unknown schema envelope version instead of eating two payload bytes",
  "refuses a previous-schema prefix before WASM extraction",
]);
const files = report.testResults ?? [];
const assertions = files.flatMap((file) => file.assertionResults ?? []);
const failures = assertions.filter((test) => test.status === "failed");
const failureTitles = new Set(failures.map((test) => test.title));
const skipped = report.numPendingTests + (report.numTodoTests ?? 0);
if (failures.length !== 2 || report.numFailedTests !== 2 || failureTitles.size !== 2 ||
    [...wantedFailures].some((title) => !failureTitles.has(title)) ||
    files.length !== expected.testFiles || skipped !== expected.skipped ||
    report.numPassedTests + report.numFailedTests !== expected.passed) {
  console.error(`schema mutation mismatch: failures=${failures.map((test) => test.title).join(" | ")} passed=${report.numPassedTests} skipped=${skipped} files=${files.length}`);
  process.exit(1);
}
' "$schema_json" "$work/tests/EXPECTED_COUNTS.json" || {
  tail -n 20 -- "$schema_err" "$schema_json" >&2
  exit 1
}
echo "check-sdk-suite-selftest: schema guard deletion failed exactly both version tests."
