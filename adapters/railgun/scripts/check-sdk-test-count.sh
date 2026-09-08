#!/usr/bin/env bash
# The sdk-tests lane asserts nothing about how many tests ran: a file that stops being
# collected — a rename, a bad glob in tests/vitest.config.ts, a describe left as
# describe.skip — passes as a green lane with less running. This gate pins the counts to
# tests/EXPECTED_COUNTS.json: `passed` is a floor, `skipped`/`testFiles`/`skippedFiles`
# are exact (an at-least/at-most pair alone is satisfied by adding a trivial test while
# a real one disappears; the exact file count is what catches that).
set -uo pipefail

ADAPTER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK="${ADAPTER_ROOT}/sdk"
EXPECTED="${SDK}/tests/EXPECTED_COUNTS.json"

if [[ ! -f "$EXPECTED" ]]; then
  echo "check-sdk-test-count: missing ${EXPECTED}" >&2
  exit 3
fi

out="$(mktemp)"
trap 'rm -f "$out"' EXIT

( cd "$SDK" && ./node_modules/.bin/vitest run --config tests/vitest.config.ts --reporter=json >"$out" 2>/dev/null )
suite_exit=$?
if [[ "$suite_exit" -ne 0 ]]; then
  echo "check-sdk-test-count: the suite itself failed (exit ${suite_exit}); fix that first" >&2
  exit "$suite_exit"
fi

node -e '
const fs = require("fs");
const expected = JSON.parse(fs.readFileSync(process.argv[1], "utf-8"));
const raw = fs.readFileSync(process.argv[2], "utf-8");
// vitest may prepend non-JSON lines; the report is the first line starting with {.
const line = raw.split("\n").find((l) => l.trimStart().startsWith("{"));
if (!line) { console.error("check-sdk-test-count: no JSON report found in vitest output"); process.exit(3); }
const r = JSON.parse(line);
// numTotalTestSuites counts describe blocks, not files; testResults is one entry per FILE.
const files = r.testResults ?? [];
const isSkipped = (a) => a.status === "pending" || a.status === "skipped" || a.status === "todo";
const got = {
  testFiles: files.length,
  skippedFiles: files.filter((f) => f.assertionResults.length > 0 && f.assertionResults.every(isSkipped)).length,
  passed: r.numPassedTests,
  skipped: r.numPendingTests + (r.numTodoTests ?? 0),
};
// Refuse a vacuous run outright: a glob matching nothing is the failure mode this exists for.
if (!got.testFiles || !got.passed) {
  console.error(`check-sdk-test-count: implausible run (files=${got.testFiles}, passed=${got.passed}) — collection is broken`);
  process.exit(1);
}
let failed = false;
const check = (name, ok, detail) => {
  if (ok) { console.log(`  ok    ${name}: ${detail}`); }
  else { console.error(`  FAIL  ${name}: ${detail}`); failed = true; }
};
check("test files (exact)", got.testFiles === expected.testFiles, `got ${got.testFiles}, expected ${expected.testFiles}`);
check("skipped files (exact)", got.skippedFiles === expected.skippedFiles, `got ${got.skippedFiles}, expected ${expected.skippedFiles}`);
check("passed (floor)", got.passed >= expected.passed, `got ${got.passed}, floor ${expected.passed}`);
check("skipped tests (exact)", got.skipped === expected.skipped, `got ${got.skipped}, expected ${expected.skipped}`);
if (failed) {
  console.error("check-sdk-test-count: counts drifted — a test file stopped being collected, a describe went .skip, or EXPECTED_COUNTS.json needs a deliberate bump WITH review.");
  process.exit(1);
}
console.log(`check-sdk-test-count: ${got.passed} passed / ${got.skipped} skipped across ${got.testFiles} files — matches EXPECTED_COUNTS.json.`);
' "$EXPECTED" "$out"
