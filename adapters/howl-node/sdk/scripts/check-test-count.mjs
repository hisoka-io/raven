// Run the suite and hold its counts to tests/EXPECTED_COUNTS.json, exactly: a suite that skips
// (no node binary, a describe left as .skip, a file no longer collected) is a failure here, not
// a green run with less in it. The counts are those of CI: HOWL_NODE_BIN set, HOWL_REPO unset.
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const sdk = new URL("..", import.meta.url).pathname;
const expected = JSON.parse(readFileSync(join(sdk, "tests/EXPECTED_COUNTS.json"), "utf8"));
const bin = process.env.HOWL_NODE_BIN ?? "";
if (bin === "" || !existsSync(bin)) {
  console.error("check-test-count: HOWL_NODE_BIN must name a built node binary; the live suite would skip");
  process.exit(2);
}
if ((process.env.HOWL_REPO ?? "") !== "") {
  console.error("check-test-count: unset HOWL_REPO; the pinned counts are those of a run without a Howl checkout");
  process.exit(2);
}

const scratch = mkdtempSync(join(tmpdir(), "howl-sdk-count-"));
const report = join(scratch, "report.json");
const run = spawnSync(
  join(sdk, "node_modules/.bin/vitest"),
  ["run", "--config", "tests/vitest.config.ts", "--reporter=default", "--reporter=json", `--outputFile.json=${report}`],
  { cwd: sdk, stdio: "inherit", env: process.env },
);
if (run.status !== 0) {
  rmSync(scratch, { recursive: true, force: true });
  console.error(`check-test-count: the suite failed (exit ${run.status})`);
  process.exit(run.status ?? 1);
}
const r = JSON.parse(readFileSync(report, "utf8"));
rmSync(scratch, { recursive: true, force: true });
const files = r.testResults ?? [];
const skippedStatus = (a) => a.status === "pending" || a.status === "skipped" || a.status === "todo";
const got = {
  testFiles: files.length,
  passed: r.numPassedTests,
  skipped: r.numPendingTests + (r.numTodoTests ?? 0),
  skippedFiles: files.filter((f) => f.assertionResults.length > 0 && f.assertionResults.every(skippedStatus)).length,
};
let failed = false;
for (const key of ["testFiles", "passed", "skipped", "skippedFiles"]) {
  const ok = got[key] === expected[key];
  (ok ? console.log : console.error)(`  ${ok ? "ok  " : "FAIL"}  ${key}: got ${got[key]}, expected ${expected[key]}`);
  failed ||= !ok;
}
if (failed) {
  console.error("check-test-count: counts drifted; a skip, a lost file or a deliberate change bumped with review");
  process.exit(1);
}
console.log(`check-test-count: ${got.passed} passed / ${got.skipped} skipped in ${got.testFiles} files`);
