// The tarball npm would publish holds dist/, the README, the LICENSE (the repository's, byte for
// byte), the changelog and package.json, and nothing else: no tests, sources, lockfile or scripts.
// Run after `pnpm build`; packs with scripts off so the check reads the dist as built.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const sdk = new URL("..", import.meta.url).pathname;
const ALWAYS = ["CHANGELOG.md", "LICENSE", "README.md", "package.json"];
const DIST = /^dist\/[a-z0-9-]+\.(js|d\.ts)$/;

const run = spawnSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: sdk, encoding: "utf8" });
if (run.status !== 0) {
  console.error(`check-pack: npm pack failed (exit ${run.status})\n${run.stderr}`);
  process.exit(2);
}
const files = JSON.parse(run.stdout)[0].files.map((f) => f.path).sort();
let failed = false;
const fail = (why) => {
  console.error(`  FAIL  ${why}`);
  failed = true;
};
for (const f of files) if (!ALWAYS.includes(f) && !DIST.test(f)) fail(`packs ${f}`);
for (const f of [...ALWAYS, "dist/index.js", "dist/index.d.ts"]) if (!files.includes(f)) fail(`does not pack ${f}`);
const license = readFileSync(join(sdk, "LICENSE"));
if (!license.equals(readFileSync(join(sdk, "../../../LICENSE")))) fail("LICENSE is not the repository's LICENSE");
if (failed) {
  console.error("check-pack: the tarball is not the published package");
  process.exit(1);
}
console.log(`check-pack: ${files.length} files: ${ALWAYS.join(", ")} and ${files.length - ALWAYS.length} under dist/`);
