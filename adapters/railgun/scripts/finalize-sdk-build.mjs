#!/usr/bin/env node
// Completes the dual-format emit `tsc` cannot do on its own.
//
// Two jobs:
//   1. Stamp a `type` marker beside each output. The package root is `"type": "module"`,
//      so without `dist/cjs/package.json` node reads the CommonJS emit as ESM and every
//      `require()` of it throws, and TypeScript resolves the CJS `.d.ts` in the wrong
//      module mode for a `NodeNext` consumer.
//   2. Give every relative specifier in the ESM emit a `.js` extension. The sources are
//      written extensionless, `tsc` copies specifiers through verbatim, and node's ESM
//      resolver refuses an extensionless relative specifier.
//
// Fails closed: a specifier that does not resolve to an emitted file aborts the build
// rather than shipping a module that throws at the consumer's first import.

import { readdirSync, readFileSync, writeFileSync, existsSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

// The package being built is the working directory, never this script's sibling: the
// pack gate's red-proof builds a COPY, and a path anchored here would emit into the
// real tree instead.
const PACKAGE_ROOT = resolve(process.cwd());
const CJS_DIR = join(PACKAGE_ROOT, "dist", "cjs");
const ESM_DIR = join(PACKAGE_ROOT, "dist", "esm");

const fail = (message) => {
  console.error(`finalize-sdk-build: ${message}`);
  process.exit(1);
};

const walk = (dir) => {
  const found = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...walk(full));
    else found.push(full);
  }
  return found;
};

for (const dir of [CJS_DIR, ESM_DIR]) {
  if (!existsSync(dir) || !statSync(dir).isDirectory()) {
    fail(`${dir} is missing - run the tsc emit steps first`);
  }
}

writeFileSync(join(CJS_DIR, "package.json"), '{\n  "type": "commonjs"\n}\n');
writeFileSync(join(ESM_DIR, "package.json"), '{\n  "type": "module"\n}\n');

// `from "..."`, `import("...")`, and bare `import "..."` side-effect forms.
const SPECIFIER = /(\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)(["'])(\.[^"']*)\2/g;

let rewritten = 0;
for (const file of walk(ESM_DIR)) {
  if (!file.endsWith(".js") && !file.endsWith(".d.ts")) continue;
  const before = readFileSync(file, "utf8");
  const after = before.replace(SPECIFIER, (whole, lead, quote, specifier) => {
    if (/\.(js|mjs|cjs|json)$/.test(specifier)) return whole;
    const target = resolve(dirname(file), specifier);
    const emitted = existsSync(`${target}.js`)
      ? `${specifier}.js`
      : existsSync(join(target, "index.js"))
        ? `${specifier}/index.js`
        : null;
    if (emitted === null) {
      fail(`${file}: relative specifier ${specifier} resolves to no emitted module`);
    }
    rewritten += 1;
    return `${lead}${quote}${emitted}${quote}`;
  });
  if (after !== before) writeFileSync(file, after);
}

if (rewritten === 0) {
  fail("rewrote no ESM specifier - the emit shape changed and this step is now blind");
}

console.log(
  `finalize-sdk-build: stamped dist/cjs + dist/esm module types, extended ${rewritten} ESM specifiers.`,
);
