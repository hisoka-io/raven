// The Howl client in headless Chromium against a local chain and node: a page bundled by webpack
// with the -bundler wasm, and an unpacked Manifest V3 extension whose service worker runs the -web
// wasm through initSync. Both pages allow only script-src 'self' 'wasm-unsafe-eval', and both reach
// the node cross-origin. Each must give the result the Node build gives.
//
// HOWL_SMOKE_PLANT names one fault for the red proof: `csp` drops 'wasm-unsafe-eval', `cors` puts a
// proxy that strips the CORS headers in front of the node, `nodewasm` bundles the Node build.
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, request, type Server } from "node:http";
import { tmpdir } from "node:os";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { build } from "esbuild";
import { chromium } from "playwright";
import webpack from "webpack";
import * as nodeWasm from "@hisoka-io/howl-client-wasm";
import { LocalChain } from "../tests/helpers/chain.js";
import { fixture, hex, walletTags } from "../tests/helpers/fixture.js";
import { smoke } from "./scenario.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const plant = process.env.HOWL_SMOKE_PLANT ?? "";
const bin = process.env.HOWL_NODE_BIN ?? "";
const CSP = plant === "csp" ? "script-src 'self'; object-src 'self'" : "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'";
const READY_MS = 30_000;

const require = (await import("node:module")).createRequire(import.meta.url);
const webWasm = join(dirname(require.resolve("@hisoka-io/howl-client-wasm-web/package.json")), "howl_client_wasm_bg.wasm");

function listen(server: Server): Promise<string> {
  return new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () => {
      const a = server.address();
      resolve(`http://127.0.0.1:${typeof a === "object" && a !== null ? a.port : 0}`);
    }),
  );
}

/** Serves `dir` with the page's content security policy. */
function staticServer(dir: string): Server {
  const types: Record<string, string> = { ".html": "text/html", ".js": "text/javascript", ".wasm": "application/wasm" };
  return createServer((req, res) => {
    const path = new URL(req.url ?? "/", "http://x").pathname;
    const file = path === "/" ? "index.html" : path.slice(1);
    try {
      const body = readFileSync(join(dir, file));
      res.writeHead(200, { "content-type": types[extname(file)] ?? "application/octet-stream", "content-security-policy": CSP });
      res.end(body);
    } catch {
      res.writeHead(404).end();
    }
  });
}

/** Forwards to `target` and drops every access-control-* header of its answers. */
function corsStrippingProxy(target: string): Server {
  const to = new URL(target);
  return createServer((req, res) => {
    const out = request(
      { host: to.hostname, port: to.port, path: req.url, method: req.method, headers: { ...req.headers, host: to.host } },
      (answer) => {
        const headers = Object.fromEntries(Object.entries(answer.headers).filter(([k]) => !k.startsWith("access-control-")));
        res.writeHead(answer.statusCode ?? 502, headers);
        answer.pipe(res);
      },
    );
    out.on("error", () => res.writeHead(502).end());
    req.pipe(out);
  });
}

async function bundlePage(out: string): Promise<void> {
  mkdirSync(out, { recursive: true });
  cpSync(join(here, "page/index.html"), join(out, "index.html"));
  const compiler = webpack({
    mode: "production",
    target: "web",
    entry: join(here, "page/page.mjs"),
    output: { path: out, filename: "page.js" },
    experiments: { asyncWebAssembly: true },
    performance: { hints: false },
    resolve: plant === "nodewasm" ? { alias: { "@hisoka-io/howl-client-wasm-bundler": "@hisoka-io/howl-client-wasm" } } : {},
  });
  await new Promise<void>((resolve, reject) =>
    compiler.run((error, stats) => {
      if (error !== null && error !== undefined) return reject(error);
      if (stats?.hasErrors()) return reject(new Error(`webpack: ${stats.toString({ all: false, errors: true })}`));
      compiler.close(() => resolve());
    }),
  );
}

async function buildExtension(out: string): Promise<void> {
  mkdirSync(out, { recursive: true });
  await build({ entryPoints: [join(here, "extension/sw.mjs")], bundle: true, format: "esm", platform: "browser", outfile: join(out, "sw.js"), logLevel: "error" });
  cpSync(webWasm, join(out, "howl_client_wasm_bg.wasm"));
  const manifest = {
    manifest_version: 3,
    name: "Howl client smoke",
    version: "0.0.1",
    background: { service_worker: "sw.js", type: "module" },
    content_security_policy: { extension_pages: CSP },
  };
  writeFileSync(join(out, "manifest.json"), JSON.stringify(manifest, null, 2));
}

type Result = Awaited<ReturnType<typeof smoke>>;
const withoutGlobals = (r: Result) => ({ ...r, globals: undefined });

async function main(): Promise<number> {
  if (bin === "") throw new Error("HOWL_NODE_BIN must name a built howl-node binary");
  const scratch = mkdtempSync(join(tmpdir(), "howl-browser-smoke-"));
  const servers: Server[] = [];
  const chain = await LocalChain.start();
  let context: Awaited<ReturnType<typeof chromium.launchPersistentContext>> | undefined;
  let failed = 0;
  try {
    await chain.mineFixture(0, fixture.blocks.length);
    await chain.startNode(bin, { paramSet: 1 });
    await chain.caughtUp();
    const proxy = corsStrippingProxy(chain.nodeUrl);
    servers.push(proxy);
    const proxied = await listen(proxy);
    const wallet = fixture.wallets[0]!;
    const input = {
      nodeUrl: plant === "cors" ? proxied : chain.nodeUrl,
      tags: walletTags(wallet).map((t) => "0x" + hex(t)),
      owned: wallet.owned_leaves.slice(0, 4).map((leafIndex) => ({ leafIndex, commitment: fixture.leaves[leafIndex]!.commitment })),
    };

    const reference = await smoke(nodeWasm, { ...input, nodeUrl: chain.nodeUrl });
    const owned = input.owned.map((o) => o.leafIndex);
    if (
      reference.leafCount !== fixture.leaf_count ||
      !owned.every((p) => reference.positions.includes(p)) ||
      reference.confirmed.some((c) => c !== "confirmed") ||
      BigInt("0x" + reference.witness.root) !== BigInt("0x" + reference.root) ||
      reference.resumed.rowsAdded !== 0
    ) {
      console.error(`SMOKE FAIL node: the reference run is wrong: ${JSON.stringify(reference)}`);
      return 1;
    }
    console.log(`node     ok: ${reference.leafCount} leaves, ${reference.positions.length} matches, ${owned.length} notes confirmed`);

    const pageDir = join(scratch, "page");
    const extDir = join(scratch, "extension");
    await bundlePage(pageDir);
    await buildExtension(extDir);
    const site = staticServer(pageDir);
    servers.push(site);
    const pageUrl = await listen(site);

    context = await chromium.launchPersistentContext(join(scratch, "profile"), {
      channel: "chromium",
      headless: true,
      args: [`--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`],
    });

    const check = (target: string, got: Result | undefined, errors: string[]): void => {
      const globalsClean = got !== undefined && got.globals.Buffer === "undefined" && got.globals.process === "undefined";
      if (got !== undefined && globalsClean && isDeepStrictEqual(withoutGlobals(got), withoutGlobals(reference))) {
        console.log(`${target.padEnd(8)} ok: the Node result, with no Buffer or process global`);
        return;
      }
      failed += 1;
      const why = got === undefined ? errors.join(" | ") || "no result" : `result differs: ${JSON.stringify(got)}`;
      console.error(`SMOKE FAIL ${target}: ${why}`);
    };

    const page = await context.newPage();
    const pageErrors: string[] = [];
    page.on("pageerror", (e) => pageErrors.push(`pageerror: ${e.message}`));
    page.on("console", (m) => m.type() === "error" && pageErrors.push(`console: ${m.text()}`));
    let pageResult: Result | undefined;
    try {
      await page.goto(pageUrl);
      await page.waitForFunction(() => typeof (globalThis as { howlSmoke?: unknown }).howlSmoke === "function", null, { timeout: READY_MS });
      pageResult = (await page.evaluate((i) => (globalThis as unknown as { howlSmoke: (x: unknown) => Promise<unknown> }).howlSmoke(i), input)) as Result;
    } catch (e) {
      pageErrors.push(String(e instanceof Error ? e.message.split("\n")[0] : e));
    }
    check("page", pageResult, pageErrors);

    const swErrors: string[] = [];
    let swResult: Result | undefined;
    try {
      const sw = context.serviceWorkers()[0] ?? (await context.waitForEvent("serviceworker", { timeout: READY_MS }));
      swResult = (await sw.evaluate((i) => (globalThis as unknown as { howlSmoke: (x: unknown) => Promise<unknown> }).howlSmoke(i), input)) as Result;
    } catch (e) {
      swErrors.push(String(e instanceof Error ? e.message.split("\n")[0] : e));
    }
    check("worker", swResult, swErrors);
  } finally {
    await context?.close();
    for (const s of servers) s.close();
    await chain.stop();
    rmSync(scratch, { recursive: true, force: true });
  }
  return failed === 0 ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error(`SMOKE FAIL setup: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  },
);
