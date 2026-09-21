import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

// The suite imports ../src directly and so can never see the manifest a consumer reads.
// check-sdk-pack.sh proves the packed tarball end to end but needs a build and two offline
// installs; these are the manifest invariants that must hold on every push without one.

const sdkRoot = resolve(__dirname, "..");
const manifest = JSON.parse(readFileSync(resolve(sdkRoot, "package.json"), "utf8")) as {
  readonly type?: string;
  readonly main?: string;
  readonly module?: string;
  readonly types?: string;
  readonly files?: readonly string[];
  readonly scripts?: Readonly<Record<string, string>>;
  readonly exports?: Readonly<Record<string, unknown>>;
};

const shippedBy = (allowlist: readonly string[], target: string): boolean => {
  const path = target.replace(/^\.\//, "");
  return path === "package.json" || allowlist.some((entry) => path.startsWith(`${entry}/`));
};

describe("published package manifest", () => {
  it("resolves its entry points to emitted JavaScript, never to TypeScript source", () => {
    for (const [field, value] of [
      ["main", manifest.main],
      ["module", manifest.module],
      ["types", manifest.types],
    ] as const) {
      expect(value, `${field} is unset`).toBeTypeOf("string");
      expect(value, `${field} points into src/`).not.toMatch(/(^|\/)src\//);
      expect(value, `${field} is not under dist/`).toMatch(/^\.\/dist\//);
    }
    expect(manifest.main).toMatch(/\.js$/);
    expect(manifest.module).toMatch(/\.js$/);
    expect(manifest.types).toMatch(/\.d\.ts$/);
  });

  it("offers both module systems a typed entry under conditional exports", () => {
    const root = manifest.exports?.["."] as
      | Record<"import" | "require", Record<"types" | "default", string>>
      | undefined;
    expect(root, "exports['.'] is missing").toBeDefined();
    for (const condition of ["import", "require"] as const) {
      const branch = root?.[condition];
      expect(branch, `exports['.'].${condition} is missing`).toBeDefined();
      expect(branch?.types, `${condition} types`).toMatch(/^\.\/dist\/.*\.d\.ts$/);
      expect(branch?.default, `${condition} default`).toMatch(/^\.\/dist\/.*\.js$/);
    }
    // The two emits must be distinct trees: one entry serving both conditions means a
    // consumer of the other module system gets a file its loader cannot read.
    expect(root?.import.default).not.toBe(root?.require.default);
    expect(manifest.exports?.["./package.json"]).toBe("./package.json");
  });

  it("ships an allowlist that covers every entry point and excludes the test tier", () => {
    const files = manifest.files;
    expect(files, "no files allowlist: npm pack ships the whole directory").toBeDefined();
    expect(files).toContain("dist");
    expect(files).not.toContain("tests");
    for (const entry of files ?? []) {
      expect(entry, "an allowlist entry escapes the package").not.toMatch(/^\.\.?\//);
    }
    const targets = [manifest.main, manifest.module, manifest.types].filter(
      (target): target is string => typeof target === "string",
    );
    for (const target of targets) {
      expect(shippedBy(files ?? [], target), `${target} is not inside the allowlist`).toBe(true);
    }
  });

  it("names both build configs and keeps the suite independent of the build", () => {
    expect(manifest.scripts?.build, "no build script").toBeTypeOf("string");
    for (const config of ["tsconfig.build.cjs.json", "tsconfig.build.esm.json"]) {
      expect(manifest.scripts?.build).toContain(config);
    }
    // A suite that needs `build` first stops being the thing that runs on every push.
    for (const script of ["test", "typecheck"] as const) {
      expect(manifest.scripts?.[script], `${script} script`).toBeTypeOf("string");
      expect(manifest.scripts?.[script]).not.toContain("build");
    }
  });
});
