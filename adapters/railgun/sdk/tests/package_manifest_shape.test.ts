import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { prerelease, satisfies, valid, validRange } from "semver";
import { describe, expect, it } from "vitest";

// The suite imports ../src directly and so can never see the manifest a consumer reads.
// check-sdk-pack.sh proves the packed tarball end to end but needs a build and two offline
// installs; these are the manifest invariants that must hold on every push without one.

const sdkRoot = resolve(__dirname, "..");
type DependencyMap = Readonly<Record<string, string>>;
const manifest = JSON.parse(readFileSync(resolve(sdkRoot, "package.json"), "utf8")) as {
  readonly name?: string;
  readonly version?: string;
  readonly publishConfig?: Readonly<Record<string, string>>;
  readonly dependencies?: DependencyMap;
  readonly optionalDependencies?: DependencyMap;
  readonly peerDependencies?: DependencyMap;
  readonly peerDependenciesMeta?: Readonly<Record<string, Readonly<{ optional?: boolean }>>>;
  readonly devDependencies?: DependencyMap;
  readonly bundleDependencies?: readonly string[] | boolean;
  readonly bundledDependencies?: readonly string[] | boolean;
  readonly type?: string;
  readonly main?: string;
  readonly module?: string;
  readonly types?: string;
  readonly files?: readonly string[];
  readonly scripts?: Readonly<Record<string, string>>;
  readonly exports?: Readonly<Record<string, unknown>>;
  readonly engines?: Readonly<Record<string, string>>;
};

const ENGINE = "@railgun-community/engine";
// What @railgun-community/wallet@10.10.0-rc.1, the terminal wallet's pin, depends on exactly.
const WALLET_ENGINE_PIN = "9.7.0-rc.0";
// Released wallets depend on `^9.6.0` (10.9.x), `^9.7.0` (11.0.1) and `^9.8.0` (11.1.0).
const WALLET_ENGINE_LINE = ["9.6.0", "9.7.0", "9.8.0"];

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
    // No export reaches the TypeScript source, so shipping it only adds its bytes to the tarball.
    expect(files).not.toContain("src");
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

  it("declares the Node floor its README states", () => {
    const readme = readFileSync(resolve(sdkRoot, "README.md"), "utf8");
    expect(readme).toContain("Node 20 or newer");
    expect(manifest.engines?.node).toBe(">=20");
  });

  it("installs every runtime dependency from the registry, never from a repository path", () => {
    for (const field of ["dependencies", "optionalDependencies", "peerDependencies"] as const) {
      for (const [name, spec] of Object.entries(manifest[field] ?? {})) {
        const message = `${field}.${name} is ${spec}, not a registry range`;
        expect(validRange(spec), message).not.toBeNull();
      }
    }
  });

  // Engine's POI seam is a static on a class; a second engine copy beside the wallet's own takes
  // an interface installed on it and never reads it. An optional peer installs nothing and reads
  // the copy the wallet brings.
  it("can never install a second engine, and its peer range admits the wallets' engines", () => {
    for (const field of ["dependencies", "optionalDependencies"] as const) {
      expect(manifest[field]?.[ENGINE], `engine in ${field}`).toBeUndefined();
    }
    for (const bundled of [manifest.bundleDependencies, manifest.bundledDependencies]) {
      expect(bundled === true || (Array.isArray(bundled) && bundled.includes(ENGINE))).toBe(false);
    }
    const peer = manifest.peerDependencies?.[ENGINE] ?? "";
    expect(validRange(peer), `engine peer range ${peer}`).not.toBeNull();
    // A required peer is one npm installs itself, at the newest version the range admits, beside
    // the wallet's exact pin.
    expect(manifest.peerDependenciesMeta?.[ENGINE]?.optional, "engine is a required peer").toBe(
      true,
    );
    // A prerelease satisfies only a range naming its own major.minor.patch: `^9.6.0` excludes it.
    for (const version of [WALLET_ENGINE_PIN, ...WALLET_ENGINE_LINE]) {
      expect(satisfies(version, peer), `${peer} admits ${version}`).toBe(true);
    }
    const typedAgainst = manifest.devDependencies?.[ENGINE] ?? "";
    expect(valid(typedAgainst), "the suite typechecks against one exact engine").not.toBeNull();
    expect(satisfies(typedAgainst, peer), `${peer} admits ${typedAgainst}`).toBe(true);
  });

  it("publishes publicly under the project's scope, off the latest tag while a prerelease", () => {
    expect(manifest.name).toMatch(/^@hisoka-io\//);
    expect(manifest.publishConfig?.access, "a scoped package publishes restricted by default").toBe(
      "public",
    );
    expect(valid(manifest.version ?? ""), "version is not semver").not.toBeNull();
    if (prerelease(manifest.version ?? "") !== null) {
      expect(manifest.publishConfig?.tag, "npm refuses a prerelease with no dist-tag").toBeTypeOf(
        "string",
      );
      expect(manifest.publishConfig?.tag).not.toBe("latest");
    }
  });
});
