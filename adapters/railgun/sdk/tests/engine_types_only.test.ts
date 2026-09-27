import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";

// Engine is an optional peer: a consumer's tree may hold no engine at all, or one the SDK must not
// load. So src/ may name engine only in spellings the compiler erases.

const ENGINE = "@railgun-community/engine";
const srcRoot = resolve(__dirname, "..", "src");

const namesEngine = (node: ts.Node | undefined): boolean =>
  node !== undefined &&
  ts.isStringLiteralLike(node) &&
  (node.text === ENGINE || node.text.startsWith(`${ENGINE}/`));

interface EngineReferences {
  readonly typeOnly: number;
  readonly value: readonly string[];
}

function engineReferences(fileName: string, source: string): EngineReferences {
  const file = ts.createSourceFile(
    fileName,
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  const value: string[] = [];
  let typeOnly = 0;
  const flag = (node: ts.Node, spelling: string): void => {
    const { line } = file.getLineAndCharacterOfPosition(node.getStart(file));
    value.push(`${fileName}:${line + 1} ${spelling}`);
  };
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) && namesEngine(node.moduleSpecifier)) {
      // Only a declaration-level `import type` is erased under every module setting; an import of
      // inline `type` specifiers survives verbatimModuleSyntax as a side-effect import.
      if (node.importClause?.isTypeOnly === true) typeOnly += 1;
      else flag(node, "import without `import type`");
    } else if (ts.isExportDeclaration(node) && namesEngine(node.moduleSpecifier)) {
      if (node.isTypeOnly) typeOnly += 1;
      else flag(node, "re-export without `export type`");
    } else if (
      ts.isImportEqualsDeclaration(node) &&
      ts.isExternalModuleReference(node.moduleReference) &&
      namesEngine(node.moduleReference.expression)
    ) {
      if (node.isTypeOnly) typeOnly += 1;
      else flag(node, "import = require");
    } else if (
      ts.isCallExpression(node) &&
      (node.expression.kind === ts.SyntaxKind.ImportKeyword ||
        (ts.isIdentifier(node.expression) && node.expression.text === "require")) &&
      namesEngine(node.arguments[0])
    ) {
      flag(node, node.expression.kind === ts.SyntaxKind.ImportKeyword ? "import()" : "require()");
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return { typeOnly, value };
}

describe("engine stays a types-only peer", () => {
  it("names engine under src/ only in spellings the compiler erases", () => {
    const files = readdirSync(srcRoot, { recursive: true, encoding: "utf8" }).filter(
      (name) => name.endsWith(".ts") && !name.endsWith(".d.ts"),
    );
    // Guards the scan itself: a moved src/ must fail here, not pass over nothing.
    expect(files.length, "source files scanned").toBeGreaterThanOrEqual(10);
    let typeOnly = 0;
    const value: string[] = [];
    for (const name of files) {
      const found = engineReferences(`src/${name}`, readFileSync(join(srcRoot, name), "utf8"));
      typeOnly += found.typeOnly;
      value.push(...found.value);
    }
    expect(value, "src/ loads engine as a value").toEqual([]);
    expect(typeOnly, "type-only engine imports found").toBeGreaterThan(0);
  });

  it("flags every spelling that leaves engine in the emitted JavaScript", () => {
    const planted: ReadonlyArray<readonly [string, string]> = [
      [`import { POI } from "${ENGINE}";`, "import without `import type`"],
      [`import { type POI } from "${ENGINE}";`, "import without `import type`"],
      [`import * as engine from "${ENGINE}";`, "import without `import type`"],
      [`import "${ENGINE}";`, "import without `import type`"],
      [`import { POI } from "${ENGINE}/dist/poi/poi";`, "import without `import type`"],
      [`export { POI } from "${ENGINE}";`, "re-export without `export type`"],
      [`export * from "${ENGINE}";`, "re-export without `export type`"],
      [`import engine = require("${ENGINE}");`, "import = require"],
      [`const engine = require("${ENGINE}");`, "require()"],
      [`export async function load() { return import("${ENGINE}"); }`, "import()"],
    ];
    for (const [source, spelling] of planted) {
      expect(engineReferences("planted.ts", source).value, source).toEqual([
        `planted.ts:1 ${spelling}`,
      ]);
    }
  });

  it("passes the spellings the compiler erases and leaves other packages alone", () => {
    const erased = [
      `import type { POI } from "${ENGINE}";`,
      `import type * as engine from "${ENGINE}";`,
      `export type { POINodeInterface } from "${ENGINE}";`,
      `import type engine = require("${ENGINE}");`,
      `type Engine = typeof import("${ENGINE}");`,
    ];
    for (const source of erased) {
      expect(engineReferences("erased.ts", source).value, source).toEqual([]);
    }
    const other = `import { poseidon } from "@railgun-community/poseidon-hash-wasm";`;
    expect(engineReferences("other.ts", other)).toEqual({ typeOnly: 0, value: [] });
  });
});
