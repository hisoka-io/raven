import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    testTimeout: 120_000,
    hookTimeout: 180_000,
    environment: "node",
    // the live suites share one local chain and node
    fileParallelism: false,
  },
});
