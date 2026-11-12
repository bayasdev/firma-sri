import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // A property signs dozens of documents, each with a certificate built
    // for it, which takes a slow machine longer than the five-second default.
    testTimeout: 60_000,
  },
});
