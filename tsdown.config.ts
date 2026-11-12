import { defineConfig } from "tsdown";

export default defineConfig({
  dts: true,
  entry: ["src/index.ts", "src/testing.ts"],
  // The package is an ES module, so its files are .js.
  fixedExtension: false,
  format: "esm",
  platform: "node",
  sourcemap: true,
});
