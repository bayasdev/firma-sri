import type { KnipConfig } from "knip";

const config: KnipConfig = {
  entry: ["lint/*.ts", "tests/*.test.ts"],
  // An independent verifier the tests run when the machine has it.
  ignoreBinaries: ["xmlsec1"],
  project: ["**/*.ts"],
};

export default config;
