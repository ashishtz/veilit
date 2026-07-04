import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  // Types are emitted separately via `tsc -p tsconfig.build.json` so declaration
  // generation is not coupled to tsup's bundled TypeScript version.
  dts: false,
  clean: true,
  minify: false,
  treeshake: true,
  sourcemap: true,
  target: "es2022",
  outDir: "dist",
});
