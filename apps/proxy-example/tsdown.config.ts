import { defineConfig } from 'tsdown';

export default defineConfig({
  // Match the paths `start` and wrangler.toml name. Without this tsdown emits
  // `.mjs`, and both production entrypoints fail after a clean build.
  outExtensions: () => ({ js: '.js', dts: '.d.ts' }),
  entry: {
    node: 'src/node.ts',
    worker: 'src/worker.ts',
  },
  format: ['esm'],
  dts: true,
  clean: true,
  sourcemap: false,
});
