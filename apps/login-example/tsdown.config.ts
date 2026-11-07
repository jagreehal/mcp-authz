import { defineConfig } from 'tsdown';

export default defineConfig({
  outExtensions: () => ({ js: '.js', dts: '.d.ts' }),
  tsconfig: 'tsconfig.build.json',
  entry: { node: 'src/node.ts' },
  format: ['esm'],
  dts: false,
  clean: true,
  sourcemap: false,
  target: false,
});
