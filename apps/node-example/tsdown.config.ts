import { defineConfig } from 'tsdown';

export default defineConfig({
  outExtensions: () => ({ js: '.js', dts: '.d.ts' }),
  tsconfig: 'tsconfig.build.json',
  entry: { index: 'src/index.ts', node: 'src/node.ts', token: 'src/token.ts' },
  format: ['esm'],
  dts: true,
  clean: true,
  sourcemap: false,
  target: false,
});
