import { defineConfig } from 'tsdown';

export default defineConfig({
  outExtensions: () => ({ js: '.js', dts: '.d.ts' }),
  tsconfig: 'tsconfig.build.json',
  entry: {
    index: 'src/index.ts',
    node: 'src/node.ts',
    policy: 'src/policy.ts',
    cli: 'src/cli.ts',
    testing: 'src/testing.ts',
  },
  format: ['esm'],
  dts: true,
  clean: true,
  sourcemap: false,
  target: false,
});
