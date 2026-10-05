import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
    exclude: ['dist/**', 'node_modules/**'],
    // Each test starts real processes: the built CLI, wrap and the server under tsx.
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
