import { createStoryReporter } from 'executable-stories-vitest/reporter';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
    exclude: ['dist/**', 'node_modules/**'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary'],
      thresholds: { statements: 85, branches: 80, functions: 90, lines: 90 },
    },
    reporters: [
      'default',
      createStoryReporter({
        formats: ['markdown'],
        outputDir: 'docs',
        outputName: 'stories',
        output: { mode: 'aggregated' },
        markdown: {
          includeMetadata: false,
          includeStatusIcons: true,
          stepStyle: 'bullets',
          sortScenarios: 'source',
        },
      }),
    ],
  },
});
