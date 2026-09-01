import eslint from '@eslint/js';
import prettier from 'eslint-config-prettier';
import vitestStories from 'eslint-plugin-executable-stories-vitest';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['**/dist/**', '**/node_modules/**', '**/docs/**'] },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  prettier,
  // A story that calls init() without `task`, or a step before init(), is
  // dropped silently: the test still passes and the documentation loses it.
  // These rules are the only thing that turns that into a build error.
  ...vitestStories.configs.recommended,
  {
    rules: {
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
      'prefer-const': 'warn',
    },
  },
);
