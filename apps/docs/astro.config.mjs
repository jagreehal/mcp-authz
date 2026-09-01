import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://jagreehal.github.io',
  base: '/mcp-authz',
  integrations: [
    starlight({
      title: 'mcp-authz',
      description:
        'Per-user permissions for an MCP server, as a library you import rather than a proxy you deploy.',
      favicon: '/favicon.svg',
      // `404.mdx` is the only /404 route; avoids a duplicate prerender attempt.
      disable404Route: true,
      components: {
        ThemeProvider: './src/components/ThemeProvider.astro',
        ThemeSelect: './src/components/ThemeSelect.astro',
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/jagreehal/mcp-authz',
        },
      ],
      editLink: {
        baseUrl: 'https://github.com/jagreehal/mcp-authz/edit/main/apps/docs/',
      },
      customCss: [
        '@fontsource-variable/inter',
        '@fontsource/jetbrains-mono',
        '@fontsource/jetbrains-mono/500.css',
        '@fontsource/jetbrains-mono/600.css',
        './src/styles/custom.css',
      ],
      sidebar: [
        {
          label: 'Start here',
          items: [
            { label: 'What this is', slug: 'introduction' },
            { label: 'Deployment', slug: 'concepts/deployment' },
            { label: 'Quick start', slug: 'quick-start' },
            { label: 'Run the example', slug: 'run-the-example' },
          ],
        },
        {
          label: 'How it works',
          items: [
            { label: 'The request ladder', slug: 'concepts/request' },
            { label: 'Policies', slug: 'concepts/policies' },
            { label: 'Capabilities', slug: 'concepts/capabilities' },
            { label: 'Human approval', slug: 'concepts/approval' },
            { label: 'Scopes and step-up', slug: 'concepts/scopes' },
            { label: 'Boot-time checks', slug: 'concepts/reconciliation' },
          ],
        },
        {
          label: 'TypeScript',
          items: [
            { label: 'API reference', slug: 'typescript/api' },
            { label: 'gate(): servers you did not write', slug: 'typescript/gate' },
            { label: 'External entitlements', slug: 'typescript/entitlements' },
            { label: 'Building the permission map', slug: 'typescript/permission-map' },
            { label: 'Proxy mode', slug: 'typescript/proxy' },
            { label: 'CLI', slug: 'typescript/cli' },
          ],
        },
        {
          label: 'Python',
          items: [
            { label: 'Quick start', slug: 'python/quick-start' },
            { label: 'gate(): servers you did not write', slug: 'python/gate' },
            { label: 'API reference', slug: 'python/api' },
          ],
        },
        {
          label: 'Guides',
          items: [
            {
              label: 'Point your AS at it',
              slug: 'guides/authorization-server',
            },
            { label: 'Troubleshooting', slug: 'guides/troubleshooting' },
            { label: 'Configuration', slug: 'guides/configuration' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'Conformance', slug: 'reference/conformance' },
            { label: 'Spec coverage', slug: 'reference/spec' },
          ],
        },
      ],
    }),
  ],
});
