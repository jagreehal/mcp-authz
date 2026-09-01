import { definePolicy } from 'mcp-authz';

export const policy = definePolicy({
  roles: {
    reader: ['cases:read'],
    editor: ['cases:read', 'cases:write'],
  },
  rules: [
    { match: { domain: 'acme.com' }, role: 'reader' },
    { match: { email: 'alice@acme.com' }, role: 'editor' },
  ],
});
