import { definePolicy } from 'mcp-authz';

/** Everyone at foo.com reads. Alice also writes. Nobody gets admin or payroll until a rule says so. */
export const policy = definePolicy({
  roles: {
    reader: ['cases:read'],
    editor: ['cases:read', 'cases:write'],
    admin: ['cases:read', 'cases:write', 'cases:admin', 'payroll:read'],
  },
  rules: [
    { match: { domain: 'foo.com' }, role: 'reader' },
    { match: { email: 'alice@foo.com' }, role: 'editor' },
  ],
});
