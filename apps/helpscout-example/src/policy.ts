import { definePolicy, type PermissionOf } from 'mcp-authz';

/**
 * One caller: the org agent. A tool priced `helpscout:write` stays unreachable
 * until a role grants it, and boot reports it.
 */
export const policy = definePolicy({
  roles: {
    reader: ['helpscout:read'],
  },
  rules: [{ match: { sub: 'claude-tag' }, role: 'reader' }],
});

export type Permission = PermissionOf<typeof policy>;
