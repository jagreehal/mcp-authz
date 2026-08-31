import { definePolicy, type PermissionOf, type PolicySpec } from 'mcp-authz';

/**
 * Written as a literal so the permission names become a type. `cases:wrtie` in
 * a tool is a build error, not a 403 nobody sees until Monday.
 */
const typedPolicy = definePolicy({
  roles: {
    reader: ['cases:read'],
    editor: ['cases:read', 'cases:write'],
    admin: ['*'],
  },
  rules: [
    // Order does not matter: every matching rule applies, and the permissions union.
    { match: { domain: 'acme.com' }, role: 'reader' },
    { match: { email: 'alice@acme.com' }, role: 'editor' },
    // Groups the IdP already maintains, rather than a list kept in step by hand.
    { match: { claim: { 'https://acme.com/groups': 'qa-leads' } }, role: 'editor' },
    { match: { sub: 'auth0|departed-contractor' }, deny: true },
  ],
});

/**
 * The no-backend path: the whole policy in one environment variable, edited by
 * an administrator without a rebuild.
 *
 *   MCP_POLICY='{"roles":{"reader":["cases:read"]},
 *                "rules":[{"match":{"domain":"acme.com"},"role":"reader"}]}'
 *
 * Same shape validation and the same boot-time reconciliation against the
 * tools. Only the compile-time name check is gone, because there was never a
 * literal for TypeScript to look at — hence the cast, which asserts the
 * deployment uses the same permission vocabulary. Get that wrong and the
 * startup reconciliation says so rather than the first caller.
 */
export const policy = process.env.MCP_POLICY
  ? (definePolicy(JSON.parse(process.env.MCP_POLICY) as PolicySpec) as typeof typedPolicy)
  : typedPolicy;

export type Permission = PermissionOf<typeof policy>;
