---
name: mcp-authz-authz
description: >
  Use when declaring per-user permissions on MCP capabilities you own with
  mcp-authz: authz(), definePolicy, tool/prompt/resource definitions, audit and
  human approval, and boot-time reconciliation.
metadata:
  type: core
  library: mcp-authz
  library_version: '0.1.0'
  sources:
    - 'jagreehal/mcp-authz:packages/mcp-authz/src/tools.ts'
    - 'jagreehal/mcp-authz:packages/mcp-authz/src/policy.ts'
    - 'jagreehal/mcp-authz:packages/mcp-authz/src/handler.ts'
---

# mcp-authz — `authz()` for capabilities you write

## Setup

```ts
import { authz, createMcpFetch, definePolicy } from 'mcp-authz';
import { z } from 'zod';

const policy = definePolicy({
  roles: { reader: ['cases:read'], lead: ['cases:read', 'cases:write'] },
  rules: [
    { match: { domain: 'acme.com' }, role: 'reader' },
    { match: { email: 'alice@acme.com' }, role: 'lead' },
  ],
});

const { tool, prompt, resource, server } = authz(policy);

const createServer = server(
  [
    tool('search_cases', { permission: 'cases:read' }, async () => ({ content: [] })),
    tool(
      'update_case',
      { permission: 'cases:write', inputSchema: { id: z.string() }, audit: ({ id }) => `case:${id}` },
      async ({ id }) => ({ content: [{ type: 'text', text: `updated ${id}` }] }),
    ),
  ],
  { name: 'case-tracker', version: '1.0.0' },
);

export default createMcpFetch({
  resourceServerUrl: new URL('https://mcp.acme.com/mcp'),
  oauthMetadata: {
    issuer: 'https://auth.acme.com',
    authorization_endpoint: 'https://auth.acme.com/authorize',
    token_endpoint: 'https://auth.acme.com/token',
    response_types_supported: ['code'],
  },
  verifier: { jwksUri: 'https://auth.acme.com/.well-known/jwks.json' },
  policy,
  createServer,
  legacy: 'stateless',
});
```

`createMcpFetch` returns a `fetch` function. Bind it with `listenMcp` from
`mcp-authz/node`, or export it from a Worker.

## Core Patterns

### The permission is the type

`permission` is typed to the policy's permissions, so a typo is a build error
rather than a capability nobody can reach. A capability whose permission no role
grants **throws at boot** — it is dead code that looks live. A permission no
capability requires only warns, because granting a role ahead of the tool that
will use it is how a staged rollout works.

### Labels

One vocabulary everywhere — permission maps, scope maps, `recordCapabilities`:

| Kind     | Label            |
| -------- | ---------------- |
| tool     | `search_cases`   |
| prompt   | `prompt:triage`  |
| resource | `resource:cases` |

### A caller sees only what they may call

`server()` registers, per request, only the capabilities the principal holds the
permission for. A reader's `tools/list` does not mention the write tools, and
naming one anyway is still refused.

### Audit, and asking a person

```ts
tool(
  'refund',
  {
    permission: 'billing:write',
    audit: ({ orderId }) => `order:${orderId}`,
    approval: ({ amount }) => amount > 500,
  },
  async ({ orderId }) => ({ content: [] }),
);
```

`audit` names what the call touched — the library cannot know `{ id: 'C1' }`
means a case. `approval` is **not** the permission check repeated: the caller
already holds the permission, and this is for actions that want a second person
anyway. It needs `onApproval` on `server()`, or boot throws.

## Common Mistakes

### CRITICAL Leaving `legacy` at its default and finding nothing connects

Wrong:

```ts
createMcpFetch({ ...options, createServer }); // legacy defaults to 'reject'
```

Correct:

```ts
createMcpFetch({ ...options, createServer, legacy: 'stateless' });
```

MCP 2026-07-28 removed the `initialize` handshake (SEP-2567), and `reject` is
the strict default. Every MCP client that currently ships still sends
`initialize`, so the default refuses all of them. The refusal says so, but set
`legacy: 'stateless'` to serve today's clients.

Source: packages/mcp-authz/src/handler.ts

### HIGH Treating an empty catalogue as the security boundary

A hidden capability is a usability feature. The permission check is the boundary:
a caller who names a tool they never saw is still refused with `403
policy_denied`. Do not rely on absence from a listing.

Source: packages/mcp-authz/src/tools.ts

### HIGH Confusing the two ways to say no

`403 policy_denied` means an administrator must change the policy —
re-authenticating will not help. `403 insufficient_scope` carries a
`WWW-Authenticate` challenge and means the caller can step up. Keep them
distinct; collapsing them sends people to the wrong place.

Source: packages/mcp-authz/src/ladder.ts

See also: mcp-authz-gate/SKILL.md — for servers you did not write
See also: mcp-authz-permission-map/SKILL.md — generating and checking the map
