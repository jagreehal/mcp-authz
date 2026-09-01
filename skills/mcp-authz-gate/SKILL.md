---
name: mcp-authz-gate
description: >
  Use when adding per-user permissions to an MCP server you did not write with
  mcp-authz gate(): the wrap hook, permission maps, deny-by-default on
  registration, and adding audit or human approval without touching their code.
metadata:
  type: core
  library: mcp-authz
  library_version: '0.1.0'
  sources:
    - 'jagreehal/mcp-authz:packages/mcp-authz/src/gate.ts'
    - 'jagreehal/mcp-authz:packages/mcp-authz/src/tools.ts'
---

# mcp-authz — `gate()` for servers you did not write

`authz()` is for capabilities you define. `gate()` is for the ones you already
have: a server from another package, or one you are not ready to change, whose
tools were never declared with a permission.

## Setup

It cannot read a built server's capability list — the SDK keeps that private,
and nothing can filter what it never saw. So it wraps the server **before**
registration, which needs one hook from whoever builds it:

```ts
// in their builder
export function buildServer(config: Config, options: { wrap?: (s: McpServer) => McpServer } = {}) {
  const server = options.wrap ? options.wrap(new McpServer(info, opts)) : new McpServer(info, opts);
  server.registerTool('search_cases', {/* ... */}, handler);
  return server;
}

// in your connector
import { gate } from 'mcp-authz';

const PERMISSIONS = {
  search_cases: 'cases:read',
  update_case: 'cases:write',
  'prompt:triage': 'cases:read',
  'resource:cases': 'cases:read',
} as const;

createMcpFetch({
  ...options,
  policy,
  createServer: (principal) => buildServer(config, { wrap: (s) => gate(s, principal, PERMISSIONS) }),
});
```

## Core Patterns

### Registers, then disables

An unpermitted capability is registered and immediately disabled rather than
skipped, so the builder still gets the handle its own code expects — the SDK
then does the list-filtering and the refusal. This is why `gate()` works on code
that keeps a reference to what it registered.

### Deny by default, loudly

A capability the map does not price throws at registration:

```
gate(): no permission declared for tool 'close_run'.
Add 'close_run' to the permission map, or stop registering it.
```

That is deliberate. A dependency that adds a tool in a patch release fails the
boot rather than shipping something reachable by everyone, or by nobody, with no
error. Keep the map current with `record --check` in CI.

### Audit and approval on somebody else's tool

The one thing worth adding to a destructive tool you do not own:

```ts
gate(server, principal, PERMISSIONS, {
  audit: { update_case: ({ id }) => `case:${id}` },
  approval: { close_run: true },
  onApproval: async (request) => askOnSlack(request),
  onAudit: (event) => log.info(event),
});
```

Keys are the same labels as `permissions`. `approval` naming anything without
`onApproval` throws at boot — asking nobody is not approving.

## Common Mistakes

### CRITICAL Calling gate() on an already-built server

Wrong:

```ts
const server = buildServer(config);
gate(server, principal, PERMISSIONS); // too late, nothing was wrapped
```

Correct:

```ts
buildServer(config, { wrap: (server) => gate(server, principal, PERMISSIONS) });
```

Registration has already happened by the time you hold the server, and the SDK
does not expose what was registered. If the package offers no `wrap` hook, ask
for one — or put [`createMcpProxy`](../mcp-authz-proxy/SKILL.md) in front of it
instead.

Source: packages/mcp-authz/src/gate.ts

### HIGH Prefixing tool labels

Wrong:

```ts
const PERMISSIONS = { 'tool:search_cases': 'cases:read' };
```

Correct:

```ts
const PERMISSIONS = { search_cases: 'cases:read' };
```

Tools are bare; only prompts and resources carry a prefix. This is the same
vocabulary `authz()` and `recordCapabilities()` use.

Source: packages/mcp-authz/src/gate.ts

See also: mcp-authz-permission-map/SKILL.md — generate the map instead of typing it
See also: mcp-authz-proxy/SKILL.md — when all you have is a URL
