---
name: mcp-authz-openapi
description: >
  Use when gating an HTTP API with mcp-authz: createOpenApiFetch and
  OpenApiAuthorizationMiddleware, recordOperations for the permission map, the
  per-caller OpenAPI document, and the routes it refuses.
metadata:
  type: core
  library: mcp-authz
  library_version: '0.1.0'
  sources:
    - 'jagreehal/mcp-authz:packages/mcp-authz/src/openapi.ts'
    - 'jagreehal/mcp-authz:packages/mcp-authz-python/src/mcp_authz/openapi.py'
---

# mcp-authz — gating an HTTP API by `operationId`

An OpenAPI document is the other catalogue an agent reads. A tool that is never
registered is a tool the model never sees; an operation that is never in the
served document is an operation the agent never calls. Same policy, same audit
events, keyed on `operationId` instead of a tool name.

## Setup

```ts
import { createOpenApiFetch } from 'mcp-authz/openapi';

export default createOpenApiFetch({
  spec,
  permissions: PERMISSIONS, // { getCase: 'cases:read', deleteCase: 'cases:delete' }
  resourceServerUrl: new URL('https://api.acme.com'),
  oauthMetadata,
  policy,
  emitter: 'cases-api',
  onAudit: (event) => logger.info(event),
  upstream: (request) => app.fetch(request), // your API, unchanged
});
```

```python
from mcp_authz.openapi import OpenApiAuthorizationMiddleware

app = OpenApiAuthorizationMiddleware(
    api,                       # any ASGI app
    spec=spec,
    permissions=PERMISSIONS,
    policy=policy,
    token_verifier=JwtVerifier(...),
    resource_server_url="https://api.acme.com",
    authorization_servers=["https://auth.acme.com"],
)
```

Opt-in entry point: `mcp-authz/openapi` does not import the MCP handler, its
route classification or its scope step-up.

## Core Patterns

### The map comes from the document

```ts
writeFileSync('permissions.ts', toPermissionsModule(recordOperations(spec)));
```

`recordOperations` needs the document and nothing else — no running server, no
introspection. Every operation lands priced `TODO:unassigned`, which no role
grants, so the boot refuses until a person has decided what each one costs.
Python: `to_permissions_module(record_operations(spec))`.

### The served document is per caller

`/openapi.json` (set `specPath` / `spec_path` to move it) is filtered to the
caller's operations and served authenticated, because it is a different document
per person. A path item left with no operations is dropped; `components` stays
whole, since pruning it means walking the `$ref` graph and a wrongly-pruned
schema breaks the document where an unused one costs a few hundred tokens.

The filtered document is a context saving, not the boundary. Naming a hidden
operation is still refused with the permission the caller lacks.

### Everything the document does not describe is refused

A route with no operation gets a 404 that says so. Health checks and static
files belong outside this wrapper, not behind it.

### Audit phase follows the status

`attempt`, then `success` or `failure`, where a 4xx or 5xx is a failure carrying
`error: 'HTTP 409'`. What an auditor is asking is whether the action happened,
and over HTTP that is the status rather than whether a promise rejected.

## Common Mistakes

### CRITICAL Relying on the filtered document as the boundary

A client coded against last month's spec never re-fetches it, and an agent can
guess a path. The check on the request is the boundary and runs whether or not
the caller ever read the document. Never treat a smaller document as a reason to
loosen the map.

Source: packages/mcp-authz/src/openapi.ts

### HIGH Operations with no `operationId`

Construction throws, naming the method and path. It is refused rather than named
`get /cases/{id}` for you: a generated fallback is a second naming scheme that
only some operations use, and it changes under a path rename, so the map
silently stops matching the route it was written for.

Source: packages/mcp-authz/src/openapi.ts

### HIGH Leaving a renamed operation in the map

An entry naming an operation the document no longer has fails the boot too. A
renamed `operationId` otherwise leaves an entry behind that prices nothing while
the new name goes unpriced.

Source: packages/mcp-authz/src/openapi.ts

### MEDIUM Mounting under a path the tokens are not bound to

`resourceServerUrl` is both the mount point and the audience tokens must carry.
A request outside it gets a 404 naming the path this answers on, which is the
first-run mistake worth reading rather than debugging.

Source: packages/mcp-authz/src/openapi.ts

See also: mcp-authz-audit/SKILL.md — the events both surfaces emit
See also: mcp-authz-permission-map/SKILL.md — pricing and drift-checking a map
