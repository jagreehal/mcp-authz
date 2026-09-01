---
name: mcp-authz-proxy
description: >
  Use when putting mcp-authz in front of an MCP server reachable only by URL:
  createMcpProxy, resourceUris for resource reads, listing filters, and the
  strictness rules a proxy applies that embed mode does not.
metadata:
  type: core
  library: mcp-authz
  library_version: '0.1.0'
  sources:
    - 'jagreehal/mcp-authz:packages/mcp-authz/src/proxy.ts'
    - 'jagreehal/mcp-authz:packages/mcp-authz/src/ladder.ts'
    - 'jagreehal/mcp-authz:packages/mcp-authz/src/upstream.ts'
---

# mcp-authz — `createMcpProxy` for URL-only upstreams

When there is no builder hook to `gate()`, this terminates the connection:
verify each person's token, run your policy, filter listings, and forward
permitted calls with a service credential.

## Setup

```ts
import { createMcpProxy } from 'mcp-authz/proxy';
import { definePolicy } from 'mcp-authz';
import { PERMISSIONS, RESOURCE_URIS } from './permissions';

export default createMcpProxy({
  resourceServerUrl: new URL('https://mcp.acme.com/mcp'),
  oauthMetadata: {
    issuer: 'https://auth.acme.com',
    authorization_endpoint: 'https://auth.acme.com/authorize',
    token_endpoint: 'https://auth.acme.com/token',
    response_types_supported: ['code'],
  },
  verifier: { jwksUri: 'https://auth.acme.com/.well-known/jwks.json' },
  policy,
  permissions: PERMISSIONS,
  resourceUris: RESOURCE_URIS,
  upstream: { url: 'https://vendor.example.com/mcp', bearer: process.env.UPSTREAM_TOKEN! },
});
```

Opt-in subpath: `mcp-authz/proxy` is not re-exported from the main entry, so
becoming the authorization boundary is something you import on purpose.

## Core Patterns

### Resources are priced by URI, not by label

A `resources/list` names a resource; a `resources/read` carries a URI. The
permission map is keyed by label, so the proxy needs both — `record` writes
`RESOURCE_URIS` for you, and the proxy **refuses to boot** if a priced
`resource:` label has no URI rather than advertising a resource it would then
refuse to read.

Where several patterns cover one URI, all of them apply: the caller needs every
matching permission and every matching scope. Which registration an upstream
routes a URI to is its business, not something to guess from map order.

### It is stricter than embed mode

`createMcpFetch` has the SDK downstream and can leave a malformed request to it.
A proxy has no second line and forwards on a credential that outranks the caller,
so it decides for itself:

- Routing headers that **disagree with the body** are an HTTP 400. `Mcp-Method:
tools/list` over a `tools/call` body is a smuggling attempt, not a hint.
- A request with **no** routing headers is authorized from the JSON-RPC body,
  which is what the upstream will act on. A header is never the source.
- A capability the map does not price is refused, so an upstream that grows a
  tool does not inherit your service credential.
- A listing it cannot read is withheld with a 502, not passed through.

### What reaches the upstream

The caller's `Authorization` is replaced with the service credential, and their
`Cookie` is dropped along with the hop-by-hop headers — including the ones the
`Connection` header names. `/health` reports counts, never the upstream address.

## Common Mistakes

### CRITICAL Assuming the request size cap only bounds requests

`maxRequestBytes` (default 1 MiB) bounds a single message **in either
direction**. Every POST is read to find the capability it names, and a catalogue
must be held whole to be filtered, so an oversized body or SSE event is refused
rather than buffered. Raise it if your upstream takes large tool arguments or
returns large catalogues.

Source: packages/mcp-authz/src/proxy.ts

### HIGH Keying resource scopes the way embed mode does

In proxy mode `capabilityScopes` keys resources by **label**:

```ts
capabilityScopes: { 'resource:case': 'cases:sensitive' }
```

Embed mode keys them by the URI **as registered**, template included
(`resource:cases://case/{id}`), because that is what its registrations are keyed
by. Each mode validates its own form at boot.

Source: packages/mcp-authz/src/proxy.ts

### MEDIUM Building the proxy per request in a Worker

Wrong:

```ts
export default { fetch: (request, env) => proxyFromEnv(env)(request) };
```

Correct:

```ts
let proxy;
export default {
  fetch(request, env) {
    proxy ??= proxyFromEnv(env);
    return proxy(request);
  },
};
```

Construction validates the map, reconciles it against the policy, and builds the
verifier whose JWKS cache lives inside it. Rebuilding per request redoes all
three and re-fetches signing keys.

Source: apps/proxy-example/src/worker.ts

See also: mcp-authz-permission-map/SKILL.md — recording an upstream you cannot read
See also: mcp-authz-gate/SKILL.md — cheaper, when a wrap hook exists
