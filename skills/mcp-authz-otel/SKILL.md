---
name: mcp-authz-otel
description: >
  Use when sending mcp-authz audit and access-decision events to OpenTelemetry
  on Node, Cloudflare Workers or Python: the mcp-authz/otel sinks, hashed
  identifiers, tail-sampling keep, traced upstream fetch, and SDK init with
  autotel.
metadata:
  type: core
  library: mcp-authz
  library_version: '0.7.0'
  sources:
    - 'jagreehal/mcp-authz:packages/mcp-authz/src/otel.ts'
    - 'jagreehal/mcp-authz:packages/mcp-authz-python/src/mcp_authz/otel.py'
---

# mcp-authz — audit events on your traces

The sinks plug into the `onAudit` and `onDecision` hooks you already have. Each
one writes the event onto the active span, so the trace for a tool call carries
who made it and what the policy decided.

## Setup

### Node

```ts
import { init } from 'autotel';
import { instrumentMcpServer } from 'autotel-mcp-instrumentation/server';
import { createOtelAuthzSinks } from 'mcp-authz/otel';

init({ service: 'cases-mcp', endpoint: process.env.OTEL_EXPORTER_OTLP_ENDPOINT });

const { onAudit, onDecision } = createOtelAuthzSinks({ hashKey: process.env.AUDIT_HASH_KEY });
const createServer = server(defs, { name: 'cases', version: '1.0.0', emitter: 'cases-prod', onAudit });
createMcpFetch({
  // …
  emitter: 'cases-prod',
  onDecision,
  createServer: (ctx) => instrumentMcpServer(createServer(ctx), { networkTransport: 'tcp' }),
});
```

### Workers

`mcp-authz/otel` imports `@opentelemetry/api` alone, so the sinks bundle for
Workers unchanged. Initialise with `autotel-cloudflare` and enable
`nodejs_compat` in `wrangler.toml`.

```ts
import { wrapModule } from 'autotel-cloudflare';

export default wrapModule(
  { service: { name: 'mcp-proxy' }, nativeTracing: 'auto' },
  { fetch: (request, env) => proxy(request) },
);
```

### Python

```bash
pip install 'mcp-authz[otel]'
```

```python
import os

from autotel import init
from mcp_authz.otel import create_otel_authz_sinks

init(service="cases-mcp", instrumentation=["mcp"])
sinks = create_otel_authz_sinks(hash_key=os.environ["AUDIT_HASH_KEY"])
AuthorizedMCPServer(..., on_audit=sinks["on_audit"], on_decision=sinks["on_decision"])
```

## Core Patterns

### Wire both sinks

`onAudit` records permitted calls. `onDecision` records allow and deny answers,
including refusals that never reach a handler.

### Identifiers need a key

Pass `hashKey` (`hash_key` in Python) from a secret. `sub`, `email` and
`approvedBy` then land as HMAC-SHA-256 digests that TypeScript and Python
compute identically, so you can join spans across both. Without a key the sinks
leave those identifiers off.

### Spans survive tail sampling

Each sink sets `autotel.sampling.tail.keep`. Pass `{ forceKeep: false }`
(`force_keep=False` in Python) to let your sampler decide.

### Carry the trace upstream

In proxy mode, pass `createTracedFetch()` as `upstream.fetch` so the upstream
joins the same trace.

## Common Mistakes

### CRITICAL Importing Node `autotel` into a Worker

Use `autotel-cloudflare` for init on Workers. Keep `autotel` in the Node entry
point.

### HIGH Wiring only `onAudit`

Denials reach `onDecision` alone, so your traces show permitted calls and miss
every refusal.

### HIGH Hard-coding `hashKey`

A key in source lets anyone with the repo match digests to people. Read it from
a secret (`wrangler secret put AUDIT_HASH_KEY` on Workers).

### HIGH Calling `init()` inside `createServer`

`createServer` runs per request. Call `init` once per process, or `wrapModule`
once per Worker.

See also: mcp-authz-audit/SKILL.md — the events these sinks write
