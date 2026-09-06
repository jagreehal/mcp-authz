---
name: mcp-authz-audit
description: >
  Use when wiring mcp-authz audit and access-decision events: onAudit and
  onDecision, the callId/domain/emitter fields, fail-closed delivery rules, and
  where the events should go.
metadata:
  type: core
  library: mcp-authz
  library_version: '0.1.0'
  sources:
    - 'jagreehal/mcp-authz:packages/mcp-authz/src/tools.ts'
    - 'jagreehal/mcp-authz:packages/mcp-authz/src/decision.ts'
    - 'jagreehal/mcp-authz:packages/mcp-authz-python/src/mcp_authz/audit.py'
    - 'jagreehal/mcp-authz:conformance/v1/audit/events.json'
---

# mcp-authz — the record tying a person to an action

The downstream API sees one service account. These events are the only place a
person appears, so both packages emit the same two records with the same JSON
keys.

## Setup

```ts
server(definitions, {
  name: 'cases',
  version: '1.0.0',
  emitter: 'cases-prod',
  onAudit: (event) => logger.info(event),
  onAuditError: (failure) => retryQueue.add(failure.event),
});

createMcpFetch({ /* … */ emitter: 'cases-prod', onDecision: (event) => logger.warn(event) });
```

```python
AuthorizedMCPServer(
    "cases",
    ...,
    emitter="cases-prod",
    on_audit=lambda event: log.info("audit", extra=event.to_dict()),
    on_decision=lambda event: log.warning("access", extra=event.to_dict()),
)
```

`gate`, `createMcpProxy` / `McpProxy` and the OpenAPI entry points take the same
hooks.

## Core Patterns

### Two events, wired separately

`mcp_authz.audit.v1` covers calls that were permitted: `attempt`, then
`success`, `failure` or `refused`. `mcp_authz.decision.v1` covers who was let in
or turned away, including somebody naming a capability they were never shown —
the single most interesting line in the log. They are separate hooks because
they happen in different places, so wire both.

### Three fields exist for the reader

- `callId` is the same on both events of one call and different for every other,
  so a store can join an attempt to its outcome. Correlating by identity and
  timestamp breaks under exactly the concurrency that makes the question worth
  asking.
- `domain` is the verified Workspace domain from the `hd` claim: the nearest
  thing to an organisation this can prove. Key one by `(issuer, domain)`.
- `emitter` names the deployment, and you set it. Use the same value in every
  entry point of one deployment.

### `kind` spans both surfaces

`tool`, `prompt`, `resource`, or `operation` for HTTP operations gated through
the OpenAPI entry point, so one query covers both surfaces of a product.

### The attempt write is the fail-closed one

It is awaited, and a rejection stops the call before it runs — an action nobody
could record is an action that should not happen. Terminal writes happen after
the action reached its result and cannot change it; their failures go to
`onAuditError` / `on_audit_error`.

## Common Mistakes

### CRITICAL Calling a third-party API from `onAudit`

A webhook on the attempt path puts somebody else's uptime in front of your
tools: when their endpoint is slow, every call waits, and when it is down, every
call fails. Write locally and ship asynchronously.

Source: packages/mcp-authz/src/tools.ts

### HIGH Wiring only `onAudit`

The refusals are on `onDecision`, and a probe for a capability the caller was
never shown never reaches `onAudit` at all — nothing ran. A log with only the
successes cannot answer the question a security team actually asks.

Source: packages/mcp-authz/src/handler.ts

### HIGH Putting arguments in the event

Only `resource` records what a call touched, and it comes from the capability's
own `audit` callback — `({ id }) => \`case:${id}\`` — so the recorded detail is
chosen rather than dumped. Do not widen it with raw arguments; a log store is
the wrong first home for whatever a caller typed.

Source: packages/mcp-authz/src/tools.ts

### MEDIUM Renaming a key in a sink

`conformance/v1/audit/events.json` pins the type strings and the key sets, and
both packages read it. Adding an optional key is fine and does not move the
`v1`; renaming or re-meaning one breaks a query somebody has stored, and fails
the conformance test.

Source: conformance/v1/audit/events.json

See also: mcp-authz-authz/SKILL.md — declaring the capability an event describes
See also: mcp-authz-openapi/SKILL.md — the same events over an HTTP API
