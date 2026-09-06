---
'mcp-authz': minor
---

Gate an HTTP API by `operationId`, and give the audit trail a shape a log store can query.

**`mcp-authz/openapi`.** An OpenAPI document is the other catalogue an agent
reads, so the bet `gate()` makes works there too: `createOpenApiFetch` serves the
document filtered to each caller, and checks the request whether or not they ever
read it. `recordOperations(spec)` builds the permission map from the document —
no running server, no introspection — and `toPermissionsModule` prices every
operation `TODO:unassigned` so the boot refuses until somebody decides what each
one costs. Construction fails on an unpriced operation, on an entry naming an
operation the document no longer has, and on a permission no role grants. A route
the document does not describe is refused with a 404 that says so. It is its own
entry point: the MCP handler, its route classification and its scope step-up stay
out of an OpenAPI-only bundle.

**Events say what they are.** `onAudit` and `onDecision` now emit
`mcp_authz.audit.v1` and `mcp_authz.decision.v1`. Each carries its own `type`, so
the two can share a store and still be told apart; a new optional field does not
move the version, and changing what an existing field means does.

Three fields join the audit event for whoever reads it later. `callId` is the
same on both events of one call and different for every other, so an attempt and
its outcome can be joined without guessing from timestamps. `domain` is the
verified Workspace domain, the nearest thing to an organisation this can prove —
key one by `(issuer, domain)`. `emitter` names the deployment, set it the same in
every entry point and a reader can tell which server a call reached. `kind` now
spans `operation` alongside `tool`, `prompt` and `resource`, so one query covers
both surfaces of a product.

`conformance/v1/audit/events.json` pins the type strings and the key sets, and
both language packages read it.

**Python reaches the same surface.** `mcp_authz` gains `on_audit`,
`on_audit_error` and `on_decision` on `AuthorizedMCPServer` and `gate`, emitting
the events above with the same JSON keys through `event.to_dict()`.
`mcp_authz.openapi` and `mcp_authz.proxy` are ASGI equivalents of the TypeScript
entry points, sharing the policy, the boot-time checks and the events.
