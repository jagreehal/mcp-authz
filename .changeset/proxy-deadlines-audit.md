---
'mcp-authz': minor
---

`createMcpProxy` stops slow and abandoned calls and records each one.

- `upstream.timeoutMs` caps how long one forwarded request may take, answer included. Past it the proxy stops the upstream request and answers `504`. The proxy's own catalogue reads use the same deadline.
- The proxy passes the incoming request's `signal` to the upstream, so a client that disconnects stops the forwarded request.
- `onAudit` and `onAuditError` record each forwarded tool call, prompt get and resource read as `mcp_authz.audit.v1` events, the ones embed mode and `mcp-authz/openapi` emit: an `attempt`, then `success` or `failure` under one `callId`, written once the client has read the whole answer. When the `attempt` write throws, the call does not run and the caller gets a `503`.

The Python `McpProxy` gains `upstream_timeout`, `on_audit` and `on_audit_error` with the same behaviour.
