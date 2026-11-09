---
'mcp-authz': minor
---

Add `mcp-authz/otel`, which writes audit and access-decision events onto the active OpenTelemetry span. Pass `createOtelAuthzSinks()` to `onAudit` and `onDecision`, and `createTracedFetch()` as the proxy's `upstream.fetch` to carry the trace upstream. The sinks depend on `@opentelemetry/api` alone and run on Node and Workers. In Python, `mcp_authz.otel` does the same, and `pip install 'mcp-authz[otel]'` adds autotel. Pass `hashKey` to add HMAC-SHA-256 digests of the subject, email and approver, identical in TypeScript and Python. Handler error messages stay off spans unless you pass `captureErrors: true`.
