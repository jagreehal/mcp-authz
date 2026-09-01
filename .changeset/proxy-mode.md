---
'mcp-authz': minor
---

Add `mcp-authz/proxy`: enforce OAuth and RBAC in front of an MCP server you can
only reach by URL.

`createMcpProxy` verifies each caller's token, runs your policy, filters
catalogue listings to what they may reach, and forwards permitted calls with a
service credential. It shares the request ladder with `createMcpFetch` and is
stricter where a proxy has to be, because nothing downstream re-checks anything
and the credential it forwards on outranks the caller: routing headers that
disagree with the body are refused rather than forwarded, a request without them
is authorized from the JSON-RPC body, an unpriced capability is refused, and a
listing it cannot read is withheld instead of passed through. The caller's
`Authorization` and `Cookie` stay at the edge.

`resources/read` is priced by URI rather than by label, since that is what the
request carries, so `recordCapabilities` now emits a `RESOURCE_URIS` map beside
`PERMISSIONS` and the proxy refuses to boot without one for every priced
resource.

Also fixes a step-up scope that never fired for resources reached through a URI
template, in `createMcpFetch` and `gate()` as well as the proxy. `capabilityScopes`
is keyed by the resource as registered — `resource:cases://case/{id}` — while a
read carries one concrete URI, and the two were compared as strings, so a
baseline-only token could reach a resource priced for step-up.
