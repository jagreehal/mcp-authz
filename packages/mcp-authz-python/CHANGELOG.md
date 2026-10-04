# mcp-authz (Python)

PyPI releases are versioned separately from the npm package. Policy behaviour is
shared and pinned by [`conformance/v1`](../../conformance/README.md); everything
else moves independently.

## Unreleased

The proxy, breaking:

- **`McpProxy` requires `definitions`.** A capability whose live definition
  differs from the one recorded is hidden from listings and its calls are
  refused; a call the proxy has not seen listed lately is checked against the
  upstream's catalogue first. Changed `server/discover` instructions are
  withheld.
- **MCP `2026-07-28` only, and only methods it can price.** Legacy requests,
  non-`POST` methods (`405`) and unknown methods (`-32601`) are refused rather
  than forwarded. `completion/complete` and `subscriptions/listen` are priced as
  the prompt or resource reads they stand in for.
- **Filtered listings are private.** `cacheScope: "private"` and
  `Cache-Control: private, no-store`, with the upstream's validators removed.
- **A body that repeats a key is refused** with `-32600`.
- **Tool calls are held to the recorded schemas.** Arguments that break the
  recorded `inputSchema` are refused with `-32602`; structured output that
  breaks the `outputSchema` is withheld; output with invisible characters or
  text addressed to the model gets a warning prepended. Adds `jsonschema`, which
  the MCP SDK already installs, as a declared dependency.

## 0.2.0

Two refusals that used to be silent permissions. Both are breaking, and both
were places where a mistake in your own wiring read as an allow.

- **A capability nobody priced is refused, and hidden.** A tool, prompt or
  resource registered straight on `.mcp`, bypassing the decorator that names its
  permission, used to be reachable by everyone with nothing in the logs to read.
  It now raises `forbidden` / `undeclared_capability` and is filtered out of
  every listing. If you register capabilities outside the decorators, add them to
  the decorators or expect a refusal.
- **A caller matching no rule is refused on every method.** Previously they
  reached an empty listing and no explanation. They now get `forbidden` /
  `policy_denied` on listings as well as calls, which is what the TypeScript
  package has always answered with HTTP 403.

Added:

- **Human approval.** A capability can declare `approval=True`, or a predicate
  over its arguments, and the call waits for `on_approval` before it runs.
  Approving without naming the approver is refused, silence past
  `approval_timeout` is refused, and a sink that raises is refused. A capability
  that asks for a person while no approver is configured is refused at
  registration rather than at the first destructive call.
- `policy.explain(identity)` returns the decision alongside every `MatchedRule`
  that produced it, each carrying its index in your own `rules` list, plus
  `denied_by` when a deny emptied the grant. It shares the one matcher with the
  decision, so an explanation cannot disagree with what the middleware did.

## 0.1.0

First release. OAuth resource-server verification, a deny-by-default policy, and
per-capability permissions filtering discovery and invocation on the official MCP
Python SDK v2.
