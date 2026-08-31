---
'mcp-authz': minor
---

Human approval for permitted actions, policy explain and a CLI, plus security and audit fixes.

**Approval.** A capability can declare `approval: true`, or a predicate over its
arguments, and the call waits for a person before it runs. Pass `onApproval` to
`server()` (or to `gate()`, for tools you did not write) and return
`{ approved: true, by }`. The approving branch will not compile without a name,
an approval that arrives naming nobody is refused at runtime as well, and that
name lands on the `success` audit event beside the caller's. Silence is
a refusal after `approvalTimeoutMs` (45s by default), as is an `onApproval` that
throws. Nothing is stored: the caller is still on an open request, so a process
that dies mid-question takes the request with it.

**Explain a decision, and inspect a policy from a terminal.**
`policy.explain(identity)` returns the principal alongside every rule that
matched, each with its index in your own `rules` array, plus the deny that
emptied the grant when one did. It shares the single matcher with the decision,
so an explanation cannot disagree with what the gate did. Nothing on the request
path calls it.

The package now ships an `mcp-authz` binary over the same engine:

- `mcp-authz explain policy.json --identity alice.json` prints the derivation.
- `mcp-authz check policy.json --capabilities caps.json` runs the same
  `reconcile` the server runs at boot, so a capability no role can reach fails
  the pull request rather than the deploy.

No new dependencies: `node:util` parses the arguments.

**The body is no longer read before authentication.** Per-capability scopes are
checked against the token the request already carries, not by the bearer gate, so
the read that names the capability now happens after it. An unauthenticated
caller can no longer make this process parse anything, and `maxRequestBytes` now
bounds an authenticated caller rather than anyone who can reach the port.

**An unpermitted call is refused the same way with or without scopes.** Naming an
unregistered capability now answers `403 forbidden / policy_denied` and reaches
`onDecision`, instead of falling through to the SDK's unknown-capability error
with nothing written to the log.

**Identities without an email no longer fail with a 500.** `Principal.email` is
optional everywhere else, but the gate demanded one, so any opaque-token or
introspection identity carrying only a subject was rejected as an invalid
principal.

**Audit and construction.** Keep a completed capability result when its terminal
audit write fails, and send the delivery failure to the new `onAuditError` hook.
Attempt-audit failures still stop the handler before it runs.

Validate declarative OAuth scope maps during construction. Unknown capability
keys, duplicate tool aliases, missing baselines, empty requirements, and invalid
scope tokens now fail before the server accepts traffic.

Python-only, so no npm package moves. Recorded here because the fix crosses both
implementations.

`gate()` now exists in Python: a permission map over an `MCPServer` somebody
else builds, given one wrap hook in their builder. Unpriced registrations raise,
unpermitted tools and prompts are removed after registration, and unpermitted
resources are never registered at all.

`asyncio.wait_for` raises `asyncio.TimeoutError`, which before Python 3.11 is
not the builtin `TimeoutError`. Catching the builtin meant a silent approver on
3.10 was reported as an unnamed error rather than a missed deadline, and the
suite failed there. Both implementations now share one `request_approval`, so
the refusal has one shape and one place to fix.

An approver renders the arguments it is handed into a Slack message or a ticket,
which means serialising them. The SDK's injected `Context` holds the open
session, so it is dropped before the request is built.
