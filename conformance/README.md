# MCP Authz conformance

`conformance/v1` is the language-neutral behavioral interface shared by every
MCP Authz implementation. A package may use its ecosystem's native types and
MCP SDK, but it must produce the outcomes recorded here.

The fixtures are versioned independently from npm or PyPI packages. Changing an
existing expected outcome is a conformance-breaking change; add a new version
when implementations cannot support both meanings at once.

Current fixture groups:

- `policy/decisions.json`: identity-to-principal decisions, including deny
  precedence, claim matching and wildcard grants.
- `policy/explanations.json`: the same policy again, pinning which rules
  produced each decision. Two implementations can agree on what a caller may do
  and still disagree about why, and an index that points at the wrong rule sends
  an administrator to the wrong line.
- `policy/validation.json`: malformed policies that must fail during startup.
- `protocol/scopes.json`: scope selection for tools, prompts and resources.
- `protocol/routing.json`: the trusted 2026 request-routing ladder used before
  per-capability scope enforcement.

Each language package owns its implementation and native tooling. The fixtures
are the seam: both packages read these files rather than copying the behaviour
into a second set of assertions, which is what keeps a policy decision meaning
the same thing in either language.

Approval and per-capability scope step-up are deliberately absent here. A
fixture pins what a policy decides about an identity, and neither of those is a
policy decision: one asks a person about a particular call, the other is an HTTP
challenge about a token.

Run both adapters with:

```bash
pnpm test:conformance      # TypeScript, src/conformance.test.ts
pnpm verify:python         # Python, tests/test_conformance.py among the rest
```
