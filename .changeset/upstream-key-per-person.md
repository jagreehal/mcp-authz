---
'mcp-authz': minor
---

`createMcpProxy` can forward each call with a key picked for the person making it. Pass `upstream.bearer` as a function and it receives the principal, so you can give readers a read-only upstream key and the upstream enforces the policy's split too. The proxy's own catalogue reads call it with no principal. In Python, a one-argument `upstream_bearer` callable does the same.

The sign-in example takes token expiry from Google and Okta, answers an expired token with a 401, and caches a verified token for a minute.
