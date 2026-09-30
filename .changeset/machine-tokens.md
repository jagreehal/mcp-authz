---
'mcp-authz': minor
---

`verifier.requireEmail: false` accepts a token with no email, such as an agent's OAuth client-credentials token. The caller's identity is its `sub`, which a policy rule names. Email and domain rules never match it.
