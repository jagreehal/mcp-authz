---
'mcp-authz': patch
---

Add a sign-in example: `createMcpProxy` behind Google, Microsoft, Okta, Clerk or
GitHub, with no authorization server to run. A custom `tokenVerifier` asks the
provider whether it issued each token for this server and whose it is, and the
proxy advertises the scopes each provider's identity lookup needs. A test signs
in through an emulator for each provider and checks what three people see under
one policy. The `mcp-authz-proxy` skill and the docs show the pattern.
