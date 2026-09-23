---
'mcp-authz': patch
---

Add a Help Scout example for an org agent that presents a static bearer. A
custom `tokenVerifier` checks the key, the policy grants `helpscout:read`, and
the server lists the Mailbox tools once you set their credentials. The
`mcp-authz-authz` skill and the docs show the pattern.
