---
'mcp-authz': minor
---

Add `mcp-authz wrap`, which runs a stdio MCP server and shows the client only the tools you choose. `mcp-authz tools --out` saves a server's tools as a commented config with an editor schema, `tools --check` reports what changed on the server, and `tools --refresh` records it with your choices kept. `@modelcontextprotocol/client` is now a dependency, so every command runs from `npx`.
