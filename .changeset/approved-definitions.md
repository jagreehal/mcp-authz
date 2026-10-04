---
'mcp-authz': minor
---

Hold every MCP server to the tool definitions you approved.

- `mcp-authz tools` saves a server's catalogue with an estimated token cost per tool and flags definitions with hidden characters or text addressed to the model. New configs switch on only read-only tools. `wrap <file>` takes the config as an argument, and `tools --check` and `tools --refresh <file>` show and record changes word for word.
- `wrap` and `createMcpProxy` hide a tool whose description, schema or annotations differ from the record, and check before the first call too. They remove changed server instructions, refuse arguments outside the approved `inputSchema` and withhold output that breaks the approved `outputSchema`. Output aimed at the model arrives behind a notice, and numbers keep their exact digits both ways.
- `mcp-authz record` writes `DEFINITIONS`, the full record `createMcpProxy` now requires. `createMcpProxy` speaks MCP 2026-07-28 and forwards only methods it can price, completions and resource subscriptions included. It marks filtered listings private.
- A resource read satisfies every registration that covers its URI.
