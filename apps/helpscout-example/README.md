# Help Scout MCP example

Your own Help Scout MCP server for an org agent such as Claude Tag: tools you
wrote, with descriptions, priced by `mcp-authz`; a static bearer in front; Help
Scout credentials that never leave the process.

```
Claude Tag ──Bearer MCP_BEARER──▶ this server ──Basic (Docs key)──────────▶ docsapi.helpscout.net
                                              ──client credentials token──▶ api.helpscout.net/v2
```

The Docs API takes a key and the Mailbox API takes an App ID/Secret, both from
a dedicated read-only Help Scout user.

## Run

```bash
export MCP_PUBLIC_URL=https://mcp.example.com/mcp   # the URL Claude dials
export MCP_BEARER=$(openssl rand -hex 32)           # what Claude presents
export HELPSCOUT_DOCS_API_KEY=…                     # Profile → Security and Access
export HELPSCOUT_APP_ID=…                           # Profile → My Apps
export HELPSCOUT_APP_SECRET=…

pnpm --filter mcp-authz-helpscout-example dev       # :8400
```

## Connect Claude Tag

Access bundle → **Credentials → Custom tool**: type **Bearer**, value
`MCP_BEARER`, allowed website `mcp.example.com`. Then a plugin whose
`.mcp.json` names `MCP_PUBLIC_URL`.

## Tools

`search_articles`, `get_article`, `list_collections` (Docs);
`search_conversations`, `get_conversation`, `get_customer`, `list_inboxes`
(Mailbox). All priced `helpscout:read`. A write tool would be unreachable until
a role grants `helpscout:write`, and boot says so.
