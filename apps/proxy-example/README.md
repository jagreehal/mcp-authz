# MCP proxy example

`createMcpProxy` from `mcp-authz/proxy` sits in front of a URL-only upstream MCP
server. People authenticate with your authorization server; the proxy verifies
their token, runs your policy, filters catalogue listings, and forwards
permitted calls with a service credential.

## Record → price → proxy

```bash
# 1. Record the upstream catalogue (service credential).
npx mcp-authz record \
  --upstream "$UPSTREAM_URL" \
  --token "$UPSTREAM_TOKEN" \
  --out src/permissions.ts

# 2. Replace every TODO:unassigned with a real permission, then commit.

# 3. Point this example at the upstream and your AS.
export MCP_PUBLIC_URL=http://127.0.0.1:8300/mcp
export OAUTH_ISSUER=https://auth.example.com
export OAUTH_AUTHORIZATION_ENDPOINT=https://auth.example.com/authorize
export OAUTH_TOKEN_ENDPOINT=https://auth.example.com/token
export OAUTH_JWKS_URI=https://auth.example.com/.well-known/jwks.json
export UPSTREAM_URL=https://vendor.example.com/mcp
export UPSTREAM_TOKEN=service-token

pnpm --filter mcp-authz-proxy-example dev
```

Claude (or any MCP client) dials `MCP_PUBLIC_URL`. The proxy dials `UPSTREAM_URL`
with `UPSTREAM_TOKEN`.

The proxy speaks MCP 2026-07-28 only, so the client must too. A client that
still opens with the 2025 `initialize` handshake gets a 400, and the upstream
must answer a 2026-07-28 client, because that is how the proxy lists it.

`src/proxy.ts` passes `PERMISSIONS`, `DEFINITIONS` and `RESOURCE_URIS` from
`src/permissions.ts`. `DEFINITIONS` is what each capability said when you
recorded it: the proxy hides and refuses one whose definition has since changed,
and logs which fields moved. Before a call to a capability it has not checked
in the last minute, the proxy lists the upstream itself, so a client that calls
without listing is held to the record too. The upstream's instructions are
removed when they differ from `DEFINITIONS['server:instructions']`. Re-record to
approve a change.

## Deploy to Cloudflare Workers

```bash
pnpm --filter mcp-authz-proxy-example build
wrangler secret put UPSTREAM_TOKEN
pnpm --filter mcp-authz-proxy-example deploy
```

Set `[vars]` in `wrangler.toml` for public URLs and OAuth metadata. Keep
`UPSTREAM_TOKEN` as a secret.
