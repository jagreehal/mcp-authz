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

## Deploy to Cloudflare Workers

```bash
pnpm --filter mcp-authz-proxy-example build
wrangler secret put UPSTREAM_TOKEN
pnpm --filter mcp-authz-proxy-example deploy
```

Set `[vars]` in `wrangler.toml` for public URLs and OAuth metadata. Keep
`UPSTREAM_TOKEN` as a secret.
