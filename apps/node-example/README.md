# mcp-authz-node-example

Minimal remote MCP server built on `mcp-authz`. Three tools: `whoami`, `get_case` (read) and `update_case` (write), gated by [`src/policy.ts`](src/policy.ts).

## Try it in a minute, with no authorization server

```bash
pnpm dev                       # :8200, with a local dev key
pnpm token dana@acme.com       # reader, matches the acme.com domain rule
pnpm token alice@acme.com      # editor, matches the named rule
pnpm token sam@other.com       # nobody, matches nothing
```

Paste a token into the MCP Inspector's **Authentication → Bearer Token** field and list the tools:

| Token            | `tools/list`                        | `prompts/list` | `update_case`                  |
| ---------------- | ----------------------------------- | -------------- | ------------------------------ |
| `dana@acme.com`  | `whoami`, `get_case`                | empty          | not there to call              |
| `alice@acme.com` | `whoami`, `get_case`, `update_case` | `triage_case`  | works, and audits `case:C1234` |
| `sam@other.com`  | HTTP 403 `forbidden/policy_denied`  | 403            | —                              |

Both readers and editors see the `cases://all` resource, because both hold
`cases:read`. Prompts and resources go through the same gate as tools.

Dana does not have `update_case` _hidden_; it was never registered for her request.

Two more things worth trying:

```bash
pnpm token priya@acme.com --group qa-leads   # promoted by an IdP claim, no policy edit
pnpm token alice@acme.com --scope mcp        # tool stays visible; call → 403 insufficient_scope
```

The last one is the second axis: a **scope** gap is something the client can re-authorise for and the challenge says so, while a **permission** gap is an administrator's job.

`MCP_DEV_AUTH=1` mints tokens locally and publishes the key to verify them. It is not a login, and it refuses to start when `NODE_ENV=production`. Everything after the token is the real code path. The key pair is generated on first use into a gitignored `.dev-auth.json`; nothing secret is committed.

[`src/e2e.test.ts`](src/e2e.test.ts) asserts every row of that table, so this page cannot quietly stop being true.

## Against a real authorization server

Configure the AS first. It has to accept `resource=<your MCP URL>` and mint
tokens whose `aud` equals it, or the client will finish the whole OAuth flow and
never send the token it just got. The ordered steps are in
[Point your authorization server at it](../../packages/mcp-authz/README.md#point-your-authorization-server-at-it).

```bash
cp .env.example .env
# fill in OAuth + MCP_PUBLIC_URL; optionally set MCP_POLICY
pnpm build && pnpm start
```

Default port `8200`. Add `https://…/mcp` as a Claude custom connector.
