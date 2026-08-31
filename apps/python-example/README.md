# mcp-authz-python-example

A small remote MCP server using `mcp-authz` with the official `mcp` Python SDK
v2. Two tools, `get_case` (read) and `update_case` (write), gated by the policy
at the top of [`server.py`](server.py).

```bash
cd apps/python-example
uv sync
OAUTH_ISSUER=https://auth.acme.com \
OAUTH_JWKS_URI=https://auth.acme.com/.well-known/jwks.json \
MCP_PUBLIC_URL=https://mcp.acme.com/mcp \
uv run python server.py
```

Defaults to `127.0.0.1:8300` when you set nothing, which is enough to watch it
refuse an unauthenticated request.

The authorization server must issue signed access tokens with:

- `aud` equal to `MCP_PUBLIC_URL`
- `iss` equal to `OAUTH_ISSUER`
- `sub`, `email`, `email_verified: true`, `exp`, and the baseline `mcp` scope
- `hd: acme.com` for this example's Workspace restriction

Getting `aud` right means enabling RFC 8707 resource indicators at your AS, not
just adding a claim. The ordered setup is in
[Point your authorization server at it](../../packages/mcp-authz-python/README.md#point-your-authorization-server-at-it).

| Token                          | `tools/list`                    | `update_case`             |
| ------------------------------ | ------------------------------- | ------------------------- |
| `dana@acme.com`                | `get_case`                      | not there to call         |
| `alice@acme.com`               | `get_case`, `update_case`       | works                     |
| `sub: departed-contractor`     | `forbidden/policy_denied`       | `forbidden/policy_denied` |
| any `hd` other than `acme.com` | 401 before the policy ever runs | 401                       |

Matching no rule means holding nothing, and a caller holding nothing is refused
on every method rather than handed an empty listing that explains nothing. The
last row is the verifier rather than the policy: `allowed_domain="acme.com"`
refuses the token outright. Dana's case is different again. She holds a valid
token and a real role, and `update_case` is filtered out of her listing. Calling
the name anyway hits the same permission check.

The SDK serves OAuth Protected Resource Metadata and returns the standard
bearer challenge for missing, invalid, or under-scoped tokens.

The Node example ships a `MCP_DEV_AUTH=1` mode that mints tokens locally, so
reach for [apps/node-example](../node-example/README.md) when you want to see
the behavior without standing up an authorization server first.
