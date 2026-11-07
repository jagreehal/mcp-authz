# Sign-in example

`createMcpProxy` behind Google, Microsoft, Okta, Clerk or GitHub sign-in. You
run no authorization server. People sign in with an account they already have,
the proxy asks the provider whose token it is, and one policy decides which
tools each person sees.

```
MCP client ──provider's access token──▶ this proxy ──UPSTREAM_TOKEN──▶ upstream MCP server
                                            │
                                            └─ "issued for me?" + "whose is it?" ──▶ provider
```

## Run the test

```bash
pnpm --filter mcp-authz-login-example test
```

The test starts the `emulate` emulator for each provider and
[test-server](../test-server) as the upstream. For each provider it opens the
sign-in page, picks an account, exchanges the code with PKCE, connects as an MCP
client and checks what that person gets:

| Who             | Rule in `src/policy.ts`           | Served                                                                          |
| --------------- | --------------------------------- | ------------------------------------------------------------------------------- |
| `dana@foo.com`  | `domain: 'foo.com'` → reader      | `count_cases`, `get_account`, `get_case`, `search_cases`; a write gets a 403    |
| `alice@foo.com` | `email: 'alice@foo.com'` → editor | the reader's tools plus `transfer_credit` and `update_case`, and the write runs |
| `sam@other.com` | none                              | a 403                                                                           |

All five providers share the policy and the recorded `src/permissions.ts`.
Provider details live in `src/providers.ts`.

## Two questions per token

These providers issue opaque access tokens, so the proxy asks the provider
about each one. Whose is it? Did the provider issue it for this server, as
opposed to another app the same person uses?

| Provider  | Whose is it                       | Issued for this server                                                                    | Covered by     |
| --------- | --------------------------------- | ----------------------------------------------------------------------------------------- | -------------- |
| Okta      | userinfo                          | introspection: `aud` equals this server's URL                                             | the emulator   |
| Google    | userinfo                          | `tokeninfo`: `aud` equals your client ID                                                  | a stubbed test |
| GitHub    | `/user`, primary verified address | `POST /applications/{client_id}/token`                                                    | a stubbed test |
| Microsoft | Graph `/me`, `userPrincipalName`  | opt in with `allowUnboundTokens`, or use Entra tokens for your app ID with `jwksVerifier` | the emulator   |
| Clerk     | userinfo                          | opt in with `allowUnboundTokens`                                                          | the emulator   |

A provider with no `issuedHere` check starts only when you pass
`allowUnboundTokens: true` (`ALLOW_UNBOUND_TOKENS=1`). That flag accepts any
token the provider issues to the person, for any app.

The test sends a forged token to the Google emulator (with `strict_scopes`) and
the Okta emulator, which answer it with a 401. Each emulator gets a fixed port
so it advertises a URL the proxy can reach.

## Run it against a provider

1. Register an OAuth app with the provider for this server alone. Add your MCP
   client's callback as a redirect URI.
2. Record your upstream and give every tool a permission:
   `npx mcp-authz record --upstream "$UPSTREAM_URL" --token "$UPSTREAM_TOKEN" --out src/permissions.ts`
3. Edit `src/policy.ts`.
4. Start the proxy:

```bash
export MCP_PUBLIC_URL=http://localhost:8500/mcp
export PROVIDER=okta                          # google | microsoft | okta | clerk | github
export PROVIDER_URL=https://acme.okta.com     # Okta org or Clerk frontend API; an emulator URL otherwise
export OKTA_AUTH_SERVER_ID=mcp                # an authorization server whose audience is MCP_PUBLIC_URL
export OKTA_CLIENT_AUTH=client_secret_basic   # Okta's default; client_secret_post if the app uses it
export OAUTH_CLIENT_ID=…
export OAUTH_CLIENT_SECRET=…
export UPSTREAM_URL=https://vendor.example.com/mcp
export UPSTREAM_TOKEN=…
pnpm --filter mcp-authz-login-example dev
```

The proxy advertises each provider's scopes in its 401 challenge and its
discovery document: `openid email` for Google, Okta and Clerk, `User.Read` for
Microsoft (Graph `/me`), and `user:email` for GitHub (`/user/emails`).

For Okta, the proxy calls the introspection endpoint as your app. Set
`OKTA_CLIENT_AUTH` to match the app's **Client authentication** setting:
`client_secret_basic` (Okta's default for a web app) or `client_secret_post`.

Enter the client ID and secret in your MCP client's connector settings.
