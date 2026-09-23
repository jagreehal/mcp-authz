import { timingSafeEqual } from 'node:crypto';
import { OAuthError, OAuthErrorCode } from '@modelcontextprotocol/server';
import { createMcpFetch } from 'mcp-authz';
import { docsClient, mailboxClient } from './helpscout';
import { policy } from './policy';
import { buildServer } from './server';

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

/**
 * The caller is an org agent (Claude Tag) holding one static bearer, injected
 * by its egress proxy. No OAuth in front of this server: the verifier is a
 * constant-time compare, and the identity it yields is the one the policy
 * names. Help Scout credentials never leave this process.
 */
export function mcpFromEnv(env: NodeJS.ProcessEnv = process.env) {
  const resourceServerUrl = new URL(required(env, 'MCP_PUBLIC_URL'));
  const key = Buffer.from(required(env, 'MCP_BEARER'));

  return createMcpFetch({
    resourceServerUrl,
    // Required by the type; never followed, because the bearer is static.
    oauthMetadata: {
      issuer: resourceServerUrl.origin,
      authorization_endpoint: `${resourceServerUrl.origin}/unused`,
      token_endpoint: `${resourceServerUrl.origin}/unused`,
      response_types_supported: [],
    },
    tokenVerifier: {
      async verifyAccessToken(token) {
        const presented = Buffer.from(token);
        if (presented.length !== key.length || !timingSafeEqual(presented, key)) {
          throw new OAuthError(OAuthErrorCode.InvalidToken, 'Invalid bearer token');
        }
        // A static key has no expiry; the SDK insists on one, so give it a rolling hour.
        return {
          token,
          clientId: 'claude-tag',
          scopes: ['mcp'],
          expiresAt: Math.floor(Date.now() / 1000) + 3600,
        };
      },
    },
    identityFromAuth: () => ({
      issuer: resourceServerUrl.origin,
      sub: 'claude-tag',
      emailVerified: false,
      claims: {},
    }),
    policy,
    createServer: buildServer(
      docsClient(required(env, 'HELPSCOUT_DOCS_API_KEY')),
      env.HELPSCOUT_APP_ID && env.HELPSCOUT_APP_SECRET
        ? mailboxClient(env.HELPSCOUT_APP_ID, env.HELPSCOUT_APP_SECRET)
        : undefined,
    ),
  });
}
