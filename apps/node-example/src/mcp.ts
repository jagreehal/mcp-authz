import { createMcpFetch } from 'mcp-authz';
import { policy } from './policy';
import { buildExampleServer } from './server';

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

/**
 * OAuth scopes are a separate axis from permissions and stay that way: scopes
 * are what the client's token is allowed to ask for, permissions are what this
 * person may do. A scope gap is a 403 the client can fix by re-authorising; a
 * permission gap is an administrator's job.
 */
const TOOL_SCOPES: Record<string, string> = {
  whoami: 'mcp',
  get_case: 'mcp',
  update_case: 'write',
};

/** Build the example deployment from an explicit environment. */
export function mcpFromEnv(env: NodeJS.ProcessEnv = process.env) {
  const resourceServerUrl = new URL(required(env, 'MCP_PUBLIC_URL'));
  const issuer = required(env, 'OAUTH_ISSUER');

  return createMcpFetch({
    resourceServerUrl,
    oauthMetadata: {
      issuer,
      authorization_endpoint: required(env, 'OAUTH_AUTHORIZATION_ENDPOINT'),
      token_endpoint: required(env, 'OAUTH_TOKEN_ENDPOINT'),
      registration_endpoint: env.OAUTH_REGISTRATION_ENDPOINT,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
    },
    // issuer and resource default to the two above, so they cannot disagree.
    verifier: {
      jwksUri: required(env, 'OAUTH_JWKS_URI'),
      allowedDomain: env.GOOGLE_WORKSPACE_DOMAIN,
    },
    requiredScopes: ['mcp'],
    toolScopes: TOOL_SCOPES,
    policy,
    createServer: buildExampleServer,
  });
}
