import { createMcpProxy } from 'mcp-authz/proxy';
import { PERMISSIONS, RESOURCE_URIS } from './permissions';
import { policy } from './policy';

function required(env: Record<string, string | undefined>, name: string): string {
  const value = env[name];
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

export function proxyFromEnv(env: Record<string, string | undefined> = process.env) {
  const resourceServerUrl = new URL(required(env, 'MCP_PUBLIC_URL'));
  const issuer = required(env, 'OAUTH_ISSUER');

  return createMcpProxy({
    resourceServerUrl,
    oauthMetadata: {
      issuer,
      authorization_endpoint: required(env, 'OAUTH_AUTHORIZATION_ENDPOINT'),
      token_endpoint: required(env, 'OAUTH_TOKEN_ENDPOINT'),
      response_types_supported: ['code'],
    },
    verifier: {
      jwksUri: required(env, 'OAUTH_JWKS_URI'),
    },
    policy,
    permissions: PERMISSIONS,
    resourceUris: RESOURCE_URIS,
    upstream: {
      url: required(env, 'UPSTREAM_URL'),
      bearer: required(env, 'UPSTREAM_TOKEN'),
    },
  });
}
