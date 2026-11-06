import { createMcpProxy } from 'mcp-authz/proxy';
import { providerLogin } from './login';
import { DEFINITIONS, PERMISSIONS, RESOURCE_URIS } from './permissions';
import { policy } from './policy';
import { clerk, github, google, microsoft, okta, type Provider } from './providers';

export type ProxyOptions = {
  resourceServerUrl: URL;
  upstream: { url: string; bearer: string };
  allowUnboundTokens?: boolean;
};

/** The upstream's tools, filtered per person, behind whichever provider signs them in. */
export function proxyFor(
  provider: Provider,
  { resourceServerUrl, upstream, allowUnboundTokens }: ProxyOptions,
) {
  return createMcpProxy({
    resourceServerUrl,
    ...providerLogin(provider, { resourceServerUrl, allowUnboundTokens }),
    requiredScopes: provider.scopes,
    policy,
    permissions: PERMISSIONS,
    definitions: DEFINITIONS,
    resourceUris: RESOURCE_URIS,
    upstream,
  });
}

function required(env: Record<string, string | undefined>, name: string): string {
  const value = env[name];
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

/**
 * PROVIDER picks google | microsoft | okta | clerk | github. PROVIDER_URL is
 * the Okta org or Clerk frontend API URL. For the others, it points at a
 * local emulator.
 */
export function providerFromEnv(env: Record<string, string | undefined>, resourceServerUrl: URL): Provider {
  const name = required(env, 'PROVIDER');
  const emulator = env.PROVIDER_URL;
  const clientId = () => required(env, 'OAUTH_CLIENT_ID');
  const clientSecret = () => required(env, 'OAUTH_CLIENT_SECRET');
  switch (name) {
    case 'google':
      return google({ clientId: clientId(), emulator });
    case 'microsoft':
      return microsoft({ tenant: env.MICROSOFT_TENANT, emulator });
    case 'okta':
      return okta({
        url: required(env, 'PROVIDER_URL'),
        authServerId: env.OKTA_AUTH_SERVER_ID,
        clientId: clientId(),
        clientSecret: clientSecret(),
        clientAuth: env.OKTA_CLIENT_AUTH === 'client_secret_post' ? 'client_secret_post' : undefined,
        resourceServerUrl,
      });
    case 'clerk':
      return clerk({ url: required(env, 'PROVIDER_URL') });
    case 'github':
      return github({ clientId: clientId(), clientSecret: clientSecret(), emulator });
    default:
      throw new Error(`PROVIDER must be google, microsoft, okta, clerk or github, not '${name}'.`);
  }
}

export function proxyFromEnv(env: Record<string, string | undefined> = process.env) {
  const resourceServerUrl = new URL(required(env, 'MCP_PUBLIC_URL'));
  return proxyFor(providerFromEnv(env, resourceServerUrl), {
    resourceServerUrl,
    upstream: { url: required(env, 'UPSTREAM_URL'), bearer: required(env, 'UPSTREAM_TOKEN') },
    allowUnboundTokens: env.ALLOW_UNBOUND_TOKENS === '1',
  });
}
