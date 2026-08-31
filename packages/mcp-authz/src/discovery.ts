import type { OAuthMetadata } from '@modelcontextprotocol/server';

/**
 * Fetch the authorization server's own metadata instead of hand-copying it.
 *
 * The five endpoints in `oauthMetadata` are published by every AS worth using,
 * and copying them by hand is where a deployment breaks in a way no error
 * explains: a stale token endpoint looks like a client bug for an afternoon.
 *
 * This is opt-in and never called for you, because it trades a fetch at boot
 * for the config. An AS that is down now stops your deploy rather than only
 * your logins.
 */

/** Where an AS publishes metadata, most specific first (RFC 8414, then OIDC). */
function candidates(issuer: string): string[] {
  const url = new URL(issuer);
  const path = url.pathname === '/' ? '' : url.pathname.replace(/\/$/, '');
  return [
    // RFC 8414 inserts the well-known segment before the issuer path.
    `${url.origin}/.well-known/oauth-authorization-server${path}`,
    // OIDC Discovery appends it instead. Auth0 and Google publish only this one.
    `${url.origin}${path}/.well-known/openid-configuration`,
  ];
}

export type DiscoverOptions = {
  /** Swap in for tests, or to add a timeout or proxy. Defaults to global fetch. */
  fetch?: typeof globalThis.fetch;
};

export async function discoverOAuth(issuer: string, options: DiscoverOptions = {}): Promise<OAuthMetadata> {
  const get = options.fetch ?? globalThis.fetch;
  const tried: string[] = [];

  for (const url of candidates(issuer)) {
    tried.push(url);
    const response = await get(url).catch(() => undefined);
    if (!response?.ok) continue;

    const metadata = (await response.json().catch(() => undefined)) as OAuthMetadata | undefined;
    if (!metadata?.authorization_endpoint || !metadata.token_endpoint) continue;

    // A document claiming a different issuer is either a misconfiguration or
    // somebody else's server, and trusting its endpoints sends users there.
    if (metadata.issuer !== issuer) {
      throw new Error(
        `${url} declares issuer '${metadata.issuer}', not '${issuer}'. ` +
          'Use the issuer exactly as the authorization server writes it.',
      );
    }
    return metadata;
  }

  throw new Error(
    `No OAuth metadata for '${issuer}'. Tried:\n  ${tried.join('\n  ')}\n` +
      'Pass `oauthMetadata` directly if your AS publishes it somewhere else.',
  );
}
