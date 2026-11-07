import {
  OAuthError,
  OAuthErrorCode,
  type AuthInfo,
  type OAuthMetadata,
  type OAuthTokenVerifier,
} from '@modelcontextprotocol/server';
import type { Provider } from './providers';

/**
 * Puts a provider's sign-in in front of mcp-authz, with no authorization server
 * of your own. For each token, the verifier asks the provider whether it issued
 * the token for this server, then whose it is.
 *
 * A provider with no `issuedHere` needs `allowUnboundTokens: true`, so you opt
 * in by name to accepting any token that provider issued to the person.
 *
 * A verified token is remembered for `cacheMs` (one minute by default), never
 * past its expiry, so a client's burst of requests costs one lookup. A token
 * the provider revokes keeps working until its entry lapses; pass `cacheMs: 0`
 * to ask the provider on every request.
 */
export function providerLogin(
  provider: Provider,
  {
    resourceServerUrl,
    allowUnboundTokens = false,
    cacheMs = 60_000,
  }: { resourceServerUrl: URL; allowUnboundTokens?: boolean; cacheMs?: number },
  { fetch = globalThis.fetch, now = Date.now }: { fetch?: typeof globalThis.fetch; now?: () => number } = {},
): { oauthMetadata: OAuthMetadata; tokenVerifier: OAuthTokenVerifier } {
  if (!provider.issuedHere && !allowUnboundTokens) {
    throw new Error(
      `${provider.name} has no issuedHere check. ` +
        'Pass allowUnboundTokens: true to accept any token it issues to the person.',
    );
  }
  const invalid = (why: string) => new OAuthError(OAuthErrorCode.InvalidToken, why);
  const verified = new Map<string, { info: AuthInfo; until: number }>();

  async function verify(token: string): Promise<AuthInfo> {
    const issued = provider.issuedHere ? await provider.issuedHere(token, fetch) : {};
    if (!issued) throw invalid('Token was not issued for this server.');
    if (issued.expiresAt !== undefined && issued.expiresAt * 1000 <= now())
      throw invalid('Token has expired.');
    const who = await provider.whoIs(token, fetch);
    if (!who) throw invalid(`${provider.name} did not recognise the token.`);
    return {
      token,
      clientId: provider.name,
      scopes: provider.scopes,
      // A provider that does not report expiry gets an hour, the lifetime these
      // providers use. It refuses an expired token at the next lookup.
      expiresAt: issued.expiresAt ?? Math.floor(now() / 1000) + 3600,
      resource: resourceServerUrl,
      // The fields mcp-authz's default identityFromAuth reads.
      extra: {
        issuer: provider.oauthMetadata.issuer,
        sub: who.sub,
        email: who.email,
        emailVerified: who.emailVerified,
        domain: who.domain,
        claims: who.claims,
      },
    };
  }

  return {
    oauthMetadata: provider.oauthMetadata,
    tokenVerifier: {
      async verifyAccessToken(token) {
        const cached = verified.get(token);
        if (cached && cached.until > now()) return cached.info;
        verified.delete(token);
        const info = await verify(token);
        if (cacheMs > 0) {
          // Drop lapsed entries once the map grows, so it tracks live tokens only.
          if (verified.size >= 10_000) {
            for (const [key, entry] of verified) if (entry.until <= now()) verified.delete(key);
          }
          verified.set(token, { info, until: Math.min(now() + cacheMs, info.expiresAt! * 1000) });
        }
        return info;
      },
    },
  };
}
