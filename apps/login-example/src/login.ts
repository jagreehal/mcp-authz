import {
  OAuthError,
  OAuthErrorCode,
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
 */
export function providerLogin(
  provider: Provider,
  { resourceServerUrl, allowUnboundTokens = false }: { resourceServerUrl: URL; allowUnboundTokens?: boolean },
  deps = { fetch: globalThis.fetch },
): { oauthMetadata: OAuthMetadata; tokenVerifier: OAuthTokenVerifier } {
  if (!provider.issuedHere && !allowUnboundTokens) {
    throw new Error(
      `${provider.name} has no issuedHere check. ` +
        'Pass allowUnboundTokens: true to accept any token it issues to the person.',
    );
  }
  const invalid = (why: string) => new OAuthError(OAuthErrorCode.InvalidToken, why);

  return {
    oauthMetadata: provider.oauthMetadata,
    tokenVerifier: {
      async verifyAccessToken(token) {
        if (provider.issuedHere && !(await provider.issuedHere(token, deps.fetch))) {
          throw invalid('Token was not issued for this server.');
        }
        const who = await provider.whoIs(token, deps.fetch);
        if (!who) throw invalid(`${provider.name} did not recognise the token.`);
        return {
          token,
          clientId: provider.name,
          scopes: provider.scopes,
          // One hour, the access-token lifetime these providers use.
          expiresAt: Math.floor(Date.now() / 1000) + 3600,
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
      },
    },
  };
}
