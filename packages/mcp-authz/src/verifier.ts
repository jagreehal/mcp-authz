import {
  OAuthError,
  OAuthErrorCode,
  type AuthInfo,
  type OAuthTokenVerifier,
} from '@modelcontextprotocol/server';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import type { Identity } from './identity';

/**
 * Token verification, the one thing the SDK deliberately leaves to you.
 *
 * `authInfo` is strictly pass-through in the SDK: it is never derived from
 * request headers, and no token is checked unless we check it. So this file is
 * the security boundary of the whole server.
 *
 * The authorization server is something that already exists (WorkOS, Stytch,
 * Auth0) doing dynamic client registration / CIMD and Google Workspace login.
 * Google cannot play that role itself: it has no DCR/CIMD, and it will not
 * mint a token whose audience is this server.
 */

export type VerifierOptions = {
  /** The AS issuer, e.g. `https://auth.acme.com`. Must match the token's `iss`. */
  issuer: string;
  /** Where the AS publishes its signing keys. */
  jwksUri: string;
  /**
   * This server's public URL. A token minted for a different resource is
   * refused even when its signature is valid (RFC 8707).
   */
  resource: URL;
  /**
   * Restrict to one Google Workspace domain, checked against the `hd` claim
   * the AS passes through. Omit to accept any domain the AS admits.
   */
  allowedDomain?: string;
  /** Claim carrying the verified email. Auth0 and WorkOS both use `email`. */
  emailClaim?: string;
  /** Claim proving the email was verified. Defaults to `email_verified`. */
  emailVerifiedClaim?: string;
  /** Require an explicit `true` verified-email claim. Defaults to true. */
  requireEmailVerified?: boolean;
};

const invalidToken = (message: string) => new OAuthError(OAuthErrorCode.InvalidToken, message);

/**
 * A JWKS-backed verifier. Keys are fetched once and cached by `jose`, which
 * also handles rotation, so a key roll at the AS does not need a redeploy.
 */
export function jwksVerifier(options: VerifierOptions): OAuthTokenVerifier & {
  identityOf: (auth: AuthInfo) => Identity;
} {
  const jwks = createRemoteJWKSet(new URL(options.jwksUri));
  const emailClaim = options.emailClaim ?? 'email';
  const emailVerifiedClaim = options.emailVerifiedClaim ?? 'email_verified';
  // Compared without the hash fragment, per the AuthInfo.resource contract.
  const expectedResource = new URL(options.resource.href).href.split('#')[0]!;

  return {
    async verifyAccessToken(token: string): Promise<AuthInfo> {
      let payload: Record<string, unknown>;
      try {
        // `audience` is the resource-indicator check. Skipping it is the bug
        // that lets a token minted for another service be replayed here.
        const verified = await jwtVerify(token, jwks, {
          issuer: options.issuer,
          audience: expectedResource,
        });
        payload = verified.payload as Record<string, unknown>;
      } catch (error) {
        throw invalidToken(`Token rejected: ${error instanceof Error ? error.message : String(error)}`);
      }

      if (typeof payload.exp !== 'number') {
        throw invalidToken('Token has no `exp` claim.');
      }

      const email = payload[emailClaim];
      if (typeof email !== 'string' || !email) {
        throw invalidToken(`Token carries no '${emailClaim}' claim, so there is no identity to map.`);
      }
      if ((options.requireEmailVerified ?? true) && payload[emailVerifiedClaim] !== true) {
        throw invalidToken(`Token does not prove '${emailClaim}' with '${emailVerifiedClaim}: true'.`);
      }

      const sub = payload.sub;
      if (typeof sub !== 'string' || !sub) {
        throw invalidToken('Token has no `sub` claim, so there is no stable subject to bind to.');
      }

      const domain = typeof payload.hd === 'string' ? payload.hd : undefined;
      if (options.allowedDomain && domain?.toLowerCase() !== options.allowedDomain.toLowerCase()) {
        throw invalidToken(`Token is for ${domain ?? 'an unknown domain'}, not ${options.allowedDomain}.`);
      }

      return {
        token,
        clientId:
          typeof payload.client_id === 'string'
            ? payload.client_id
            : typeof payload.azp === 'string'
              ? payload.azp
              : sub,
        scopes: scopesOf(payload.scope),
        expiresAt: payload.exp,
        resource: options.resource,
        // The whole payload rides along so policy can match on IdP group claims
        // without this file having to know which claim an IdP puts them in.
        extra: {
          issuer: options.issuer,
          sub,
          email,
          emailVerified: options.requireEmailVerified === false || payload[emailVerifiedClaim] === true,
          domain,
          claims: payload,
        },
      };
    },

    identityOf: identityFromAuth,
  };
}

/** Default identity mapper for custom verifiers using `AuthInfo.extra`. */
export function identityFromAuth(auth: AuthInfo): Identity {
  const { issuer, sub, email, emailVerified, domain, claims } = auth.extra ?? {};
  if (typeof issuer !== 'string' || !issuer || typeof sub !== 'string' || !sub) {
    throw invalidToken('Verified token carried no issuer or subject.');
  }
  if (email !== undefined && (typeof email !== 'string' || !email)) {
    throw invalidToken('Verified token carried an invalid email.');
  }
  return {
    issuer,
    sub,
    email: typeof email === 'string' ? email : undefined,
    emailVerified: emailVerified === true,
    domain: typeof domain === 'string' ? domain : undefined,
    claims: isRecord(claims) ? claims : {},
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** OAuth scope is a space-delimited string; some servers send an array anyway. */
function scopesOf(scope: unknown): string[] {
  if (Array.isArray(scope)) return scope.filter((s): s is string => typeof s === 'string');
  if (typeof scope === 'string') return scope.split(' ').filter(Boolean);
  return [];
}
