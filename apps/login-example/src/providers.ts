import type { OAuthMetadata } from '@modelcontextprotocol/server';

/** Who a token belongs to, as the provider vouches for it. */
export type Who = {
  sub: string;
  email: string;
  /** Only a provider-verified address may satisfy an `email` or `domain` rule. */
  emailVerified: boolean;
  domain?: string;
  claims: Record<string, unknown>;
};

type Fetch = typeof globalThis.fetch;

/** A sign-in provider with opaque access tokens, which the provider describes on request. */
export type Provider = {
  name: string;
  oauthMetadata: OAuthMetadata;
  /**
   * What a token must have been granted for `whoIs` to answer. The proxy
   * advertises these, so a client asks the provider for them at sign-in.
   */
  scopes: string[];
  /** Undefined when the provider does not recognise the token. */
  whoIs(token: string, fetch: Fetch): Promise<Who | undefined>;
  /**
   * Whether the provider issued the token for this server, as opposed to
   * another app the same person uses.
   */
  issuedHere?(token: string, fetch: Fetch): Promise<boolean>;
};

const metadata = (issuer: string, authorize: string, token: string, scopes: string[]): OAuthMetadata => ({
  issuer,
  authorization_endpoint: authorize,
  token_endpoint: token,
  response_types_supported: ['code'],
  code_challenge_methods_supported: ['S256'],
  scopes_supported: scopes,
});

async function json<T>(response: Response): Promise<T | undefined> {
  return response.ok ? ((await response.json()) as T) : undefined;
}

const bearer = (token: string) => ({
  headers: { authorization: `Bearer ${token}`, accept: 'application/json' },
});

type Userinfo = { sub?: string; email?: string; email_verified?: boolean; hd?: string };

/** The OIDC userinfo answer most providers give. */
async function oidcUserinfo(url: string, token: string, fetch: Fetch): Promise<Who | undefined> {
  const me = await json<Userinfo>(await fetch(url, bearer(token)));
  if (!me?.sub || !me.email) return undefined;
  return {
    sub: me.sub,
    email: me.email,
    emailVerified: me.email_verified === true,
    domain: me.hd,
    claims: me,
  };
}

/**
 * Google. `issuedHere` asks `tokeninfo` for the token's client ID. Pass
 * `emulator` to use a local Google emulator, which has no `tokeninfo`.
 */
export function google({ clientId, emulator }: { clientId: string; emulator?: string }): Provider {
  const base = emulator ?? 'https://accounts.google.com';
  const userinfo = emulator
    ? `${emulator}/oauth2/v2/userinfo`
    : 'https://openidconnect.googleapis.com/v1/userinfo';
  const scopes = ['openid', 'email'];
  return {
    name: 'google',
    scopes,
    oauthMetadata: metadata(
      base,
      `${base}/o/oauth2/v2/auth`,
      emulator ? `${emulator}/oauth2/token` : 'https://oauth2.googleapis.com/token',
      scopes,
    ),
    whoIs: (token, fetch) => oidcUserinfo(userinfo, token, fetch),
    ...(emulator
      ? {}
      : {
          async issuedHere(token, fetch) {
            const url = `https://oauth2.googleapis.com/tokeninfo?access_token=${encodeURIComponent(token)}`;
            return (await json<{ aud?: string }>(await fetch(url)))?.aud === clientId;
          },
        }),
  };
}

/**
 * Okta, with a custom authorization server whose audience is this server's
 * URL. Introspection returns the token's audience, so `issuedHere` binds the
 * token to the MCP URL, as the library's JWKS verifier does.
 */
export function okta({
  url,
  authServerId = 'default',
  clientId,
  clientSecret,
  clientAuth = 'client_secret_basic',
  resourceServerUrl,
}: {
  url: string;
  authServerId?: string;
  clientId: string;
  clientSecret: string;
  /**
   * How this server authenticates to the introspection endpoint. It must match
   * the client's "Client authentication" setting in Okta, whose default for a
   * web app is `client_secret_basic`.
   */
  clientAuth?: 'client_secret_basic' | 'client_secret_post';
  resourceServerUrl: URL;
}): Provider {
  const base = `${url}/oauth2/${authServerId}`;
  const scopes = ['openid', 'email'];
  // RFC 6749 §2.3.1: form-encode each half, then base64 the pair.
  const basic = `Basic ${btoa(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`)}`;
  return {
    name: 'okta',
    scopes,
    oauthMetadata: metadata(base, `${base}/v1/authorize`, `${base}/v1/token`, scopes),
    whoIs: (token, fetch) => oidcUserinfo(`${base}/v1/userinfo`, token, fetch),
    async issuedHere(token, fetch) {
      const answer = await json<{ active?: boolean; token_type?: string; aud?: string | string[] }>(
        await fetch(`${base}/v1/introspect`, {
          method: 'POST',
          headers: {
            accept: 'application/json',
            ...(clientAuth === 'client_secret_basic' ? { authorization: basic } : {}),
          },
          body: new URLSearchParams({
            token,
            token_type_hint: 'access_token',
            ...(clientAuth === 'client_secret_post'
              ? { client_id: clientId, client_secret: clientSecret }
              : {}),
          }),
        }),
      );
      const audiences = [answer?.aud ?? []].flat();
      // Introspection reports refresh tokens as active too, so check the type.
      return (
        answer?.active === true &&
        answer.token_type === 'Bearer' &&
        audiences.includes(resourceServerUrl.href)
      );
    },
  };
}

/**
 * Microsoft Entra ID. The email comes from Graph's `userPrincipalName`, whose
 * domain the tenant has verified. For an audience check, issue Entra access
 * tokens for your own app ID and use the library's JWKS verifier.
 */
export function microsoft({
  tenant = 'organizations',
  emulator,
}: {
  tenant?: string;
  emulator?: string;
}): Provider {
  const login = emulator ?? `https://login.microsoftonline.com/${tenant}`;
  const graph = emulator ?? 'https://graph.microsoft.com';
  // Graph's /me needs User.Read.
  const scopes = ['User.Read'];
  return {
    name: 'microsoft',
    scopes,
    oauthMetadata: metadata(
      `${login}/v2.0`,
      `${login}/oauth2/v2.0/authorize`,
      `${login}/oauth2/v2.0/token`,
      scopes,
    ),
    async whoIs(token, fetch) {
      const me = await json<{ id?: string; userPrincipalName?: string }>(
        await fetch(`${graph}/v1.0/me`, bearer(token)),
      );
      if (!me?.id || !me.userPrincipalName) return undefined;
      return { sub: me.id, email: me.userPrincipalName, emailVerified: true, claims: me };
    },
  };
}

/** Clerk as an OAuth provider, at your Clerk frontend API URL. */
export function clerk({ url }: { url: string }): Provider {
  const scopes = ['openid', 'email'];
  return {
    name: 'clerk',
    scopes,
    oauthMetadata: metadata(url, `${url}/oauth/authorize`, `${url}/oauth/token`, scopes),
    whoIs: (token, fetch) => oidcUserinfo(`${url}/oauth/userinfo`, token, fetch),
  };
}

/**
 * GitHub. Identity is the numeric user ID, and the email is the primary
 * address with GitHub's verified flag. `issuedHere` asks GitHub whether the
 * token belongs to your OAuth app. Pass `emulator` to use a local emulator.
 */
export function github({
  clientId,
  clientSecret,
  emulator,
}: {
  clientId: string;
  clientSecret: string;
  emulator?: string;
}): Provider {
  const web = emulator ?? 'https://github.com';
  const api = emulator ?? 'https://api.github.com';
  // /user/emails needs user:email.
  const scopes = ['user:email'];
  return {
    name: 'github',
    scopes,
    oauthMetadata: metadata(web, `${web}/login/oauth/authorize`, `${web}/login/oauth/access_token`, scopes),
    async whoIs(token, fetch) {
      const user = await json<{ id?: number; login?: string }>(await fetch(`${api}/user`, bearer(token)));
      const emails = await json<{ email: string; primary: boolean; verified: boolean }[]>(
        await fetch(`${api}/user/emails`, bearer(token)),
      );
      const primary = emails?.find((entry) => entry.primary);
      if (!user?.id || !primary) return undefined;
      return {
        sub: String(user.id),
        email: primary.email,
        emailVerified: primary.verified,
        claims: { login: user.login },
      };
    },
    ...(emulator
      ? {}
      : {
          async issuedHere(token, fetch) {
            const answer = await fetch(`${api}/applications/${clientId}/token`, {
              method: 'POST',
              headers: {
                authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
                accept: 'application/vnd.github+json',
              },
              body: JSON.stringify({ access_token: token }),
            });
            return answer.ok;
          },
        }),
  };
}
