import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { exportJWK, generateKeyPair, importJWK, SignJWT, type JWK } from 'jose';

/**
 * A stand-in authorization server, for local development only.
 *
 * The library refuses to be an authorization server, and this is not one
 * either: there is no login, no consent, no PKCE, no client registration. It
 * mints a signed token and publishes the key to verify it with, which is the
 * only part of an AS this server actually depends on. Everything else in the
 * demo — verification, policy, tool filtering, audit — is the real code path.
 *
 * The key pair is generated on first use and cached in a gitignored file, so
 * the token you mint in one terminal verifies in the other. Nothing secret is
 * committed, and there is no shared demo key for somebody to reuse in anger.
 */

const KEYS_FILE = fileURLToPath(new URL('../.dev-auth.json', import.meta.url));

type DevKeys = { privateJwk: JWK; publicJwk: JWK };

async function devKeys(): Promise<DevKeys> {
  if (existsSync(KEYS_FILE)) return JSON.parse(readFileSync(KEYS_FILE, 'utf8')) as DevKeys;

  const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  const publicJwk = await exportJWK(publicKey);
  for (const jwk of [privateJwk, publicJwk]) {
    jwk.kid = 'dev-key';
    jwk.alg = 'RS256';
  }

  const keys: DevKeys = { privateJwk, publicJwk };
  writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2));
  return keys;
}

/** The OAuth settings a real deployment takes from WorkOS, Auth0 or Stytch. */
export function devAuthEnv(port: number): Record<string, string> {
  const base = `http://localhost:${port}`;
  return {
    MCP_PUBLIC_URL: `${base}/mcp`,
    OAUTH_ISSUER: `${base}/dev-auth`,
    OAUTH_AUTHORIZATION_ENDPOINT: `${base}/dev-auth/authorize`,
    OAUTH_TOKEN_ENDPOINT: `${base}/dev-auth/token`,
    OAUTH_JWKS_URI: `${base}/dev-auth/jwks`,
  };
}

export type MintOptions = {
  email: string;
  port?: number;
  /** Defaults to `auth0|<email>`, so policy rules can match on `sub`. */
  sub?: string;
  /** Space-delimited. `mcp write` by default, so the write tools are callable. */
  scope?: string;
  /** Extra claims, for trying the IdP-group rules. */
  claims?: Record<string, unknown>;
};

export async function mintToken(options: MintOptions): Promise<string> {
  const { email, port = 8200, sub = `auth0|${email}`, scope = 'mcp write', claims = {} } = options;
  const env = devAuthEnv(port);
  const { privateJwk } = await devKeys();

  return (
    new SignJWT({
      ...claims,
      email,
      email_verified: true,
      hd: email.split('@')[1],
      scope,
      client_id: 'dev-cli',
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'dev-key' })
      .setSubject(sub)
      .setIssuer(env.OAUTH_ISSUER!)
      // The audience is the resource indicator. Mint it for anything else and the
      // server refuses the token however well it is signed.
      .setAudience(env.MCP_PUBLIC_URL!)
      .setExpirationTime('8h')
      .sign(await importJWK(privateJwk, 'RS256'))
  );
}

/**
 * Serve the dev JWKS in front of the connector. Only this one route is added;
 * every other path is the real handler, unchanged.
 */
export function withDevAuth(
  fetch: (request: Request) => Promise<Response>,
  port: number,
): (request: Request) => Promise<Response> {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('MCP_DEV_AUTH is a development shortcut and refuses to run in production.');
  }
  const jwksPath = new URL(devAuthEnv(port).OAUTH_JWKS_URI!).pathname;

  return async (request) => {
    if (new URL(request.url).pathname === jwksPath) {
      const { publicJwk } = await devKeys();
      return Response.json({ keys: [publicJwk] });
    }
    return fetch(request);
  };
}
