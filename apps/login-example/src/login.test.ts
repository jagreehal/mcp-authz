import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createEmulator, type Emulator, type ServiceName } from 'emulate';
import { listen } from 'mcp-authz-test-server/src/server';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { providerLogin } from './login';
import { clerk, github, google, microsoft, okta, type Provider } from './providers';
import { proxyFor } from './proxy';

/**
 * The same policy behind five sign-in providers, each emulated: a person picks
 * their account on the provider's page, the client exchanges the code with
 * PKCE, and the proxy serves them only what their role grants.
 */

const PROXY = new URL('http://127.0.0.1:8500/mcp');
const CLIENT = { client_id: 'mcp-client', client_secret: 'mcp-secret', name: 'MCP' };
const REDIRECT = 'http://localhost:8080/callback';
const PEOPLE = ['dana@foo.com', 'alice@foo.com', 'sam@other.com'];
const READER = ['count_cases', 'get_account', 'get_case', 'search_cases'];

type Case = {
  service: ServiceName;
  seed: Record<string, unknown>;
  authorize: string;
  provider: (url: string) => Provider;
  /** The emulator answers an unknown bearer with a 401. */
  rejectsForgedTokens: boolean;
  /** The provider's emulator has no `issuedHere` endpoint. */
  unbound: boolean;
  /** The scopes the proxy should advertise for this provider. */
  scopes: string[];
};

const CASES: Case[] = [
  {
    service: 'google',
    scopes: ['openid', 'email'],
    seed: {
      strict_scopes: true,
      users: PEOPLE.map((email) => ({ email })),
      oauth_clients: [{ ...CLIENT, redirect_uris: [REDIRECT] }],
    },
    authorize: '/o/oauth2/v2/auth',
    provider: (url) => google({ clientId: CLIENT.client_id, emulator: url }),
    rejectsForgedTokens: true,
    unbound: true,
  },
  {
    service: 'okta',
    scopes: ['openid', 'email'],
    seed: {
      authorization_servers: [{ id: 'mcp', name: 'MCP', audiences: [PROXY.href] }],
      users: PEOPLE.map((login) => ({ login, email: login })),
      oauth_clients: [
        {
          ...CLIENT,
          redirect_uris: [REDIRECT],
          auth_server_id: 'mcp',
          // Okta's default for a web app, and okta()'s default.
          token_endpoint_auth_method: 'client_secret_basic',
        },
      ],
    },
    authorize: '/oauth2/mcp/v1/authorize',
    provider: (url) =>
      okta({
        url,
        authServerId: 'mcp',
        clientId: CLIENT.client_id,
        clientSecret: CLIENT.client_secret,
        resourceServerUrl: PROXY,
      }),
    rejectsForgedTokens: true,
    unbound: false,
  },
  {
    service: 'microsoft',
    scopes: ['User.Read'],
    seed: {
      users: PEOPLE.map((email) => ({ email })),
      oauth_clients: [{ ...CLIENT, redirect_uris: [REDIRECT] }],
    },
    authorize: '/oauth2/v2.0/authorize',
    provider: (url) => microsoft({ emulator: url }),
    rejectsForgedTokens: false,
    unbound: true,
  },
  {
    service: 'clerk',
    scopes: ['openid', 'email'],
    seed: {
      users: PEOPLE.map((email) => ({ email_addresses: [email] })),
      oauth_applications: [{ ...CLIENT, redirect_uris: [REDIRECT] }],
    },
    authorize: '/oauth/authorize',
    provider: (url) => clerk({ url }),
    rejectsForgedTokens: false,
    unbound: true,
  },
  {
    service: 'github',
    scopes: ['user:email'],
    seed: {
      users: PEOPLE.map((email) => ({ login: email.split('@')[0], email })),
      oauth_apps: [{ ...CLIENT, redirect_uris: [REDIRECT] }],
    },
    authorize: '/login/oauth/authorize',
    provider: (url) =>
      github({ clientId: CLIENT.client_id, clientSecret: CLIENT.client_secret, emulator: url }),
    rejectsForgedTokens: false,
    unbound: true,
  },
];

let upstream: { url: string; close: () => void };
beforeAll(async () => {
  process.env.TOKEN = 'svc';
  upstream = await listen();
});
afterAll(() => {
  upstream.close();
  delete process.env.TOKEN;
});

/** The scope an MCP client asks for: the one the proxy's 401 challenge names. */
async function advertisedScope(proxy: (request: Request) => Promise<Response>): Promise<string> {
  const challenge = (await proxy(new Request(PROXY, { method: 'POST' }))).headers.get('www-authenticate');
  return challenge?.match(/scope="([^"]*)"/)?.[1] ?? '';
}

/** What a browser does: open the provider's page, pick the account, follow the redirect. */
async function signIn(
  emulator: string,
  provider: Provider,
  authorize: string,
  email: string,
  scope: string,
): Promise<string> {
  const verifier = crypto.randomUUID() + crypto.randomUUID();
  const challenge = Buffer.from(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)),
  ).toString('base64url');
  const query = new URLSearchParams({
    client_id: CLIENT.client_id,
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope,
    state: 's',
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });
  const page = await (await fetch(`${emulator}${authorize}?${query}`)).text();
  const form = page
    .split('<form')
    .find((chunk) => chunk.includes(email) || chunk.includes(`>${email.split('@')[0]}<`));
  if (!form) throw new Error(`No account for ${email} on the ${provider.name} sign-in page.`);
  const fields = Object.fromEntries(
    [...form.matchAll(/name="([^"]+)" value="([^"]*)"/g)].map((m) => [m[1]!, m[2]!]),
  );
  const picked = await fetch(new URL(form.match(/action="([^"]+)"/)![1]!, emulator), {
    method: 'POST',
    redirect: 'manual',
    body: new URLSearchParams(fields),
  });
  const code = new URL(picked.headers.get('location')!).searchParams.get('code')!;
  const exchanged = await fetch(provider.oauthMetadata.token_endpoint, {
    method: 'POST',
    headers: { accept: 'application/json' },
    body: new URLSearchParams({
      code,
      client_id: CLIENT.client_id,
      client_secret: CLIENT.client_secret,
      redirect_uri: REDIRECT,
      grant_type: 'authorization_code',
      code_verifier: verifier,
    }),
  });
  return ((await exchanged.json()) as { access_token: string }).access_token;
}

async function toolsFor(proxy: (request: Request) => Promise<Response>, token: string) {
  const transport = new StreamableHTTPClientTransport(PROXY, {
    fetch: ((url: string | URL, init?: RequestInit) => proxy(new Request(String(url), init))) as typeof fetch,
    authProvider: { token: async () => token },
  });
  const client = new Client(
    { name: 'login-example', version: '1.0.0' },
    { versionNegotiation: { mode: { pin: '2026-07-28' } } },
  );
  await client.connect(transport);
  try {
    const names = (await client.listTools()).tools.map((tool) => tool.name).sort();
    const write = await client.callTool({ name: 'update_case', arguments: { id: 'C1', title: 'x' } }).then(
      () => 'ran',
      () => 'refused',
    );
    return { names, write };
  } finally {
    await client.close();
  }
}

let port = 4100;

describe.each(CASES)(
  '$service sign-in',
  ({ service, seed, authorize, provider: make, rejectsForgedTokens, unbound, scopes }) => {
    let emulator: Emulator;
    let provider: Provider;
    let proxy: (request: Request) => Promise<Response>;

    beforeAll(async () => {
      // A fixed port each, so the emulator advertises a reachable URL.
      emulator = await createEmulator({ service, port: port++, seed: { [service]: seed } });
      provider = make(emulator.url);
      proxy = proxyFor(provider, {
        resourceServerUrl: PROXY,
        upstream: { url: upstream.url, bearer: 'svc' },
        allowUnboundTokens: unbound,
      });
    });
    afterAll(() => emulator.close());

    /** Signs in with the scope the proxy advertises, as an MCP client does. */
    const as = async (email: string) =>
      signIn(emulator.url, provider, authorize, email, await advertisedScope(proxy));

    it('asks clients for the scopes the provider needs to say who they are', async () => {
      expect((await advertisedScope(proxy)).split(' ')).toEqual(scopes);
      const answer = await proxy(new Request(new URL('/.well-known/oauth-protected-resource/mcp', PROXY)));
      expect(((await answer.json()) as { scopes_supported: string[] }).scopes_supported).toEqual(scopes);
    });

    it('sends the client to the provider to sign in', async () => {
      expect((await proxy(new Request(PROXY, { method: 'POST' }))).status).toBe(401);
      const answer = await proxy(new Request(new URL('/.well-known/oauth-protected-resource/mcp', PROXY)));
      const { authorization_servers } = (await answer.json()) as { authorization_servers: string[] };
      expect(authorization_servers).toEqual([provider.oauthMetadata.issuer]);
    });

    it('serves a foo.com reader the read tools, and refuses them a write', async () => {
      const { names, write } = await toolsFor(proxy, await as('dana@foo.com'));
      expect(names).toEqual(READER);
      expect(write).toBe('refused');
    });

    it('serves the editor the write tools too', async () => {
      const { names, write } = await toolsFor(proxy, await as('alice@foo.com'));
      expect(names).toEqual([...READER, 'transfer_credit', 'update_case'].sort());
      expect(write).toBe('ran');
    });

    it('refuses someone outside foo.com', async () => {
      await expect(toolsFor(proxy, await as('sam@other.com'))).rejects.toThrow();
    });

    it.runIf(rejectsForgedTokens)('refuses a token the provider never issued', async () => {
      await expect(toolsFor(proxy, 'forged')).rejects.toThrow();
    });
  },
);

describe('audience checks against stubbed providers', () => {
  const stub = (answer: (url: string) => Response) => ({
    fetch: (async (url: string | URL) => answer(String(url))) as typeof fetch,
  });
  const verify = (provider: Provider, fetch: { fetch: typeof globalThis.fetch }) =>
    providerLogin(provider, { resourceServerUrl: PROXY }, fetch).tokenVerifier.verifyAccessToken('t');

  it('refuses a Google token issued to another client', async () => {
    const answer = (aud: string) =>
      stub((url) =>
        url.includes('tokeninfo')
          ? Response.json({ aud })
          : Response.json({ sub: '1', email: 'dana@foo.com', email_verified: true }),
      );
    const provider = google({ clientId: 'mcp-client' });
    await expect(verify(provider, answer('someone-else'))).rejects.toThrow('not issued for this server');
    expect((await verify(provider, answer('mcp-client'))).extra?.email).toBe('dana@foo.com');
  });

  it('refuses a GitHub token that belongs to another OAuth app', async () => {
    const provider = github({ clientId: 'mcp-client', clientSecret: 's' });
    await expect(
      verify(
        provider,
        stub(() => new Response(null, { status: 404 })),
      ),
    ).rejects.toThrow('not issued for this server');
  });

  it('authenticates to Okta introspection with Basic by default, in the body when asked', async () => {
    const sent: { authorization: string | null; body: string }[] = [];
    const record = {
      fetch: (async (url: string | URL, init?: RequestInit) => {
        if (String(url).endsWith('/introspect')) {
          sent.push({
            authorization: new Headers(init?.headers).get('authorization'),
            body: String(init?.body),
          });
          return Response.json({ active: true, token_type: 'Bearer', aud: [PROXY.href] });
        }
        return Response.json({ sub: '1', email: 'dana@foo.com', email_verified: true });
      }) as typeof fetch,
    };
    const options = {
      url: 'https://acme.okta.com',
      clientId: 'mcp client',
      clientSecret: 's:cret',
      resourceServerUrl: PROXY,
    };
    await verify(okta(options), record);
    await verify(okta({ ...options, clientAuth: 'client_secret_post' }), record);

    expect(sent[0]!.authorization).toBe(`Basic ${btoa('mcp%20client:s%3Acret')}`);
    expect(sent[0]!.body).not.toContain('client_secret');
    expect(sent[1]!.authorization).toBeNull();
    expect(new URLSearchParams(sent[1]!.body).get('client_secret')).toBe('s:cret');
  });

  it('will not stand up a provider with no audience check unless told to', () => {
    expect(() =>
      providerLogin(clerk({ url: 'https://clerk.example.com' }), { resourceServerUrl: PROXY }),
    ).toThrow('allowUnboundTokens');
  });
});
