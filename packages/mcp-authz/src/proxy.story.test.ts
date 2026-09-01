import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createMcpHandler, McpServer, ResourceTemplate } from '@modelcontextprotocol/server';
import { story } from 'executable-stories-vitest';
import { exportJWK, generateKeyPair, SignJWT, type JWK, type KeyObject } from 'jose';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { z } from 'zod';
import { createMcpProxy } from './proxy';
import { definePolicy } from './policy';

const UPSTREAM = new URL('https://upstream.vendor.com/mcp');
const PROXY = new URL('https://mcp.acme.com/mcp');
const ISSUER = 'https://auth.acme.com';

let privateKey: KeyObject;
let publicJwk: JWK;
let restoreFetch: (() => void) | undefined;

beforeAll(async () => {
  const pair = await generateKeyPair('RS256', { extractable: true });
  privateKey = pair.privateKey as KeyObject;
  publicJwk = await exportJWK(pair.publicKey);
  publicJwk.kid = 'proxy-key';
  publicJwk.alg = 'RS256';
});

afterEach(() => {
  restoreFetch?.();
  restoreFetch = undefined;
});

function stubJwks() {
  const real = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request) => {
    if (String(input).includes('/jwks')) {
      return new Response(JSON.stringify({ keys: [publicJwk] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return real(input);
  }) as typeof fetch;
  restoreFetch = () => {
    globalThis.fetch = real;
  };
}

async function token(email: string, overrides: { scope?: string } = {}) {
  return new SignJWT({
    email,
    email_verified: true,
    hd: 'acme.com',
    scope: overrides.scope ?? 'mcp',
    client_id: 'claude',
  })
    .setProtectedHeader({ alg: 'RS256', kid: 'proxy-key' })
    .setSubject(`auth0|${email}`)
    .setIssuer(ISSUER)
    .setAudience(PROXY.href)
    .setExpirationTime('5m')
    .sign(privateKey);
}

const POLICY = definePolicy({
  roles: {
    reader: ['cases:read'],
    lead: ['cases:read', 'cases:write'],
    nobody: [],
  },
  rules: [
    { match: { email: 'dana@acme.com' }, role: 'reader' },
    { match: { email: 'alice@acme.com' }, role: 'lead' },
    { match: { email: 'nobody@acme.com' }, role: 'nobody' },
  ],
});

const PERMISSIONS = {
  search_cases: 'cases:read',
  get_case: 'cases:read',
  update_case: 'cases:write',
  close_run: 'cases:write',
  'prompt:triage': 'cases:read',
  'resource:cases': 'cases:read',
  'resource:case': 'cases:read',
} as const;

function caseTrackerServer(options: { extraTool?: boolean } = {}): McpServer {
  const server = new McpServer(
    { name: 'case-tracker', version: '3.2.0' },
    { capabilities: { tools: {}, prompts: {}, resources: {} } },
  );

  server.registerTool('search_cases', { description: 'Find cases' }, async () => ({
    content: [{ type: 'text' as const, text: 'C1, C2' }],
  }));
  server.registerTool(
    'get_case',
    { description: 'One case', inputSchema: { id: z.string() } },
    async ({ id }) => ({ content: [{ type: 'text' as const, text: `case ${id}` }] }),
  );
  server.registerTool(
    'update_case',
    { description: 'Change a case', inputSchema: { id: z.string() } },
    async ({ id }) => ({ content: [{ type: 'text' as const, text: `updated ${id}` }] }),
  );
  server.registerPrompt('triage', { description: 'Walk a failure' }, () => ({
    messages: [{ role: 'user' as const, content: { type: 'text' as const, text: 'triage it' } }],
  }));
  server.registerResource('cases', 'cases://all', { mimeType: 'text/plain' }, async (uri) => ({
    contents: [{ uri: uri.href, text: 'every case' }],
  }));
  server.registerResource(
    'case',
    new ResourceTemplate('cases://case/{id}', { list: undefined }),
    { mimeType: 'text/plain' },
    async (uri) => ({ contents: [{ uri: uri.href, text: 'one case' }] }),
  );

  if (options.extraTool) {
    server.registerTool('close_run', { description: 'Irreversible' }, async () => ({
      content: [{ type: 'text' as const, text: 'closed' }],
    }));
  }
  return server;
}

async function connect(handler: (request: Request) => Promise<Response>, bearer?: string) {
  const transport = new StreamableHTTPClientTransport(PROXY, {
    fetch: ((url: string | URL, init?: RequestInit) =>
      handler(new Request(String(url), init))) as unknown as typeof fetch,
    ...(bearer ? { authProvider: { token: async () => bearer } } : {}),
  });
  const client = new Client({ name: 'proxy-e2e-client', version: '1.0.0' });
  await client.connect(transport);
  return client;
}

const RESOURCE_URIS = {
  'resource:cases': 'cases://all',
  'resource:case': 'cases://case/{id}',
} as const;

function proxyFixture(options: {
  upstreamFetch?: typeof fetch;
  capabilityScopes?: Record<string, string>;
  permissions?: Record<string, 'cases:read' | 'cases:write'>;
  maxRequestBytes?: number;
  resourceUris?: Record<string, string>;
}) {
  const upstreamHandler = createMcpHandler(() => caseTrackerServer({ extraTool: true }), {
    legacy: 'stateless',
  });
  let upstreamCalls = 0;
  const forwarded: string[] = [];
  const upstreamFetch =
    options.upstreamFetch ??
    ((async (input: string | URL | Request, init?: RequestInit) => {
      upstreamCalls += 1;
      const source = input instanceof Request ? input : new Request(String(input), init);
      const rewritten = new Request(source.url.replace(PROXY.href, UPSTREAM.href), source);
      if (rewritten.method.toUpperCase() === 'POST') forwarded.push(await rewritten.clone().text());
      return upstreamHandler.fetch(rewritten);
    }) as typeof fetch);

  const proxy = createMcpProxy({
    resourceServerUrl: PROXY,
    oauthMetadata: {
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      response_types_supported: ['code'],
    },
    verifier: { jwksUri: `${ISSUER}/jwks` },
    policy: POLICY,
    permissions: options.permissions ?? PERMISSIONS,
    resourceUris: options.resourceUris ?? RESOURCE_URIS,
    ...(options.maxRequestBytes ? { maxRequestBytes: options.maxRequestBytes } : {}),
    ...(options.capabilityScopes ? { capabilityScopes: options.capabilityScopes } : {}),
    upstream: {
      url: UPSTREAM.href,
      bearer: 'service-token',
      fetch: upstreamFetch,
    },
  });

  return { proxy, upstreamCalls: () => upstreamCalls, forwarded };
}

const names = <T extends { name: string }>(list: T[]) => list.map((entry) => entry.name).sort();

const catalogueOf = async (client: Client) => {
  const [tools, prompts, resources, templates] = await Promise.all([
    client.listTools(),
    client.listPrompts(),
    client.listResources(),
    client.listResourceTemplates(),
  ]);
  return {
    tools: names(tools.tools),
    prompts: names(prompts.prompts),
    resources: names(resources.resources),
    resourceTemplates: names(templates.resourceTemplates),
  };
};

const listRequest = async (bearer: string) =>
  new Request(PROXY.href, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${bearer}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'MCP-Protocol-Version': '2026-07-28',
      'Mcp-Method': 'tools/list',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
      params: {
        _meta: {
          'io.modelcontextprotocol/protocolVersion': '2026-07-28',
          'io.modelcontextprotocol/clientCapabilities': {},
        },
      },
    }),
  });

const readRequest = async (bearer: string, uri: string) =>
  new Request(PROXY.href, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${bearer}`,
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      'MCP-Protocol-Version': '2026-07-28',
      'Mcp-Method': 'resources/read',
      'Mcp-Name': uri,
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'resources/read',
      params: {
        uri,
        _meta: {
          'io.modelcontextprotocol/protocolVersion': '2026-07-28',
          'io.modelcontextprotocol/clientCapabilities': {},
        },
      },
    }),
  });

const messageOf = async (call: Promise<unknown>) => {
  try {
    await call;
    return 'no error — the call went through';
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
};

describe('createMcpProxy', () => {
  it('returns 401 before the upstream is contacted when there is no bearer', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'security'], covers: ['src/proxy.ts'] });
    stubJwks();
    const { proxy, upstreamCalls } = proxyFixture({});

    story.when('a client connects with no bearer token');
    const message = await messageOf(connect(proxy));
    story.code({ label: 'What the client got back', content: message, lang: 'text' });

    story.then('the proxy refuses it and the upstream is never called');
    expect(message).not.toBe('no error — the call went through');
    expect(upstreamCalls()).toBe(0);
  });

  it('returns 403 when the policy grants nothing', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'policy'], covers: ['src/proxy.ts', 'src/ladder.ts'] });
    stubJwks();
    const { proxy } = proxyFixture({});

    story.when('someone whose policy role grants no permissions connects');
    const response = await proxy(
      new Request(PROXY.href, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${await token('nobody@acme.com')}`,
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'MCP-Protocol-Version': '2026-07-28',
          'Mcp-Method': 'tools/list',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/list',
          params: { _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28' } },
        }),
      }),
    );

    story.then('the proxy refuses before forwarding');
    expect(response.status).toBe(403);
  });

  it('filters tools/list to what the reader may reach', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'catalogue'], covers: ['src/proxy.ts', 'src/catalogue.ts'] });
    stubJwks();
    const { proxy } = proxyFixture({});
    const client = await connect(proxy, await token('dana@acme.com'));
    const catalogue = await catalogueOf(client);
    story.state({ label: 'Catalogue', value: catalogue });

    story.then('read tools survive and write tools are hidden');
    expect(catalogue.tools).toEqual(['get_case', 'search_cases']);
    await client.close();
  });

  it('forwards a permitted tools/call', async ({ task }) => {
    story.init(task, { tags: ['proxy'], covers: ['src/proxy.ts', 'src/upstream.ts'] });
    stubJwks();
    const { proxy } = proxyFixture({});
    const client = await connect(proxy, await token('dana@acme.com'));

    story.when('the reader calls a read tool');
    const result = await client.callTool({ name: 'get_case', arguments: { id: 'C1' } });
    story.code({
      label: 'get_case C1',
      content: (result.content as { text: string }[])[0]?.text ?? '',
      lang: 'text',
    });

    story.then('the upstream answer comes back through the proxy');
    expect((result.content as { text: string }[])[0]?.text).toBe('case C1');
    await client.close();
  });

  it('refuses a denied tools/call before the upstream runs', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'security'], covers: ['src/proxy.ts', 'src/ladder.ts'] });
    stubJwks();
    const { proxy, upstreamCalls } = proxyFixture({});
    const callsBefore = upstreamCalls();

    story.when('the reader names a write tool without listing first');
    const response = await proxy(
      new Request(PROXY.href, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${await token('dana@acme.com')}`,
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
          'MCP-Protocol-Version': '2026-07-28',
          'Mcp-Method': 'tools/call',
          'Mcp-Name': 'update_case',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: {
            name: 'update_case',
            arguments: { id: 'C1' },
            _meta: {
              'io.modelcontextprotocol/protocolVersion': '2026-07-28',
              'io.modelcontextprotocol/clientCapabilities': {},
            },
          },
        }),
      }),
    );

    story.then('the proxy refuses it and the upstream is never asked for the call');
    expect(response.status).toBe(403);
    expect(upstreamCalls()).toBe(callsBefore);
  });

  it('filters prompts and resources the same way as tools', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'catalogue'], covers: ['src/catalogue.ts'] });
    stubJwks();
    const { proxy } = proxyFixture({});
    const client = await connect(proxy, await token('dana@acme.com'));
    const catalogue = await catalogueOf(client);

    story.then('the reader sees the read catalogue across all four kinds');
    expect(catalogue.prompts).toEqual(['triage']);
    expect(catalogue.resources).toEqual(['cases']);
    expect(catalogue.resourceTemplates).toEqual(['case']);
    await client.close();
  });

  it('returns insufficient_scope when the token lacks a required step-up scope', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'scopes'], covers: ['src/proxy.ts', 'src/ladder.ts'] });
    stubJwks();
    const { proxy } = proxyFixture({
      capabilityScopes: { update_case: 'cases:write' },
    });

    story.when('the lead calls a write tool with only the baseline scope');
    const response = await proxy(
      new Request(PROXY.href, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${await token('alice@acme.com', { scope: 'mcp' })}`,
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
          'MCP-Protocol-Version': '2026-07-28',
          'Mcp-Method': 'tools/call',
          'Mcp-Name': 'update_case',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: {
            name: 'update_case',
            arguments: { id: 'C1' },
            _meta: {
              'io.modelcontextprotocol/protocolVersion': '2026-07-28',
              'io.modelcontextprotocol/clientCapabilities': {},
            },
          },
        }),
      }),
    );
    const body = await response.text();
    story.code({ label: 'What the client got back', content: body, lang: 'text' });

    story.then('the proxy asks for the missing scope instead of forwarding');
    expect(response.status).toBe(403);
    expect(response.headers.get('WWW-Authenticate')).toMatch(/insufficient_scope/);
  });

  it('passes SSE upstream bodies through without parsing them', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'streaming'], covers: ['src/upstream.ts'] });
    stubJwks();
    const sseBody = 'event: message\ndata: {"jsonrpc":"2.0","method":"notifications/progress"}\n\n';
    const { proxy } = proxyFixture({
      upstreamFetch: (async () =>
        new Response(sseBody, {
          status: 200,
          headers: { 'Content-Type': 'text/event-stream' },
        })) as typeof fetch,
    });

    const response = await proxy(
      new Request(PROXY.href, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${await token('dana@acme.com')}`,
          Accept: 'text/event-stream',
        },
      }),
    );

    story.then('the event stream is forwarded unchanged');
    expect(response.headers.get('content-type')).toContain('text/event-stream');
    expect(await response.text()).toBe(sseBody);
  });

  it('refuses to boot when the scope map names an unpriced capability', () => {
    expect(() =>
      createMcpProxy({
        resourceServerUrl: PROXY,
        oauthMetadata: {
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          response_types_supported: ['code'],
        },
        verifier: { jwksUri: `${ISSUER}/jwks` },
        policy: POLICY,
        permissions: PERMISSIONS,
        resourceUris: RESOURCE_URIS,
        capabilityScopes: { ghost_tool: 'mcp' },
        upstream: { url: UPSTREAM.href, bearer: 'service-token' },
      }),
    ).toThrow("Scope map key 'ghost_tool' names no registered capability.");
  });

  it('refuses to boot when a permission value is empty', () => {
    expect(() =>
      createMcpProxy({
        resourceServerUrl: PROXY,
        oauthMetadata: {
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          response_types_supported: ['code'],
        },
        verifier: { jwksUri: `${ISSUER}/jwks` },
        policy: POLICY,
        permissions: { search_cases: '' as 'cases:read' },
        upstream: { url: UPSTREAM.href, bearer: 'service-token' },
      }),
    ).toThrow("permissions['search_cases'] must be a non-empty string.");
  });

  it('filters JSON listing responses from the upstream', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'catalogue'], covers: ['src/proxy.ts'] });
    stubJwks();
    const { proxy } = proxyFixture({
      upstreamFetch: (async () =>
        new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            result: { tools: [{ name: 'search_cases' }, { name: 'update_case' }] },
          }),
          { headers: { 'Content-Type': 'application/json' } },
        )) as typeof fetch,
    });

    const response = await proxy(
      new Request(PROXY.href, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${await token('dana@acme.com')}`,
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'MCP-Protocol-Version': '2026-07-28',
          'Mcp-Method': 'tools/list',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/list',
          params: {
            _meta: {
              'io.modelcontextprotocol/protocolVersion': '2026-07-28',
              'io.modelcontextprotocol/clientCapabilities': {},
            },
          },
        }),
      }),
    );

    const body = (await response.json()) as { result: { tools: { name: string }[] } };
    expect(body.result.tools.map((tool) => tool.name)).toEqual(['search_cases']);
  });

  it('answers health checks with proxy metadata', async () => {
    stubJwks();
    const { proxy } = proxyFixture({});
    const response = await proxy(new Request(new URL('/health', PROXY).href));
    const body = (await response.json()) as { mode: string; upstream?: string };
    expect(body.mode).toBe('proxy');
    expect(body.upstream).toBeUndefined();
  });

  it('refuses an invocation that is not priced in the permission map', async () => {
    stubJwks();
    const { proxy, upstreamCalls } = proxyFixture({
      permissions: {
        search_cases: 'cases:read',
        get_case: 'cases:read',
      },
      resourceUris: {},
    });
    const callsBefore = upstreamCalls();
    const response = await proxy(
      new Request(PROXY.href, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${await token('dana@acme.com')}`,
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
          'MCP-Protocol-Version': '2026-07-28',
          'Mcp-Method': 'tools/call',
          'Mcp-Name': 'update_case',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: {
            name: 'update_case',
            arguments: { id: 'C1' },
            _meta: {
              'io.modelcontextprotocol/protocolVersion': '2026-07-28',
              'io.modelcontextprotocol/clientCapabilities': {},
            },
          },
        }),
      }),
    );
    expect(response.status).toBe(403);
    expect(upstreamCalls()).toBe(callsBefore);
  });

  it('refuses a POST whose routing headers disagree with its body', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'security'], covers: ['src/proxy.ts', 'src/ladder.ts'] });
    stubJwks();
    const { proxy, upstreamCalls } = proxyFixture({});
    const callsBefore = upstreamCalls();

    story.given('a reader who may not write');
    story.when('they label a write call as a harmless listing in the Mcp-Method header');
    const response = await proxy(
      new Request(PROXY.href, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${await token('dana@acme.com')}`,
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
          'MCP-Protocol-Version': '2026-07-28',
          'Mcp-Method': 'tools/list',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: {
            name: 'update_case',
            arguments: { id: 'C9' },
            _meta: {
              'io.modelcontextprotocol/protocolVersion': '2026-07-28',
              'io.modelcontextprotocol/clientCapabilities': {},
            },
          },
        }),
      }),
    );
    story.code({ label: 'What the client got back', content: await response.clone().text(), lang: 'json' });

    story.then('the proxy refuses it rather than trusting the header');
    expect(response.status).toBe(400);
    story.and('the upstream never sees the smuggled call');
    expect(upstreamCalls()).toBe(callsBefore);
  });

  it('authorises a resources/read by URI, template included', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'resources'], covers: ['src/proxy.ts', 'src/ladder.ts'] });
    stubJwks();
    const { proxy } = proxyFixture({});
    const client = await connect(proxy, await token('dana@acme.com'));

    story.when('the reader reads the static resource the catalogue offered her');
    const statik = await client.readResource({ uri: 'cases://all' });
    story.then('the upstream answer comes back');
    expect((statik.contents[0] as { text: string }).text).toBe('every case');

    story.when('she reads one that only a URI template covers');
    const templated = await client.readResource({ uri: 'cases://case/C1' });
    story.then('the template matches and the read is allowed');
    expect((templated.contents[0] as { text: string }).text).toBe('one case');
    await client.close();
  });

  it('refuses a resources/read that no priced URI covers', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'security'], covers: ['src/proxy.ts'] });
    stubJwks();
    const { proxy, forwarded } = proxyFixture({});
    const client = await connect(proxy, await token('dana@acme.com'));

    story.when('the reader names a URI outside every priced resource');
    const message = await messageOf(client.readResource({ uri: 'secrets://payroll' }));
    story.code({ label: 'What the client got back', content: message, lang: 'text' });

    story.then('the proxy refuses it and the upstream never sees the read');
    expect(message).toContain('policy_denied');
    expect(forwarded.some((body) => body.includes('secrets://payroll'))).toBe(false);
    await client.close();
  });

  it('does not put the upstream framing headers on a body it rewrote', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'streaming'], covers: ['src/proxy.ts'] });
    stubJwks();
    const unfiltered = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      result: { tools: [{ name: 'search_cases' }, { name: 'update_case' }] },
    });
    const { proxy } = proxyFixture({
      upstreamFetch: (async () =>
        new Response(unfiltered, {
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': String(unfiltered.length),
            'Content-Encoding': 'gzip',
          },
        })) as typeof fetch,
    });

    const response = await proxy(await listRequest(await token('dana@acme.com')));
    const text = await response.clone().text();
    story.state({
      label: 'Framing',
      value: {
        contentLength: response.headers.get('content-length'),
        contentEncoding: response.headers.get('content-encoding'),
        actualBytes: new TextEncoder().encode(text).length,
      },
    });

    story.then('the stale length and encoding are dropped rather than copied onto the shorter body');
    expect(response.headers.get('content-encoding')).toBeNull();
    const declared = response.headers.get('content-length');
    if (declared !== null) {
      expect(Number(declared)).toBe(new TextEncoder().encode(text).length);
    }
  });

  it('does not forward the caller credentials meant for the proxy', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'security'], covers: ['src/upstream.ts'] });
    stubJwks();
    let seen: Headers | undefined;
    const { proxy } = proxyFixture({
      upstreamFetch: (async (input: string | URL | Request, init?: RequestInit) => {
        seen = (input instanceof Request ? input : new Request(String(input), init)).headers;
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { tools: [] } }), {
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch,
    });

    story.when('a browser-borne request arrives carrying a session cookie');
    const request = await listRequest(await token('dana@acme.com'));
    request.headers.set('Cookie', 'session=super-secret');
    await proxy(request);
    story.state({
      label: 'Upstream saw',
      value: { cookie: seen?.get('cookie'), authorization: seen?.get('authorization') },
    });

    story.then('the upstream gets the service credential and none of the caller cookies');
    expect(seen?.get('cookie')).toBeNull();
    expect(seen?.get('authorization')).toBe('Bearer service-token');
  });

  it('refuses to boot when a priced resource has no URI to match reads against', () => {
    expect(() =>
      createMcpProxy({
        resourceServerUrl: PROXY,
        oauthMetadata: {
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          response_types_supported: ['code'],
        },
        verifier: { jwksUri: `${ISSUER}/jwks` },
        policy: POLICY,
        permissions: { 'resource:cases': 'cases:read' as const },
        upstream: { url: UPSTREAM.href, bearer: 'service-token' },
      }),
    ).toThrow(/resource:cases/);
  });

  it('lets a genuine failure reach the host instead of flattening it to a 500', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'operations'], covers: ['src/proxy.ts'] });
    stubJwks();
    const { proxy } = proxyFixture({
      upstreamFetch: (() => {
        throw new TypeError('upstream DNS exploded');
      }) as typeof fetch,
    });

    story.when('a step fails for a reason that is nobody policy decision');
    const thrown = await proxy(await listRequest(await token('dana@acme.com'))).then(
      () => undefined,
      (error: unknown) => error,
    );
    story.code({
      label: 'What escaped the proxy',
      content: thrown instanceof Error ? `${thrown.name}: ${thrown.message}` : String(thrown),
      lang: 'text',
    });

    story.then('the original error propagates, with its type and message intact');
    story.note(
      'A refusal is a considered answer and is returned. A bug is not, and belongs to whatever ' +
        'runs this process — swallowing it into a 500 would lose the stack that explains it.',
    );
    expect(thrown).toBeInstanceOf(TypeError);
    expect((thrown as Error).message).toBe('upstream DNS exploded');
  });

  it('requires a resource step-up scope, matched by URI against the label it was keyed by', async ({
    task,
  }) => {
    story.init(task, { tags: ['proxy', 'scopes'], covers: ['src/proxy.ts', 'src/scopes.ts'] });
    stubJwks();
    const { proxy } = proxyFixture({ capabilityScopes: { 'resource:case': 'cases:sensitive' } });

    story.when('a reader with only the baseline scope reads a resource priced for step-up');
    const response = await proxy(await readRequest(await token('dana@acme.com'), 'cases://case/C1'));
    story.code({
      label: 'Challenge',
      content: response.headers.get('WWW-Authenticate') ?? '(none)',
      lang: 'text',
    });

    story.then('the proxy asks for the missing scope rather than serving the read');
    story.note(
      'The scope map is keyed by label, and the request carries a URI. Looking one up as the ' +
        'other is a step-up that silently never happens.',
    );
    expect(response.status).toBe(403);
    expect(response.headers.get('WWW-Authenticate')).toMatch(/insufficient_scope/);
  });

  it('refuses a URI a privileged template also covers, whatever the map order', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'security'], covers: ['src/ladder.ts'] });
    stubJwks();
    const { proxy, forwarded } = proxyFixture({
      permissions: { 'resource:everything': 'cases:read', 'resource:payroll': 'cases:write' },
      resourceUris: {
        'resource:everything': 'cases://{+rest}',
        'resource:payroll': 'cases://payroll/{id}',
      },
    });

    story.given('a broad readable template listed before a narrow privileged one');
    story.when('a reader reads a URI both of them match');
    const response = await proxy(await readRequest(await token('dana@acme.com'), 'cases://payroll/42'));

    story.then('the proxy refuses, because it cannot know which one the upstream will route to');
    expect(response.status).toBe(403);
    expect(forwarded.some((body) => body.includes('payroll'))).toBe(false);
  });

  it('filters an SSE listing whatever shape the event framing takes', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'streaming'], covers: ['src/proxy.ts'] });
    stubJwks();
    const payload = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      result: { tools: [{ name: 'search_cases' }, { name: 'update_case' }] },
    });
    const pretty = JSON.stringify(JSON.parse(payload), null, 2)
      .split('\n')
      .map((line) => `data:${line}`)
      .join('\n');
    const { proxy } = proxyFixture({
      // `data:` needs no space after it, and one payload may arrive across
      // several data lines that the client rejoins with newlines.
      upstreamFetch: (async () =>
        new Response(`event: message\n${pretty}\n\n`, {
          headers: { 'Content-Type': 'text/event-stream' },
        })) as typeof fetch,
    });

    const body = await (await proxy(await listRequest(await token('dana@acme.com')))).text();
    story.code({ label: 'What reached the client', content: body, lang: 'text' });

    story.then('the write tool is gone from the stream, not merely from the JSON shape');
    expect(body).toContain('search_cases');
    expect(body).not.toContain('update_case');
  });

  it('refuses a listing it cannot read rather than passing it through', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'security'], covers: ['src/proxy.ts'] });
    stubJwks();
    const { proxy } = proxyFixture({
      upstreamFetch: (async () =>
        new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            result: { tools: [{ name: 'search_cases' }, { name: 'update_case' }] },
          }),
          { headers: { 'Content-Type': 'text/plain' } },
        )) as typeof fetch,
    });

    story.when('the upstream answers a listing in a content type the proxy cannot filter');
    const response = await proxy(await listRequest(await token('dana@acme.com')));
    const body = await response.text();
    story.code({ label: 'What reached the client', content: body.slice(0, 200), lang: 'text' });

    story.then('the catalogue is withheld rather than served unfiltered');
    story.note('Failing open here would hand every caller the full catalogue on a content-type change.');
    expect(body).not.toContain('update_case');
  });

  it('delivers a filtered event before the upstream stream has finished', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'streaming'], covers: ['src/proxy.ts'] });
    stubJwks();
    const encoder = new TextEncoder();
    let release: (() => void) | undefined;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });

    const { proxy } = proxyFixture({
      upstreamFetch: (async () =>
        new Response(
          new ReadableStream<Uint8Array>({
            async start(controller) {
              controller.enqueue(
                encoder.encode(
                  `data: ${JSON.stringify({
                    jsonrpc: '2.0',
                    id: 1,
                    result: { tools: [{ name: 'search_cases' }, { name: 'update_case' }] },
                  })}\n\n`,
                ),
              );
              // The upstream keeps the stream open. A proxy that buffers to EOF
              // never hands this first event on.
              await held;
              controller.close();
            },
          }),
          { headers: { 'Content-Type': 'text/event-stream' } },
        )) as typeof fetch,
    });

    story.when('the upstream sends one event and then holds the connection open');
    const response = await proxy(await listRequest(await token('dana@acme.com')));
    const reader = response.body!.getReader();
    const first = await reader.read();
    const text = new TextDecoder().decode(first.value);
    story.code({ label: 'First event through', content: text, lang: 'text' });

    story.then('the filtered event arrives while the stream is still open');
    expect(text).toContain('search_cases');
    story.and('the write tool never appears in it');
    expect(text).not.toContain('update_case');

    release!();
    await reader.cancel();
  }, 20_000);

  it('refuses to boot on two scope keys that name the same tool', () => {
    expect(() =>
      createMcpProxy({
        resourceServerUrl: PROXY,
        oauthMetadata: {
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          response_types_supported: ['code'],
        },
        verifier: { jwksUri: `${ISSUER}/jwks` },
        policy: POLICY,
        permissions: PERMISSIONS,
        resourceUris: RESOURCE_URIS,
        capabilityScopes: { update_case: 'cases:write', 'tool:update_case': 'cases:admin' },
        upstream: { url: UPSTREAM.href, bearer: 'service-token' },
      }),
    ).toThrow(/more than once/);
  });

  it('filters an SSE listing framed with bare carriage returns and a byte-order mark', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'streaming'], covers: ['src/proxy.ts'] });
    stubJwks();
    const payload = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      result: { tools: [{ name: 'search_cases' }, { name: 'update_case' }] },
    });
    const { proxy } = proxyFixture({
      // A lone CR is a valid SSE line terminator, and a stream may open with a
      // UTF-8 BOM. Either one turns a `data:` field into an unrecognised one.
      upstreamFetch: (async () =>
        new Response(`\uFEFFevent: message\rdata: ${payload}\r\r`, {
          headers: { 'Content-Type': 'text/event-stream' },
        })) as typeof fetch,
    });

    const body = await (await proxy(await listRequest(await token('dana@acme.com')))).text();
    story.code({ label: 'What reached the client', content: body, lang: 'text' });

    story.then('the catalogue is filtered rather than passed through unread');
    expect(body).toContain('search_cases');
    expect(body).not.toContain('update_case');
  });

  it('refuses an SSE event that never ends rather than growing to hold it', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'security'], covers: ['src/proxy.ts'] });
    stubJwks();
    const { proxy } = proxyFixture({
      maxRequestBytes: 512,
      upstreamFetch: (async () =>
        new Response(
          new ReadableStream<Uint8Array>({
            // Never terminates the event. A proxy that waits for the blank line
            // holds every byte of this.
            pull(controller) {
              controller.enqueue(new TextEncoder().encode(`data: ${'x'.repeat(256)}`));
            },
          }),
          { headers: { 'Content-Type': 'text/event-stream' } },
        )) as typeof fetch,
    });

    story.when('an upstream sends an event with no terminator, larger than the cap');
    const body = await (await proxy(await listRequest(await token('dana@acme.com')))).text();
    story.code({ label: 'What reached the client', content: body.slice(0, 200), lang: 'text' });

    story.then('the proxy stops rather than buffering whatever the upstream sends');
    story.note('Otherwise a broken or hostile upstream decides how much memory this process spends.');
    expect(body).not.toContain('xxxx');
    expect(body).toContain('could not be filtered');
  }, 20_000);

  it('filters an SSE listing whose two line endings differ from each other', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'streaming'], covers: ['src/proxy.ts'] });
    stubJwks();
    const payload = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      result: { tools: [{ name: 'search_cases' }, { name: 'update_case' }] },
    });
    let release: (() => void) | undefined;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const { proxy } = proxyFixture({
      // An event ends on any two line terminators, and nothing says they have to
      // match: LF then CRLF is as valid as CRLF twice. The stream then stays
      // open, so an unrecognised boundary shows up as silence rather than as a
      // stream that happens to end and gets rescued on flush.
      upstreamFetch: (async () =>
        new Response(
          new ReadableStream<Uint8Array>({
            async start(controller) {
              controller.enqueue(new TextEncoder().encode(`event: message\ndata: ${payload}\n\r\n`));
              await held;
              controller.close();
            },
          }),
          { headers: { 'Content-Type': 'text/event-stream' } },
        )) as typeof fetch,
    });

    const response = await proxy(await listRequest(await token('dana@acme.com')));
    const reader = response.body!.getReader();
    const body = new TextDecoder().decode((await reader.read()).value);
    story.code({ label: 'What reached the client', content: body, lang: 'text' });

    story.then('the boundary is recognised and the catalogue filtered, without waiting for EOF');
    expect(body).toContain('search_cases');
    expect(body).not.toContain('update_case');

    release!();
    await reader.cancel();
  }, 20_000);

  it('refuses an oversized event whether or not its terminator shares a chunk', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'security'], covers: ['src/proxy.ts'] });
    stubJwks();
    const payload = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      result: { tools: [{ name: 'search_cases', description: 'p'.repeat(2048) }] },
    });
    const { proxy } = proxyFixture({
      maxRequestBytes: 512,
      // Terminated, well-formed, and over the cap — arriving whole in one chunk.
      upstreamFetch: (async () =>
        new Response(`event: message\ndata: ${payload}\n\n`, {
          headers: { 'Content-Type': 'text/event-stream' },
        })) as typeof fetch,
    });

    const body = await (await proxy(await listRequest(await token('dana@acme.com')))).text();
    story.code({ label: 'What reached the client', content: body.slice(0, 200), lang: 'text' });

    story.then('the cap holds regardless of how the transport happened to split it');
    story.note('A limit that depends on chunk boundaries is a limit an upstream can choose to miss.');
    expect(body).not.toContain('pppp');
    expect(body).toContain('could not be filtered');
  });

  it('answers an unfilterable event under the id the client is waiting on', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'streaming'], covers: ['src/proxy.ts'] });
    stubJwks();
    const { proxy } = proxyFixture({
      upstreamFetch: (async () =>
        new Response('event: message\ndata: not json at all\n\n', {
          headers: { 'Content-Type': 'text/event-stream' },
        })) as typeof fetch,
    });

    story.when('the upstream sends an event the proxy cannot read');
    const body = await (await proxy(await listRequest(await token('dana@acme.com')))).text();
    const emitted = JSON.parse(body.slice(body.indexOf('data: ') + 6).split('\n')[0] ?? '{}') as {
      id: unknown;
    };
    story.state({ label: 'Error envelope', value: emitted });

    story.then('the error carries the request id, so the caller stops waiting on it');
    story.note(
      'An error with id null matches no pending request. A client that ignores it leaves the ' +
        'original listing outstanding for as long as the stream stays open.',
    );
    expect(emitted.id).toBe(1);
  });

  it('refuses a JSON catalogue larger than the cap instead of buffering it', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'security'], covers: ['src/proxy.ts'] });
    stubJwks();
    const huge = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      result: { tools: [{ name: 'search_cases', description: 'p'.repeat(4096) }] },
    });
    const { proxy } = proxyFixture({
      maxRequestBytes: 512,
      upstreamFetch: (async () =>
        new Response(huge, { headers: { 'Content-Type': 'application/json' } })) as typeof fetch,
    });

    story.when('the upstream answers a listing with a body far over the cap');
    const response = await proxy(await listRequest(await token('dana@acme.com')));
    const body = await response.text();
    story.code({ label: 'What reached the client', content: body.slice(0, 200), lang: 'text' });

    story.then('the cap applies to what comes back, not only to what goes out');
    story.note('It is advertised as bounding a message in either direction, so it has to.');
    expect(body).not.toContain('pppp');
    expect(body).toContain('could not be filtered');
  });

  it('measures the event cap in bytes, not in UTF-16 units', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'security'], covers: ['src/proxy.ts'] });
    stubJwks();
    // 400 UTF-16 units, three bytes each: comfortably under a 700-unit reading
    // of the cap and comfortably over a 700-byte one.
    const payload = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      result: { tools: [{ name: 'search_cases', description: '日'.repeat(400) }] },
    });
    expect(payload.length).toBeLessThan(700);
    expect(new TextEncoder().encode(payload).length).toBeGreaterThan(700);

    const { proxy } = proxyFixture({
      maxRequestBytes: 700,
      upstreamFetch: (async () =>
        new Response(`event: message\ndata: ${payload}\n\n`, {
          headers: { 'Content-Type': 'text/event-stream' },
        })) as typeof fetch,
    });

    const body = await (await proxy(await listRequest(await token('dana@acme.com')))).text();
    story.code({ label: 'What reached the client', content: body.slice(0, 200), lang: 'text' });

    story.then('a cap in bytes is enforced in bytes, whatever alphabet the content is in');
    story.note('Otherwise the advertised limit is three times larger for anyone not writing ASCII.');
    expect(body).toContain('could not be filtered');
  });

  it('finds an event boundary split across two chunks', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'streaming'], covers: ['src/proxy.ts'] });
    stubJwks();
    const payload = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      result: { tools: [{ name: 'search_cases' }, { name: 'update_case' }] },
    });
    const encoder = new TextEncoder();
    let release: (() => void) | undefined;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const { proxy } = proxyFixture({
      // The terminator arrives one character at a time, so a scan that only
      // looks at new bytes has to look far enough back to still see it.
      upstreamFetch: (async () =>
        new Response(
          new ReadableStream<Uint8Array>({
            async start(controller) {
              controller.enqueue(encoder.encode(`event: message\ndata: ${payload}\r`));
              controller.enqueue(encoder.encode('\n'));
              controller.enqueue(encoder.encode('\r'));
              controller.enqueue(encoder.encode('\n'));
              await held;
              controller.close();
            },
          }),
          { headers: { 'Content-Type': 'text/event-stream' } },
        )) as typeof fetch,
    });

    const response = await proxy(await listRequest(await token('dana@acme.com')));
    const reader = response.body!.getReader();
    const body = new TextDecoder().decode((await reader.read()).value);
    story.code({ label: 'What reached the client', content: body, lang: 'text' });

    story.then('the event is recognised and filtered without waiting for the stream to end');
    expect(body).toContain('search_cases');
    expect(body).not.toContain('update_case');

    release!();
    await reader.cancel();
  }, 20_000);

  it('counts bytes correctly when multibyte characters straddle chunks', async ({ task }) => {
    story.init(task, { tags: ['proxy', 'streaming'], covers: ['src/proxy.ts'] });
    stubJwks();
    const payload = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      result: { tools: [{ name: 'search_cases', description: '日'.repeat(400) }] },
    });
    const raw = new TextEncoder().encode(`event: message\ndata: ${payload}\n\n`);
    const { proxy } = proxyFixture({
      maxRequestBytes: 700,
      // Split mid-character, so a decoder that does not carry state across
      // chunks would mis-measure and mis-read this.
      upstreamFetch: (async () =>
        new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              for (let at = 0; at < raw.length; at += 37) controller.enqueue(raw.slice(at, at + 37));
              controller.close();
            },
          }),
          { headers: { 'Content-Type': 'text/event-stream' } },
        )) as typeof fetch,
    });

    const body = await (await proxy(await listRequest(await token('dana@acme.com')))).text();
    story.then('the byte cap still refuses it, counted over the reassembled event');
    expect(body).toContain('could not be filtered');
  }, 20_000);
});
