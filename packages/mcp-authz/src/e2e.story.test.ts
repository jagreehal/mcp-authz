import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { McpServer, ResourceTemplate } from '@modelcontextprotocol/server';
import { story } from 'executable-stories-vitest';
import { exportJWK, generateKeyPair, SignJWT, type JWK, type KeyObject } from 'jose';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { z } from 'zod';
import { createMcpFetch } from './handler';
import { gate } from './gate';
import { definePolicy } from './policy';
import { recordCapabilities } from './testing';
import { authz } from './tools';

/**
 * The whole stack, driven by a real MCP client.
 *
 * `mcp.story.test.ts` proves the wire format by building JSON-RPC envelopes by
 * hand: precise, and blind to whatever a client actually does with the answer.
 * Nothing there imports a client, so "the tool is absent from `tools/list`" was
 * only ever checked against our own parse of our own response.
 *
 * Here a real `Client` speaks real Streamable HTTP — negotiation, framing, SSE,
 * the bearer header — to the real resource-server handler, over a signed token
 * verified against a real JWKS. The transport's `fetch` is the handler, so no
 * port is bound, and nothing else is faked.
 *
 * The server under test is deliberately not a stub with one tool on it. It has
 * the shape a published MCP server has — tools, a prompt, a static resource and
 * a resource template — because the parts of a catalogue people forget to gate
 * are the last three.
 */

const RESOURCE = new URL('https://mcp.acme.com/mcp');
const ISSUER = 'https://auth.acme.com';

let privateKey: KeyObject;
let publicJwk: JWK;
let restoreFetch: (() => void) | undefined;

beforeAll(async () => {
  const pair = await generateKeyPair('RS256', { extractable: true });
  privateKey = pair.privateKey as KeyObject;
  publicJwk = await exportJWK(pair.publicKey);
  publicJwk.kid = 'e2e-key';
  publicJwk.alg = 'RS256';
});

afterEach(() => {
  restoreFetch?.();
  restoreFetch = undefined;
});

/**
 * Only the JWKS route. The MCP traffic goes through the transport's own `fetch`,
 * so a stray call to anything else is a failure rather than a silent pass.
 */
function stubJwks() {
  const real = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request) => {
    if (String(input).includes('/jwks')) {
      return new Response(JSON.stringify({ keys: [publicJwk] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return new Response('unexpected', { status: 502 });
  }) as typeof fetch;
  restoreFetch = () => {
    globalThis.fetch = real;
  };
}

async function token(email: string, overrides: { audience?: string } = {}) {
  return new SignJWT({ email, email_verified: true, hd: 'acme.com', scope: 'mcp', client_id: 'claude' })
    .setProtectedHeader({ alg: 'RS256', kid: 'e2e-key' })
    .setSubject(`auth0|${email}`)
    .setIssuer(ISSUER)
    .setAudience(overrides.audience ?? RESOURCE.href)
    .setExpirationTime('5m')
    .sign(privateKey);
}

const POLICY = definePolicy({
  roles: {
    reader: ['cases:read'],
    lead: ['cases:read', 'cases:write'],
  },
  rules: [
    { match: { email: 'dana@acme.com' }, role: 'reader' },
    { match: { email: 'alice@acme.com' }, role: 'lead' },
  ],
});

/**
 * What somebody else's published server looks like: it takes options, registers
 * a catalogue of four kinds, and hands back the server it built. The `wrap` hook
 * is the only line in it that knows this library exists.
 */
type TheirOptions = { wrap?: (server: McpServer) => McpServer; extraTool?: boolean };

function caseTrackerServer(options: TheirOptions = {}): McpServer {
  const built = new McpServer(
    { name: 'case-tracker', version: '3.2.0' },
    { capabilities: { tools: {}, prompts: {}, resources: {} } },
  );
  const server = options.wrap ? options.wrap(built) : built;

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

const PERMISSIONS = {
  search_cases: 'cases:read',
  get_case: 'cases:read',
  update_case: 'cases:write',
  close_run: 'cases:write',
  'prompt:triage': 'cases:read',
  'resource:cases': 'cases:read',
  'resource:case': 'cases:read',
} as const;

/** A real client, on a real transport, whose only unusual property is where its fetch goes. */
async function connect(handler: (request: Request) => Promise<Response>, bearer: string) {
  const transport = new StreamableHTTPClientTransport(RESOURCE, {
    fetch: ((url: string | URL, init?: RequestInit) =>
      handler(new Request(String(url), init))) as unknown as typeof fetch,
    authProvider: { token: async () => bearer },
  });
  const client = new Client({ name: 'e2e-client', version: '1.0.0' });
  await client.connect(transport);
  return client;
}

/**
 * `legacy: 'stateless'` is not a relaxation for old software here — it is what
 * the current SDK client needs. It still opens with an `initialize` handshake,
 * and 2026-07-28 removed that (SEP-2567), so every shipping client is a legacy
 * client from this handler's side. The default is `reject`, which is why the
 * compatibility story below exists.
 */
function gatedHandler(options: TheirOptions & { legacy?: 'reject' | 'stateless' } = {}) {
  return createMcpFetch({
    legacy: options.legacy ?? 'stateless',
    resourceServerUrl: RESOURCE,
    oauthMetadata: {
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      response_types_supported: ['code'],
    },
    verifier: { jwksUri: `${ISSUER}/jwks` },
    policy: POLICY,
    permissions: new Map(Object.entries(PERMISSIONS)),
    createServer: (principal) =>
      caseTrackerServer({ ...options, wrap: (server) => gate(server, principal, PERMISSIONS) }),
  });
}

const names = <T extends { name: string }>(list: T[]) => list.map((entry) => entry.name).sort();

/** What a caller can actually reach, as a snapshot the report can diff. */
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

const messageOf = async (call: Promise<unknown>) => {
  try {
    await call;
    return 'no error — the call went through';
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
};

describe('A published server somebody else wrote, gated per person', () => {
  it('gives a reader a catalogue that stops at what she may do', async ({ task }) => {
    story.init(task, { tags: ['e2e', 'gate'], covers: ['src/gate.ts', 'src/handler.ts'] });

    story.given('case-tracker 3.2.0, a server this library did not write', {
      note:
        'The fixture is deliberately not a stub with one tool on it. It registers all four kinds ' +
        'of capability, because the three that are not tools are the ones deployments forget to gate.',
      json: {
        label: 'What the package registers',
        value: {
          tools: ['search_cases', 'get_case', 'update_case'],
          prompts: ['triage'],
          resources: ['cases'],
          resourceTemplates: ['case'],
        },
      },
    });
    stubJwks();

    story.given('a permission map that puts a price on every one of them', {
      json: { label: 'Permission map', value: PERMISSIONS },
      note: 'gate() throws on a registration it cannot find here, so a partial map fails the boot.',
    });
    const handler = gatedHandler();

    story.given('Dana, whom the policy makes a reader', {
      kv: { label: 'Grants', value: 'cases:read' },
      note: 'Her token is signed by the test issuer and verified against a real JWKS, like any other.',
    });

    story.when('she connects with a real MCP client and lists all four kinds');
    story.note(
      'A real Client on a real Streamable HTTP transport, whose fetch is the handler. Framing, ' +
        'negotiation, SSE and the bearer header are the genuine article; no port is bound.',
    );
    const client = await connect(handler, await token('dana@acme.com'));
    const catalogue = await catalogueOf(client);
    story.state({ label: 'Catalogue', value: catalogue });

    story.then('the two read tools are there, and the write tool is not');
    expect(catalogue.tools).toEqual(['get_case', 'search_cases']);

    story.and('the prompt, the resource and the template she may read all survive the gate');
    expect(catalogue.prompts).toEqual(['triage']);
    expect(catalogue.resources).toEqual(['cases']);
    expect(catalogue.resourceTemplates).toEqual(['case']);

    story.and('what she can see, she can actually run');
    const result = await client.callTool({ name: 'get_case', arguments: { id: 'C1' } });
    story.code({
      label: 'get_case C1',
      content: (result.content as { text: string }[])[0]?.text ?? '',
      lang: 'text',
    });
    expect((result.content as { text: string }[])[0]?.text).toBe('case C1');
    await client.close();
  });

  it('refuses the write tool even when the client names it without listing', async ({ task }) => {
    story.init(task, { tags: ['e2e', 'gate', 'security'], covers: ['src/gate.ts'] });

    story.given('the same reader, and a client that skips tools/list entirely', {
      note:
        'Absence from the catalogue is a context saving, not a security boundary. A model that ' +
        'guessed the name, or a malicious client that read the docs, never consults the list.',
    });
    stubJwks();
    const client = await connect(gatedHandler(), await token('dana@acme.com'));

    story.when('she calls update_case by name');
    const message = await messageOf(client.callTool({ name: 'update_case', arguments: { id: 'C1' } }));
    story.code({ label: 'What the client got back', content: message, lang: 'text' });

    story.then('the server refuses it, so the hidden entry was never what protected the write');
    await expect(client.callTool({ name: 'update_case', arguments: { id: 'C1' } })).rejects.toThrow();
    await client.close();
  });

  it('widens the same catalogue for a lead, from the same server', async ({ task }) => {
    story.init(task, { tags: ['e2e', 'gate'], covers: ['src/gate.ts', 'src/policy.ts'] });

    story.given('one handler, one permission map, two people', {
      note:
        'Nothing about the server changes between these two connections. The only difference is ' +
        'which token arrives, which is the whole claim this library makes.',
    });
    stubJwks();
    const handler = gatedHandler();

    story.when('the reader connects');
    const readerClient = await connect(handler, await token('dana@acme.com'));
    story.state({ label: 'Catalogue', value: await catalogueOf(readerClient) });
    await readerClient.close();

    story.when('the lead connects to the very same handler');
    const leadClient = await connect(handler, await token('alice@acme.com'));
    const leadCatalogue = await catalogueOf(leadClient);
    story.state({ label: 'Catalogue', value: leadCatalogue });

    story.then('update_case has appeared, and nothing else has');
    expect(leadCatalogue.tools).toEqual(['get_case', 'search_cases', 'update_case']);

    story.and('it runs, so the extra grant is real and not a listing artefact');
    const result = await leadClient.callTool({ name: 'update_case', arguments: { id: 'C9' } });
    expect((result.content as { text: string }[])[0]?.text).toBe('updated C9');
    await leadClient.close();
  });

  it('gates a capability the server only registers on some deployments', async ({ task }) => {
    story.init(task, { tags: ['e2e', 'gate'], covers: ['src/gate.ts'] });

    story.given('the same package with its optional close_run tool switched on', {
      note:
        'A real server registers a different catalogue per configuration — a feature flag, a ' +
        'licence tier, an env var. The map prices every branch, so turning one on cannot quietly ' +
        'widen what a reader sees.',
    });
    stubJwks();
    const handler = gatedHandler({ extraTool: true });

    story.when('the reader and the lead each list tools');
    const readerClient = await connect(handler, await token('dana@acme.com'));
    const readerTools = names((await readerClient.listTools()).tools);
    await readerClient.close();
    const leadClient = await connect(handler, await token('alice@acme.com'));
    const leadTools = names((await leadClient.listTools()).tools);
    story.table({
      label: 'Who sees the optional tool',
      columns: ['Caller', 'Tools'],
      rows: [
        ['Dana (reader)', readerTools.join(', ')],
        ['Alice (lead)', leadTools.join(', ')],
      ],
    });

    story.then('the reader does not see it');
    expect(readerTools).toEqual(['get_case', 'search_cases']);

    story.and('the lead does, because the map priced it as a write');
    expect(leadTools).toContain('close_run');
    await leadClient.close();
  });
});

describe('The same guarantees on the seam you own', () => {
  it('presents an authz-defined server identically to a real client', async ({ task }) => {
    story.init(task, { tags: ['e2e', 'authz'], covers: ['src/tools.ts'] });

    story.given('the same policy, over tools you declared rather than wrapped', {
      note:
        'gate() is for code you cannot change; authz() is for code you wrote. This checks the two ' +
        'seams are indistinguishable from outside — the choice is about whose source you can reach, ' +
        'not about how strong the result is.',
    });
    stubJwks();
    const { tool, server } = authz(POLICY);
    const handler = createMcpFetch({
      resourceServerUrl: RESOURCE,
      oauthMetadata: {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        response_types_supported: ['code'],
      },
      verifier: { jwksUri: `${ISSUER}/jwks` },
      legacy: 'stateless',
      policy: POLICY,
      createServer: (principal) =>
        server(
          [
            tool(
              'get_case',
              { permission: 'cases:read', inputSchema: z.object({ id: z.string() }) },
              async ({ id }) => ({ content: [{ type: 'text' as const, text: `case ${id}` }] }),
            ),
            tool(
              'update_case',
              { permission: 'cases:write', inputSchema: z.object({ id: z.string() }) },
              async () => ({ content: [{ type: 'text' as const, text: 'updated' }] }),
            ),
          ],
          { name: 'ours', version: '1.0.0' },
        )(principal),
    });

    story.when('the same reader lists tools against it');
    const client = await connect(handler, await token('dana@acme.com'));
    const { tools } = await client.listTools();
    story.state({ label: 'Catalogue', value: { tools: names(tools) } });

    story.then('she sees exactly what the gated server showed her');
    expect(names(tools)).toEqual(['get_case']);

    story.and('and the write tool is refused here too');
    await expect(client.callTool({ name: 'update_case', arguments: { id: 'C1' } })).rejects.toThrow();
    await client.close();
  });
});

describe('A client from before this protocol version', () => {
  it('is refused by default, and served when the deployment opts in', async ({ task }) => {
    story.init(task, { tags: ['e2e', 'compatibility'], covers: ['src/handler.ts', 'src/routing.ts'] });

    story.given('an unmodified SDK client, which opens with an initialize handshake', {
      note:
        'Revision 2026-07-28 removed that handshake, and the client shipping today still sends it. ' +
        'So "legacy" here does not mean old software — it means every client you can install now.',
    });
    story.link({
      label: 'SEP-2567 — no initialize handshake',
      url: 'https://modelcontextprotocol.io/specification/2026-07-28',
    });
    stubJwks();
    const bearer = await token('dana@acme.com');

    story.when('it connects to a deployment left on the default setting');
    const refusal = await messageOf(connect(gatedHandler({ legacy: 'reject' }), bearer));
    story.code({ label: 'What the client is told', content: refusal, lang: 'text' });

    story.then("it is turned away, because `legacy: 'reject'` is the default");
    await expect(connect(gatedHandler({ legacy: 'reject' }), bearer)).rejects.toThrow();

    story.and('the refusal names the setting that would serve it');
    story.note(
      'This is the first thing anybody wiring up the library sees go wrong, and the ' +
        'protocol error alone does not say that a setting exists, let alone which one.',
    );
    expect(refusal).toContain("legacy: 'stateless'");

    story.and("the same client is served once the deployment sets `legacy: 'stateless'`");
    const relaxed = await connect(gatedHandler(), bearer);
    expect(names((await relaxed.listTools()).tools)).toEqual(['get_case', 'search_cases']);

    story.but('the gate still holds on that path — an older handshake is not a way around it');
    await expect(relaxed.callTool({ name: 'update_case', arguments: { id: 'C1' } })).rejects.toThrow();
    await relaxed.close();
  });
});

describe('A client that cannot prove who it is', () => {
  it('is turned away before any catalogue exists to filter', async ({ task }) => {
    story.init(task, { tags: ['e2e', 'security'], covers: ['src/handler.ts'] });

    story.given('a token minted for a different resource', {
      json: {
        label: 'Token audience',
        value: { issued_for: 'https://elsewhere.example', this_server: RESOURCE.href },
      },
      note:
        'The audience check is what stops a token issued for another service being replayed here. ' +
        'Everything else in this file is about what a verified caller may reach; this is about not ' +
        'being one.',
    });
    stubJwks();
    const handler = gatedHandler();

    story.when('a client connects with it');
    const message = await messageOf(
      connect(handler, await token('dana@acme.com', { audience: 'https://elsewhere.example' })),
    );
    story.code({ label: 'What the client is told', content: message, lang: 'text' });

    story.then('the connection fails, rather than degrading to an anonymous session');
    await expect(
      connect(handler, await token('dana@acme.com', { audience: 'https://elsewhere.example' })),
    ).rejects.toThrow();
  });
});

describe('Building the map this file gates with', () => {
  it('reads the same capability set the permission map prices', async ({ task }) => {
    story.init(task, { tags: ['e2e', 'gate'], covers: ['src/testing.ts'] });

    story.given('case-tracker with every capability its configuration can register');
    story.note(
      'A catalogue that varies by configuration has to be recorded with the branches on. ' +
        'Record it with close_run switched off and the map is short by exactly the tool ' +
        'most worth pricing.',
    );

    story.when('the capabilities are read off the ungated server');
    const { names } = await recordCapabilities(() => caseTrackerServer({ extraTool: true }));

    story.then('they are precisely the labels PERMISSIONS gives a price to');
    story.note('The two vocabularies are written by different code. This is what keeps them one.');
    expect(names).toEqual(Object.keys(PERMISSIONS).sort());
  });
});
