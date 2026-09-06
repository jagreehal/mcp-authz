import { McpServer, ResourceTemplate } from '@modelcontextprotocol/server';
import { story } from 'executable-stories-vitest';
import { exportJWK, generateKeyPair, SignJWT, type JWK, type KeyObject } from 'jose';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { z } from 'zod';
import { AccessDeniedError } from './identity';
import { createMcpFetch, type AuthorizationDecisionEvent } from './handler';
import { createPrincipal, definePermissions, definePolicy, type Principal } from './policy';
import { discoverOAuth } from './discovery';
import { gate } from './gate';
import { authz, type ApprovalRequest, type ApprovalSink, type AuditEvent, type AuditSink } from './tools';
import type { CapabilityScopeMap } from './scopes';

/**
 * Everything the server does over the wire: discovery, the bearer gate, and
 * the refusals. Policy decisions live in `policy.story.test.ts`.
 */

const RESOURCE = new URL('https://mcp.acme.com/mcp');
const ISSUER = 'https://auth.acme.com';

const ACCESS = new Set(['dana@acme.com']);
const REQUEST_META = {
  'io.modelcontextprotocol/protocolVersion': '2026-07-28',
  'io.modelcontextprotocol/clientCapabilities': {},
};

let privateKey: KeyObject;
let publicJwk: JWK;
let restoreFetch: (() => void) | undefined;

beforeAll(async () => {
  const pair = await generateKeyPair('RS256', { extractable: true });
  privateKey = pair.privateKey as KeyObject;
  publicJwk = await exportJWK(pair.publicKey);
  publicJwk.kid = 'test-key';
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
    return new Response('unexpected', { status: 502 });
  }) as typeof fetch;
  restoreFetch = () => {
    globalThis.fetch = real;
  };
}

type TokenOverrides = {
  audience?: string;
  email?: string;
  emailVerified?: boolean;
  hd?: string | null;
  issuer?: string;
  scope?: string;
};

async function token(overrides: TokenOverrides = {}) {
  const hd = overrides.hd === undefined ? 'acme.com' : overrides.hd;
  return new SignJWT({
    email: overrides.email ?? 'dana@acme.com',
    email_verified: overrides.emailVerified ?? true,
    ...(hd === null ? {} : { hd }),
    scope: overrides.scope ?? 'mcp',
    client_id: 'claude',
  })
    .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
    .setSubject(`auth0|${overrides.email ?? 'dana@acme.com'}`)
    .setIssuer(overrides.issuer ?? ISSUER)
    .setAudience(overrides.audience ?? RESOURCE.href)
    .setExpirationTime('5m')
    .sign(privateKey);
}

function stubServer() {
  return new McpServer({ name: 'test', version: '0.0.0' }, { capabilities: { tools: {} } });
}

function server() {
  return createMcpFetch({
    resourceServerUrl: RESOURCE,
    oauthMetadata: {
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      registration_endpoint: `${ISSUER}/register`,
      response_types_supported: ['code'],
    },
    verifier: {
      issuer: ISSUER,
      jwksUri: `${ISSUER}/jwks`,
      resource: RESOURCE,
      allowedDomain: 'acme.com',
    },
    toolScopes: { echo: 'mcp', mutate: 'write' },
    resolve: async (identity) => {
      if (!identity.email || !ACCESS.has(identity.email.toLowerCase())) {
        throw AccessDeniedError.notPermitted(identity.email ?? `${identity.issuer}#${identity.sub}`);
      }
      return { email: identity.email };
    },
    createServer: () => stubServer(),
  });
}

const call = (
  auth?: string,
  headers: Record<string, string> = {},
  message: { method: string; params?: Record<string, unknown> } = { method: 'tools/list', params: {} },
) => {
  const params: Record<string, unknown> = { ...(message.params ?? {}), _meta: REQUEST_META };
  const name =
    typeof params.name === 'string' ? params.name : typeof params.uri === 'string' ? params.uri : undefined;
  return new Request(RESOURCE.href, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      ...(auth ? { Authorization: auth } : {}),
      'MCP-Protocol-Version': '2026-07-28',
      'Mcp-Method': message.method,
      ...(name ? { 'Mcp-Name': name } : {}),
      ...headers,
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, ...message, params }),
  });
};

describe('Connecting Claude through Google', () => {
  it('accepts a custom opaque-token verifier and identity mapper without JWKS', async () => {
    const policy = definePolicy({ roles: { reader: ['cases:read'] }, rules: [{ role: 'reader' }] });
    const fetch = createMcpFetch({
      resourceServerUrl: RESOURCE,
      oauthMetadata: {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        response_types_supported: ['code'],
      },
      tokenVerifier: {
        verifyAccessToken: async (presented) => ({
          token: presented,
          clientId: 'opaque-client',
          scopes: ['mcp'],
          expiresAt: Math.floor(Date.now() / 1000) + 60,
          extra: { opaqueSubject: 'user-1', mail: 'dana@acme.com' },
        }),
      },
      identityFromAuth: (auth) => ({
        issuer: ISSUER,
        sub: String(auth.extra?.opaqueSubject),
        email: String(auth.extra?.mail),
        emailVerified: true,
        claims: auth.extra ?? {},
      }),
      policy,
      createServer: () => stubServer(),
    });
    const body = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
      params: {
        _meta: {
          'io.modelcontextprotocol/protocolVersion': '2026-07-28',
          'io.modelcontextprotocol/clientCapabilities': {},
        },
      },
    };

    const response = await fetch(
      new Request(RESOURCE, {
        method: 'POST',
        headers: {
          Authorization: 'Bearer opaque-token',
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'MCP-Protocol-Version': '2026-07-28',
          'Mcp-Method': 'tools/list',
        },
        body: JSON.stringify(body),
      }),
    );

    expect(response.status).toBe(200);
  });

  it('lets an async authorizer grant permissions and passes rich context to handlers', async () => {
    const catalogue = definePermissions(['cases:read'] as const);
    type Context = { principal: Principal<'cases:read'>; tenant: string };
    const { tool, server } = authz(catalogue, { principal: (context: Context) => context.principal });
    const createServer = server(
      [
        tool('tenant', { permission: 'cases:read' }, async (_args, context) => ({
          content: [{ type: 'text', text: context.tenant }],
        })),
      ],
      { name: 'context-test', version: '1.0.0' },
    );
    const decisions: AuthorizationDecisionEvent[] = [];
    const fetch = createMcpFetch({
      resourceServerUrl: RESOURCE,
      oauthMetadata: {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        response_types_supported: ['code'],
      },
      tokenVerifier: {
        verifyAccessToken: async (presented) => ({
          token: presented,
          clientId: 'client',
          scopes: ['mcp'],
          expiresAt: Math.floor(Date.now() / 1000) + 60,
          extra: {
            issuer: ISSUER,
            sub: 'user-1',
            email: 'dana@acme.com',
            emailVerified: true,
            claims: {},
          },
        }),
      },
      authorize: async (identity) => createPrincipal(identity, ['reader'], ['cases:read']),
      resolve: (_identity, principal) => ({ principal, tenant: 'acme' }),
      onDecision: (event) => decisions.push(event),
      createServer,
    });
    const body = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: {
        _meta: {
          'io.modelcontextprotocol/protocolVersion': '2026-07-28',
          'io.modelcontextprotocol/clientCapabilities': {},
        },
        name: 'tenant',
        arguments: {},
      },
    };

    const response = await fetch(
      new Request(RESOURCE, {
        method: 'POST',
        headers: {
          Authorization: 'Bearer opaque-token',
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'MCP-Protocol-Version': '2026-07-28',
          'Mcp-Method': 'tools/call',
          'Mcp-Name': 'tenant',
        },
        body: JSON.stringify(body),
      }),
    );
    const result = (await response.json()) as { result: { content: { text: string }[] } };

    expect(response.status).toBe(200);
    expect(result.result.content[0]?.text).toBe('acme');
    expect(decisions).toContainEqual(
      expect.objectContaining({
        type: 'mcp_authz.decision.v1',
        decision: 'allow',
        email: 'dana@acme.com',
      }),
    );
  });

  it('authorizes a verified identity that carries no email at all', async () => {
    // An introspected opaque token often proves a subject and nothing else.
    // `Identity.email` is optional and `createPrincipal` allows it to be absent,
    // so the gate must not demand one on the way back out.
    const policy = definePolicy({
      roles: { reader: ['cases:read'] },
      rules: [{ match: { claim: { groups: 'qa' } }, role: 'reader' }],
    });
    const fetch = createMcpFetch({
      resourceServerUrl: RESOURCE,
      oauthMetadata: {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        response_types_supported: ['code'],
      },
      tokenVerifier: {
        verifyAccessToken: async (presented) => ({
          token: presented,
          clientId: 'opaque-client',
          scopes: ['mcp'],
          expiresAt: Math.floor(Date.now() / 1000) + 60,
          extra: { issuer: ISSUER, sub: 'user-1', claims: { groups: ['qa'] } },
        }),
      },
      policy,
      createServer: () => stubServer(),
    });

    const response = await fetch(
      new Request(RESOURCE, {
        method: 'POST',
        headers: {
          Authorization: 'Bearer opaque-token',
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'MCP-Protocol-Version': '2026-07-28',
          'Mcp-Method': 'tools/list',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/list',
          params: { _meta: REQUEST_META },
        }),
      }),
    );

    expect(response.status).toBe(200);
  });

  it('refuses an unpermitted call with a 403 whether or not scopes are configured', async ({ task }) => {
    story.init(task, { tags: ['security', 'audit'], covers: ['src/handler.ts'] });

    story.given('a server whose tools declare permissions, and no scope step-up map');
    const policy = definePolicy({
      roles: { reader: ['cases:read'], editor: ['cases:read', 'cases:write'] },
      rules: [{ match: { email: 'dana@acme.com' }, role: 'reader' }],
    });
    const { tool, server } = authz(policy);
    const createServer = server(
      [tool('update_case', { permission: 'cases:write' }, async () => ({ content: [] }))],
      { name: 'test', version: '1.0.0' },
    );
    const decisions: AuthorizationDecisionEvent[] = [];
    stubJwks();
    const fetch = createMcpFetch({
      resourceServerUrl: RESOURCE,
      oauthMetadata: {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        response_types_supported: ['code'],
      },
      verifier: { jwksUri: `${ISSUER}/jwks` },
      policy,
      onDecision: (event) => decisions.push(event),
      createServer,
    });

    story.when('a reader names the tool it was never shown');
    const response = await fetch(
      new Request(RESOURCE, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${await token()}`,
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'MCP-Protocol-Version': '2026-07-28',
          'Mcp-Method': 'tools/call',
          'Mcp-Name': 'update_case',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { _meta: REQUEST_META, name: 'update_case', arguments: {} },
        }),
      }),
    );

    story.then('it is the same actionable 403 a scope-configured server would give');
    story.note(
      'Non-registration already makes the tool unreachable, but on its own it answers a ' +
        'probe with the SDK’s "unknown tool" and writes no record. The refusal a person ' +
        'has to explain later is worth naming, and worth auditing.',
    );
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: 'forbidden', reason: 'policy_denied' });

    story.and('the denied attempt reaches the decision sink');
    expect(decisions).toContainEqual(
      expect.objectContaining({ decision: 'deny', reason: 'policy_denied', email: 'dana@acme.com' }),
    );
  });

  it('points an unauthenticated caller at the authorization server', async ({ task }) => {
    story.init(task, { tags: ['oauth', 'discovery'], covers: ['src/handler.ts'] });

    story.given('Claude has never seen this server and holds no token');
    stubJwks();

    story.when('it calls a tool');
    const response = await server()(call());

    story.then('it is refused with the challenge that starts the whole flow');
    expect(response.status).toBe(401);

    story.and('the challenge names where to find the resource metadata (RFC 9728)');
    story.note('Without this header Claude has nowhere to begin: it cannot guess the authorization server.');
    expect(response.headers.get('WWW-Authenticate')).toContain('resource_metadata=');
  });

  it('publishes metadata naming this exact host', async ({ task }) => {
    story.init(task, { tags: ['oauth', 'discovery'], covers: ['src/handler.ts'] });

    story.given('a client following the challenge to the metadata document');
    stubJwks();

    story.when('it fetches the protected resource metadata');
    const response = await server()(
      new Request('https://mcp.acme.com/.well-known/oauth-protected-resource/mcp'),
    );

    story.then('the resource is the URL clients actually call');
    story.note(
      'Advertise a different host and a conforming client never attaches its token, so the flow ' +
        'loops forever with a valid token it refuses to use. No error says "wrong host".',
    );
    const body = (await response.json()) as {
      resource: string;
      authorization_servers: string[];
      scopes_supported: string[];
    };
    expect(body.resource).toBe(RESOURCE.href);
    expect(body.authorization_servers).toContain(ISSUER);
    expect(body.scopes_supported).toEqual(expect.arrayContaining(['mcp', 'write']));
  });

  it('refuses a token minted for a different resource', async ({ task }) => {
    story.init(task, { tags: ['oauth', 'security'], covers: ['src/verifier.ts'] });

    story.given('a valid, correctly signed token issued for another service');
    stubJwks();
    const other = await token({ audience: 'https://jira.acme.com/mcp' });

    story.when('it is presented here');
    const response = await server()(call(`Bearer ${other}`));

    story.then('the signature being good is not enough');
    story.note('RFC 8707 audience binding: a token is for one resource, not for any resource.');
    expect(response.status).toBe(401);
  });

  it('refuses an email identity the issuer did not mark as verified', async () => {
    stubJwks();
    const unverified = await token({ emailVerified: false });

    const response = await server()(call(`Bearer ${unverified}`));

    expect(response.status).toBe(401);
  });

  it('refuses someone outside the Workspace domain', async ({ task }) => {
    story.init(task, { tags: ['oauth', 'security'], covers: ['src/verifier.ts'] });

    story.given('a token for a personal Google account rather than the company one');
    stubJwks();
    const outsider = await token({ email: 'someone@gmail.com', hd: null });

    story.when('they call a tool');
    const response = await server()(call(`Bearer ${outsider}`));

    story.then('the domain check refuses them');
    expect(response.status).toBe(401);
  });

  it('answers a permitted-nowhere person with an actionable 403, not an internal error', async ({ task }) => {
    story.init(task, { tags: ['access', 'security'], covers: ['src/handler.ts'] });

    story.given('Leo, who signs in with Google but is not on the access list');
    stubJwks();
    const leo = await token({ email: 'leo@acme.com' });

    story.when('he calls a tool over HTTP');
    const response = await server()(call(`Bearer ${leo}`));

    story.then('he gets a refusal that tells him what to do about it');
    story.note(
      'Resolving inside the MCP factory instead makes this a 500: the SDK owns factory failures, ' +
        'so the reason never reaches the caller. Resolve before handing off.',
    );
    expect(response.status).toBe(403);
    const body = (await response.json()) as { error_description: string };
    expect(body.error_description).toContain('leo@acme.com');
  });

  it('challenges for write when Mcp-Name names a mutating tool', async ({ task }) => {
    story.init(task, { tags: ['oauth', 'scopes'], covers: ['src/scopes.ts', 'src/handler.ts'] });

    story.given('Dana holds only the baseline mcp scope');
    stubJwks();
    const dana = await token({ scope: 'mcp' });

    story.when('she calls a tool that needs write, named on Mcp-Name');
    const response = await server()(
      call(`Bearer ${dana}`, {}, { method: 'tools/call', params: { name: 'mutate', arguments: {} } }),
    );

    story.then('the gate refuses with an actionable insufficient_scope challenge');
    story.note(
      'A tool returning isError cannot set WWW-Authenticate, so the client has nothing to step up to.',
    );
    expect(response.status).toBe(403);
    expect(response.headers.get('WWW-Authenticate')).toMatch(/insufficient_scope/);
  });

  const resolverWithScopes = (options: {
    capabilityScopes?: CapabilityScopeMap;
    requiredScopes?: string[];
    supportedScopes?: string[];
  }) =>
    createMcpFetch({
      resourceServerUrl: RESOURCE,
      oauthMetadata: {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        response_types_supported: ['code'],
      },
      verifier: { jwksUri: `${ISSUER}/jwks` },
      resolve: () => ({}),
      createServer: () => stubServer(),
      ...options,
    });

  it('refuses a scope map that names no registered capability', () => {
    const policy = definePolicy({ roles: { editor: ['cases:write'] }, rules: [{ role: 'editor' }] });
    const { tool, server } = authz(policy);
    const createServer = server(
      [tool('update_case', { permission: 'cases:write' }, async () => ({ content: [] }))],
      { name: 'test', version: '1.0.0' },
    );

    expect(() =>
      createMcpFetch({
        resourceServerUrl: RESOURCE,
        oauthMetadata: {
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          response_types_supported: ['code'],
        },
        verifier: { jwksUri: `${ISSUER}/jwks` },
        policy,
        capabilityScopes: { udpate_case: 'write' },
        createServer,
      }),
    ).toThrow("Scope map key 'udpate_case' names no registered capability");
  });

  it('refuses two scope keys for the same tool', () => {
    expect(() =>
      resolverWithScopes({
        capabilityScopes: { update_case: 'write', 'tool:update_case': 'admin' },
      }),
    ).toThrow("Scope map names tool 'update_case' more than once");
  });

  it('requires a baseline when a declarative scope map can fall back to it', () => {
    expect(() =>
      resolverWithScopes({
        requiredScopes: [],
        capabilityScopes: { update_case: 'write' },
      }),
    ).toThrow('A declarative scope map needs at least one baseline scope');
  });

  it('refuses a capability with no required scope', () => {
    expect(() =>
      resolverWithScopes({
        capabilityScopes: { update_case: [] },
      }),
    ).toThrow("Scope map key 'update_case' needs at least one scope");
  });

  it('refuses an empty scope name', () => {
    expect(() =>
      resolverWithScopes({
        capabilityScopes: { update_case: '' },
      }),
    ).toThrow("Scope map key 'update_case' has an invalid scope");
  });

  it('refuses a scope value containing two space-delimited names', () => {
    expect(() =>
      resolverWithScopes({
        capabilityScopes: { update_case: 'write admin' },
      }),
    ).toThrow("Scope map key 'update_case' has an invalid scope");
  });

  it('refuses an invalid baseline scope', () => {
    expect(() =>
      resolverWithScopes({
        requiredScopes: ['mcp read'],
      }),
    ).toThrow("requiredScopes has an invalid scope: 'mcp read'");
  });

  it('refuses an invalid advertised scope', () => {
    expect(() =>
      resolverWithScopes({
        supportedScopes: ['case read'],
      }),
    ).toThrow("supportedScopes has an invalid scope: 'case read'");
  });
});

describe('Asking a person before a permitted action runs', () => {
  const policy = definePolicy({
    roles: { editor: ['cases:read', 'cases:delete'] },
    rules: [{ match: { domain: 'acme.com' }, role: 'editor' }],
  });
  const build = (
    onApproval: ApprovalSink,
    onAudit?: AuditSink,
    approvalTimeoutMs?: number,
    onAuditError?: (failure: { error: unknown; event: AuditEvent }) => unknown,
  ) => {
    const { tool, server } = authz(policy);
    const createServer = server(
      [
        tool('get_case', { permission: 'cases:read' }, async () => ({ content: [] })),
        tool('fail_case', { permission: 'cases:read' }, async () => {
          throw new Error('handler failed');
        }),
        tool(
          'delete_case',
          {
            permission: 'cases:delete',
            inputSchema: z.object({ id: z.string(), force: z.boolean().default(false) }),
            audit: ({ id }) => `case:${id}`,
            // Only the destructive half of the argument space warrants a person.
            approval: ({ force }) => force,
          },
          async () => ({ content: [{ type: 'text' as const, text: 'deleted' }] }),
        ),
      ],
      { name: 'test', version: '0.0.0', onApproval, onAudit, approvalTimeoutMs, onAuditError },
    );
    stubJwks();
    return createMcpFetch({
      resourceServerUrl: RESOURCE,
      oauthMetadata: {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        response_types_supported: ['code'],
      },
      verifier: { jwksUri: `${ISSUER}/jwks` },
      policy,
      createServer,
    });
  };

  /** Over HTTP, the way a client reaches it — no SDK internals reached into. */
  const callTool = async (fetch: ReturnType<typeof build>, name: string, args: Record<string, unknown>) => {
    const response = await fetch(
      call(
        `Bearer ${await token({ email: 'alice@acme.com' })}`,
        {},
        {
          method: 'tools/call',
          params: { name, arguments: args },
        },
      ),
    );
    return (await response.json()) as {
      result?: { content?: { text: string }[]; isError?: boolean };
      error?: { message: string };
    };
  };

  const errorText = (body: Awaited<ReturnType<typeof callTool>>) =>
    body.error?.message ?? body.result?.content?.map((part) => part.text).join(' ') ?? '';

  it('runs a permitted call only once a named person says yes', async ({ task }) => {
    story.init(task, { tags: ['approval', 'security'], covers: ['src/tools.ts'] });

    story.given('an editor who already holds cases:delete');
    story.note(
      'Approval is not the permission check again. Alice is permitted; the question is ' +
        'whether this particular call should happen, and that is a second person’s to answer.',
    );
    const asked: ApprovalRequest[] = [];
    const audit: AuditEvent[] = [];
    const factory = build(
      (request) => {
        asked.push(request);
        return { approved: true, by: 'sam@acme.com' };
      },
      (event) => void audit.push(event),
    );

    story.when('she deletes with force, which this tool says needs a person');
    const result = await callTool(factory, 'delete_case', { id: 'C1234', force: true });

    story.then('the approver saw who was asking and what it would touch');
    expect(asked).toHaveLength(1);
    expect(asked[0]).toMatchObject({
      email: 'alice@acme.com',
      name: 'delete_case',
      permission: 'cases:delete',
      resource: 'case:C1234',
      arguments: { id: 'C1234', force: true },
    });

    story.and('the action ran');
    expect(result.result?.content?.[0]?.text).toBe('deleted');

    story.and('the audit trail names the approver, not just the caller');
    story.note(
      'One service account downstream, two people upstream. The success event is the only ' +
        'place both of them appear.',
    );
    expect(audit.map((event) => event.phase)).toEqual(['attempt', 'success']);
    expect(audit.at(-1)).toMatchObject({ email: 'alice@acme.com', approvedBy: 'sam@acme.com' });

    story.and('every event says what it is, for a log store that holds both kinds');
    expect(audit.map((event) => event.type)).toEqual(['mcp_authz.audit.v1', 'mcp_authz.audit.v1']);
  });

  it('returns a completed action when the terminal audit write fails', async () => {
    const failed: { error: unknown; event: AuditEvent }[] = [];
    const factory = build(
      () => ({ approved: true, by: 'sam@acme.com' }),
      (event) => {
        if (event.phase === 'success') throw new Error('audit store unavailable');
      },
      undefined,
      (failure) => {
        failed.push(failure);
        throw new Error('audit error reporter unavailable');
      },
    );

    const result = await callTool(factory, 'delete_case', { id: 'C1234', force: true });

    expect(result.result?.content?.[0]?.text).toBe('deleted');
    expect(failed).toHaveLength(1);
    expect(failed[0]?.event).toMatchObject({ phase: 'success', name: 'delete_case' });
    expect(failed[0]?.error).toMatchObject({ message: 'audit store unavailable' });
  });

  it('preserves a handler failure when the failure-audit write also fails', async () => {
    const failed: { error: unknown; event: AuditEvent }[] = [];
    const factory = build(
      () => ({ approved: true, by: 'sam@acme.com' }),
      (event) => {
        if (event.phase === 'failure') throw new Error('audit store unavailable');
      },
      undefined,
      (failure) => void failed.push(failure),
    );

    const result = await callTool(factory, 'fail_case', {});

    expect(errorText(result)).toContain('handler failed');
    expect(failed).toHaveLength(1);
    expect(failed[0]?.event).toMatchObject({ phase: 'failure', name: 'fail_case' });
  });

  it('refuses a runtime approval that does not name the approver', async ({ task }) => {
    story.init(task, { tags: ['approval', 'security'], covers: ['src/tools.ts'] });

    story.given('an untyped approval adapter that accidentally returns yes without a name');
    const audit: AuditEvent[] = [];
    const anonymous = build(
      (() => ({ approved: true })) as unknown as ApprovalSink,
      (event) => void audit.push(event),
    );

    story.when('a destructive call asks that adapter');
    const result = await callTool(anonymous, 'delete_case', { id: 'C1234', force: true });

    story.then('the runtime check fails closed even though TypeScript was bypassed');
    expect(errorText(result)).toMatch('did not name who gave it');
    expect(audit.map((event) => event.phase)).toEqual(['attempt', 'refused']);
    expect(audit.at(-1)).toMatchObject({ decision: 'deny', error: 'approval did not name who gave it' });
  });

  it('refuses when the person says no, and when nobody answers in time', async ({ task }) => {
    story.init(task, { tags: ['approval', 'security'], covers: ['src/tools.ts'] });

    story.given('an approver who declines');
    const audit: AuditEvent[] = [];
    const declined = build(
      () => ({ approved: false, by: 'sam@acme.com', reason: 'not during the freeze' }),
      (event) => void audit.push(event),
    );

    story.when('the call is made');
    story.then('the handler never runs, and the reason reaches the caller');
    expect(errorText(await callTool(declined, 'delete_case', { id: 'C1234', force: true }))).toMatch(
      'not during the freeze',
    );
    expect(audit.map((event) => event.phase)).toEqual(['attempt', 'refused']);
    expect(audit.at(-1)).toMatchObject({ decision: 'deny', approvedBy: 'sam@acme.com' });

    story.and('silence is a refusal too, so an unanswered request cannot hold a connection open');
    story.note(
      'The deadline is what keeps this a library. Nothing has to survive a restart, because ' +
        'a process that dies mid-question takes the open request with it and the action ' +
        'correctly did not happen.',
    );
    const stalled = build(() => new Promise<never>(() => {}), undefined, 20);
    expect(errorText(await callTool(stalled, 'delete_case', { id: 'C1234', force: true }))).toMatch(
      'no answer within',
    );

    story.and('a sink that throws refuses rather than letting the action through');
    const broken = build(() => {
      throw new Error('slack is down');
    });
    expect(errorText(await callTool(broken, 'delete_case', { id: 'C1234', force: true }))).toMatch(
      'slack is down',
    );
  });

  it('measures the wait for a person, so the log shows what a call really cost', async ({ task }) => {
    story.init(task, { tags: ['approval', 'operations'], covers: ['src/tools.ts'] });

    story.given('an approver who takes a moment, as a person does');
    story.note(
      'A duration that stopped at the handler would say a destructive call took a ' +
        'millisecond, when it actually held a connection open while somebody decided.',
    );
    const audit: AuditEvent[] = [];
    const slow = build(
      () => new Promise((resolve) => setTimeout(() => resolve({ approved: true, by: 'sam@acme.com' }), 30)),
      (event) => void audit.push(event),
    );

    story.when('the call is approved');
    await callTool(slow, 'delete_case', { id: 'C1234', force: true });

    story.then('the success event covers the whole wait, not just the handler');
    const [attempt, success] = audit;
    expect(success?.durationMs).toBeGreaterThanOrEqual(25); // timers can fire a hair early

    story.and('the events are stamped in the order they happened');
    expect(Date.parse(success!.at)).toBeGreaterThanOrEqual(Date.parse(attempt!.at));
    expect(new Date(attempt!.at).toISOString()).toBe(attempt!.at);

    story.and('the attempt is recorded before the answer, so a refusal still has a start');
    expect(attempt).toMatchObject({ phase: 'attempt', decision: 'allow' });
    expect(attempt?.approvedBy).toBeUndefined();
  });

  it('asks nobody for the calls that did not ask for a person', async ({ task }) => {
    story.init(task, { tags: ['approval'], covers: ['src/tools.ts'] });

    story.given('the same tool called without force, and a tool that never asks');
    const asked: ApprovalRequest[] = [];
    const factory = build((request) => {
      asked.push(request);
      return { approved: true, by: 'sam@acme.com' };
    });

    story.when('both run');
    await callTool(factory, 'delete_case', { id: 'C1234', force: false });
    await callTool(factory, 'get_case', {});

    story.then('neither interrupted anyone');
    story.note('The predicate reads the arguments, so the cheap path stays as cheap as it was.');
    expect(asked).toHaveLength(0);
  });

  it('asks for a person before a prompt, which is a tool call somebody else composed', async ({ task }) => {
    story.init(task, { tags: ['approval', 'security'], covers: ['src/tools.ts'] });

    story.given('the destructive call reachable through a prompt as well as directly');
    story.note(
      'Gating the tool alone leaves the prompt as a way to reach the same action without ' +
        'a person. A prompt costs what the call it composes costs, approval included.',
    );
    const asked: ApprovalRequest[] = [];
    const { prompt, server } = authz(policy);
    const createServer = server(
      [
        prompt(
          'walk_through_delete',
          { permission: 'cases:delete', argsSchema: z.object({ id: z.string() }), approval: true },
          async () => ({ messages: [] }),
        ),
      ],
      {
        name: 'test',
        version: '0.0.0',
        onApproval: (request) => {
          asked.push(request);
          return { approved: false, by: 'sam@acme.com', reason: 'not through a prompt either' };
        },
      },
    );
    stubJwks();
    const fetch = createMcpFetch({
      resourceServerUrl: RESOURCE,
      oauthMetadata: {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        response_types_supported: ['code'],
      },
      verifier: { jwksUri: `${ISSUER}/jwks` },
      policy,
      createServer,
    });

    story.when('the prompt is fetched');
    const response = await fetch(
      call(
        `Bearer ${await token({ email: 'alice@acme.com' })}`,
        {},
        { method: 'prompts/get', params: { name: 'walk_through_delete', arguments: { id: 'C1234' } } },
      ),
    );

    story.then('the same person was asked, and the same refusal reached the caller');
    expect(asked).toHaveLength(1);
    expect(asked[0]).toMatchObject({ kind: 'prompt', name: 'walk_through_delete' });
    expect(JSON.stringify(await response.json())).toMatch('not through a prompt either');
  });

  it('treats an answer that arrives after the deadline as no answer', async ({ task }) => {
    story.init(task, { tags: ['approval', 'security'], covers: ['src/tools.ts'] });

    story.given('an approver who says yes, forty milliseconds too late');
    story.note(
      'Fail closed. A yes that arrives after the caller has been told no would run an ' +
        'action nobody is still watching, and the audit trail would disagree with itself.',
    );
    const late = build(
      () => new Promise((resolve) => setTimeout(() => resolve({ approved: true, by: 'sam@acme.com' }), 60)),
      undefined,
      20,
    );

    story.when('the call is made');
    const body = await callTool(late, 'delete_case', { id: 'C1234', force: true });

    story.then('the deadline already answered, and the late yes changes nothing');
    expect(errorText(body)).toMatch('no answer within');
  });

  it('refuses to boot when a capability asks for a person and none can be reached', async ({ task }) => {
    story.init(task, { tags: ['approval', 'operations'], covers: ['src/tools.ts'] });

    story.given('a tool declaring approval, and a server built without a sink');
    const { tool, server } = authz(policy);

    story.when('the server is built');
    story.then('it fails at boot rather than at the first destructive call');
    expect(() =>
      server(
        [tool('delete_case', { permission: 'cases:delete', approval: true }, async () => ({ content: [] }))],
        {
          name: 'test',
          version: '0.0.0',
        },
      ),
    ).toThrow('MCP approval is not configured');
  });
});

describe('Gating everything a caller can reach', () => {
  it('hides the prompt and the resource from someone who may only read', async ({ task }) => {
    story.init(task, { tags: ['access', 'security'], covers: ['src/tools.ts'] });

    story.given('a reader, and a prompt that costs the same permission as the write it composes');
    story.note(
      'MCP exposes tools, prompts and resources. Gating tools alone leaves two doors open, ' +
        'and a prompt is a tool call somebody else already wrote.',
    );
    const policy = definePolicy({
      roles: { reader: ['cases:read'], editor: ['cases:read', 'cases:write'] },
      rules: [
        { match: { domain: 'acme.com' }, role: 'reader' },
        { match: { email: 'alice@acme.com' }, role: 'editor' },
      ],
    });
    const { tool, prompt, resource, server } = authz(policy);

    const build = server(
      [
        tool('get_case', { permission: 'cases:read' }, async () => ({ content: [] })),
        prompt('triage_case', { permission: 'cases:write' }, async () => ({ messages: [] })),
        resource('cases', { permission: 'cases:read', uri: 'cases://all' }, async (uri) => ({
          contents: [{ uri: uri.href, text: '[]' }],
        })),
      ],
      { name: 'test', version: '0.0.0' },
    );

    story.when('each of them connects');
    const reader = policy({
      issuer: ISSUER,
      sub: 'u1',
      email: 'dana@acme.com',
      emailVerified: true,
      claims: {},
    });
    const editor = policy({
      issuer: ISSUER,
      sub: 'u2',
      email: 'alice@acme.com',
      emailVerified: true,
      claims: {},
    });

    story.then('the boot-time check counts all three, keyed so a prompt cannot shadow a tool');
    expect([...build.permissions.keys()].sort()).toEqual([
      'get_case',
      'prompt:triage_case',
      'resource:cases',
    ]);

    story.and('each of them gets a server, carrying only what their permissions cover');
    story.note(
      'What the reader is refused is proved over HTTP in the example app, where prompts/list ' +
        'comes back without triage_case.',
    );
    expect(reader.can('cases:write')).toBe(false);
    expect(editor.can('cases:write')).toBe(true);
    expect(build(reader)).toBeDefined();
    expect(build(editor)).toBeDefined();
  });

  it('resolves a concrete resource URI through its protected template', () => {
    const policy = definePolicy({
      roles: { reader: ['cases:read'] },
      rules: [{ role: 'reader' }],
    });
    const { resource, server } = authz(policy);
    const build = server(
      [
        resource('case', { permission: 'cases:read', uri: 'case://{caseId}' }, async (uri) => ({
          contents: [{ uri: uri.href, text: '{}' }],
        })),
      ],
      { name: 'test', version: '0.0.0' },
    );

    expect(build.permissionForRoute('resource', 'case://C1234')).toBe('cases:read');
  });
});

describe('Starting up with a policy that does not match the tools', () => {
  it('refuses to boot rather than serving a tool nobody can reach', async ({ task }) => {
    story.init(task, {
      tags: ['policy', 'operations'],
      covers: ['src/handler.ts', 'src/policy.ts'],
    });

    story.given('a policy whose roles have drifted from the registered tools');
    const policy = definePolicy({
      roles: { lead: ['cases:read'] },
      rules: [{ match: { domain: 'acme.com' }, role: 'lead' }],
    });
    const { tool, server } = authz(policy);
    const createServer = server(
      [
        tool('get_case', { permission: 'cases:read' }, async () => ({ content: [] })),
        // @ts-expect-error no role grants this, which is the point
        tool('delete_case', { permission: 'cases:delete' }, async () => ({ content: [] })),
      ],
      { name: 'test', version: '0.0.0' },
    );

    story.when('the server is constructed');
    story.then('it throws before serving a request, naming both directions of the drift');
    story.note(
      'The compiler already rejects the permission name; this is the same check for a ' +
        'policy loaded from JSON or YAML, where there was never a literal to check.',
    );
    const boot = () =>
      createMcpFetch({
        resourceServerUrl: RESOURCE,
        oauthMetadata: {
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          response_types_supported: ['code'],
        },
        verifier: { issuer: ISSUER, jwksUri: `${ISSUER}/jwks`, resource: RESOURCE },
        policy,
        createServer,
      });

    expect(boot).toThrow('delete_case');
    expect(boot).toThrow('granted by: no role');
  });

  it('still checks the tools when a factory of your own wraps them', async ({ task }) => {
    story.init(task, {
      tags: ['policy', 'operations'],
      covers: ['src/handler.ts'],
    });

    story.given('a context richer than the principal, so createServer wraps the built server');
    const policy = definePolicy({
      roles: { lead: ['cases:read'] },
      rules: [{ match: { domain: 'acme.com' }, role: 'lead' }],
    });
    const { tool, server } = authz(policy);
    const servers = server(
      [
        // @ts-expect-error no role grants this, which is the point
        tool('delete_case', { permission: 'cases:delete' }, async () => ({ content: [] })),
      ],
      { name: 'test', version: '0.0.0' },
    );

    story.when('the wrapper is handed the permissions map the wrapping hid');
    const boot = (permissions?: ReadonlyMap<string, string>) => () =>
      createMcpFetch({
        resourceServerUrl: RESOURCE,
        oauthMetadata: {
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          response_types_supported: ['code'],
        },
        verifier: { issuer: ISSUER, jwksUri: `${ISSUER}/jwks`, resource: RESOURCE },
        policy,
        permissions,
        resolve: (_identity, principal) => ({ principal, tenant: 'acme' }),
        createServer: (context: { principal: Principal<'cases:read'>; tenant: string }) =>
          servers(context.principal),
      });

    story.then('the unreachable tool still fails the boot');
    expect(boot(servers.permissions)).toThrow('delete_case');

    story.and('omitting it is how the check goes silent');
    story.note(
      'A wrapper is a plain function, so there is no map to read off it. Nothing can ' +
        'tell that apart from a hand-written factory that has no tool list at all.',
    );
    expect(boot()).not.toThrow();
  });
});

describe('Configuring against a real authorization server', () => {
  it('reads the endpoints off the authorization server instead of a config file', async ({ task }) => {
    story.init(task, { tags: ['operations', 'oauth'], covers: ['src/discovery.ts'] });

    story.given('an AS that publishes only the OIDC document, as Auth0 and Google do');
    story.note(
      'RFC 8414 puts the well-known segment before the issuer path and OIDC appends it. ' +
        'Trying one path only works for about half of the providers people actually use.',
    );
    const document = {
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/oauth/token`,
      jwks_uri: `${ISSUER}/.well-known/jwks.json`,
    };
    const asked: string[] = [];
    const stub = (async (input: string | URL | Request) => {
      const url = String(input);
      asked.push(url);
      if (!url.endsWith('/.well-known/openid-configuration')) return new Response('', { status: 404 });
      return Response.json(document);
    }) as typeof fetch;

    story.when('the application discovers it at boot');
    const metadata = await discoverOAuth(ISSUER, { fetch: stub });

    story.then('the RFC 8414 location is tried first, then the OIDC one');
    expect(asked).toEqual([
      `${ISSUER}/.well-known/oauth-authorization-server`,
      `${ISSUER}/.well-known/openid-configuration`,
    ]);

    story.and('the JWKS comes with it, so nothing about the AS is written twice');
    expect(metadata.jwks_uri).toBe(document.jwks_uri);

    story.and('a document claiming a different issuer is refused rather than trusted');
    story.note('Endpoints from somebody else’s server would send your users there to sign in.');
    const impostor = (async () =>
      Response.json({ ...document, issuer: 'https://evil.example' })) as typeof fetch;
    await expect(discoverOAuth(ISSUER, { fetch: impostor })).rejects.toThrow('declares issuer');

    story.and('an AS that publishes nothing fails the boot naming what was tried');
    const missing = (async () => new Response('', { status: 404 })) as typeof fetch;
    await expect(discoverOAuth(ISSUER, { fetch: missing })).rejects.toThrow('oauth-authorization-server');
  });
});

describe('Putting a policy in front of a server somebody else wrote', () => {
  it('reports a terminal audit failure without changing a gated tool result', async () => {
    const policy = definePolicy({ roles: { reader: ['cases:read'] }, rules: [{ role: 'reader' }] });
    const failures: { error: unknown; event: AuditEvent }[] = [];
    stubJwks();
    const fetch = createMcpFetch({
      resourceServerUrl: RESOURCE,
      oauthMetadata: {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        response_types_supported: ['code'],
      },
      verifier: { jwksUri: `${ISSUER}/jwks` },
      policy,
      permissions: new Map([['get_case', 'cases:read']]),
      createServer: (principal) => {
        const server = gate(
          new McpServer({ name: 'theirs', version: '1.0.0' }, { capabilities: { tools: {} } }),
          principal,
          { get_case: 'cases:read' },
          {
            onAudit: (event) => {
              if (event.phase === 'success') throw new Error('audit store unavailable');
            },
            onAuditError: (failure) => void failures.push(failure),
          },
        );
        server.registerTool('get_case', {}, async () => ({
          content: [{ type: 'text' as const, text: 'case' }],
        }));
        return server;
      },
    });

    const response = await fetch(
      call(`Bearer ${await token()}`, {}, { method: 'tools/call', params: { name: 'get_case' } }),
    );
    const body = (await response.json()) as { result?: { content?: { text: string }[] } };

    expect(body.result?.content?.[0]?.text).toBe('case');
    expect(failures).toHaveLength(1);
    expect(failures[0]?.event).toMatchObject({ phase: 'success', name: 'get_case' });
  });

  it('asks for a person before a tool somebody else wrote, and refuses to wire it without a sink', async ({
    task,
  }) => {
    story.init(task, { tags: ['approval', 'security'], covers: ['src/gate.ts'] });

    story.given('their destructive tool, priced by you, with an approver of yours behind it');
    story.note(
      'Their builder knows nothing about approval. The permission map already says what ' +
        'their tools cost; naming one here says which of them wants a second person too.',
    );
    let ran = false;
    const theirBuilder = (server: McpServer) => {
      server.registerTool('delete_run', { description: 'write' }, async () => {
        ran = true;
        return { content: [] };
      });
      return server;
    };
    const leadPolicy = definePolicy({
      roles: { lead: ['testrail:delete'] },
      rules: [{ match: { domain: 'acme.com' }, role: 'lead' }],
    });
    const PERMISSIONS = { delete_run: 'testrail:delete' } as const;
    const asked: ApprovalRequest[] = [];

    story.when('a permitted lead calls it');
    stubJwks();
    const fetch = createMcpFetch({
      resourceServerUrl: RESOURCE,
      oauthMetadata: {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        response_types_supported: ['code'],
      },
      verifier: { jwksUri: `${ISSUER}/jwks` },
      policy: leadPolicy,
      permissions: new Map(Object.entries(PERMISSIONS)),
      createServer: (principal) =>
        theirBuilder(
          gate(
            new McpServer({ name: 'theirs', version: '1.0.0' }, { capabilities: { tools: {} } }),
            principal,
            PERMISSIONS,
            {
              approval: { delete_run: true },
              onApproval: (request) => {
                asked.push(request);
                return { approved: false, reason: 'not on a Friday' };
              },
            },
          ),
        ),
    });
    const response = await fetch(
      call(
        `Bearer ${await token({ email: 'lead@acme.com' })}`,
        {},
        { method: 'tools/call', params: { name: 'delete_run', arguments: {} } },
      ),
    );

    story.then('the person was asked, and their handler never ran');
    expect(asked).toHaveLength(1);
    expect(asked[0]).toMatchObject({ name: 'delete_run', permission: 'testrail:delete' });
    expect(JSON.stringify(await response.json())).toMatch('not on a Friday');
    expect(ran).toBe(false);

    story.and('naming a tool for approval with no sink fails when it is wired, not at the call');
    story.note('The same boot-time refusal `authz` makes, for capabilities it never defined.');
    expect(() =>
      gate(
        new McpServer({ name: 'theirs', version: '1.0.0' }, { capabilities: { tools: {} } }),
        createPrincipal(
          { issuer: ISSUER, sub: 'lead', emailVerified: true, claims: {} },
          ['lead'],
          ['testrail:delete'],
        ),
        PERMISSIONS,
        { approval: { delete_run: true } },
      ).registerTool('delete_run', {}, async () => ({ content: [] })),
    ).toThrow(/asks for approval/);
  });

  it('hides the tools a caller may not use, without changing their code', async ({ task }) => {
    story.init(task, { tags: ['access', 'policy'], covers: ['src/gate.ts'] });

    story.given('an MCP server from another package, whose tools declare no permissions');
    story.note(
      'The SDK keeps a built server’s tool list private, so nothing can filter what it ' +
        'never saw. Gating the server before it registers needs one hook from its builder.',
    );
    const theirBuilder = (server: McpServer) => {
      server.registerTool('get_case', { description: 'read' }, async () => ({ content: [] }));
      server.registerTool('delete_run', { description: 'write' }, async () => ({ content: [] }));
      return server;
    };

    const policy = definePolicy({
      roles: { reader: ['testrail:read'], lead: ['testrail:read', 'testrail:delete'] },
      rules: [
        { match: { domain: 'acme.com' }, role: 'reader' },
        { match: { email: 'lead@acme.com' }, role: 'lead' },
      ],
    });
    const PERMISSIONS = { get_case: 'testrail:read', delete_run: 'testrail:delete' } as const;

    story.when('a reader connects through the gate');
    stubJwks();
    const audited: AuditEvent[] = [];
    const fetch = createMcpFetch({
      resourceServerUrl: RESOURCE,
      oauthMetadata: {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        response_types_supported: ['code'],
      },
      verifier: { jwksUri: `${ISSUER}/jwks`, allowedDomain: 'acme.com' },
      policy,
      permissions: new Map(Object.entries(PERMISSIONS)),
      createServer: (principal) =>
        theirBuilder(
          gate(
            new McpServer({ name: 'theirs', version: '1.0.0' }, { capabilities: { tools: {} } }),
            principal,
            PERMISSIONS,
            {
              onAudit: (event) => audited.push(event),
            },
          ),
        ),
    });

    const list = async (email: string) => {
      const response = await fetch(call(`Bearer ${await token({ email })}`));
      const text = await response.text();
      const json = text.includes('data: ') ? text.slice(text.indexOf('data: ') + 6).split('\n')[0]! : text;
      return (JSON.parse(json).result?.tools ?? []).map((tool: { name: string }) => tool.name).sort();
    };

    story.then('their write tool is absent from tools/list for the reader');
    expect(await list('dana@acme.com')).toEqual(['get_case']);

    story.and('the lead sees both, from the same unchanged builder');
    expect(await list('lead@acme.com')).toEqual(['delete_run', 'get_case']);

    story.and('their tool calls land in your audit log, which their code never writes');
    story.note(
      'TestRail or Jira sees one service account on every call. This is the only record ' +
        'tying the person to what they did.',
    );
    await fetch(
      call(
        `Bearer ${await token({ email: 'dana@acme.com' })}`,
        {},
        { method: 'tools/call', params: { name: 'get_case', arguments: {} } },
      ),
    );
    expect(audited).toContainEqual(
      expect.objectContaining({
        email: 'dana@acme.com',
        kind: 'tool',
        name: 'get_case',
        permission: 'testrail:read',
        decision: 'allow',
        phase: 'success',
      }),
    );

    story.and('a tool nobody priced fails loudly rather than defaulting either way');
    const unpriced = () =>
      gate(
        new McpServer({ name: 't', version: '1' }, { capabilities: { tools: {} } }),
        policy({ issuer: ISSUER, sub: 'u', email: 'dana@acme.com', emailVerified: true, claims: {} }),
        {},
      ).registerTool('surprise', {}, async () => ({ content: [] }));
    expect(unpriced).toThrow("no permission declared for tool 'surprise'");

    story.and('an SDK handle that cannot be disabled fails closed');
    const unsafeServer = { registerTool: () => ({}) } as unknown as McpServer;
    const denied = policy({
      issuer: ISSUER,
      sub: 'u',
      email: 'outsider@other.com',
      emailVerified: true,
      claims: {},
    });
    const cannotDisable = () =>
      gate(unsafeServer, denied, { get_case: 'testrail:read' }).registerTool('get_case', {}, async () => ({
        content: [],
      }));
    expect(cannotDisable).toThrow('cannot be disabled safely');
  });
});

describe('Reading the body that names the capability', () => {
  const scoped = () =>
    createMcpFetch({
      resourceServerUrl: RESOURCE,
      oauthMetadata: {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        response_types_supported: ['code'],
      },
      verifier: { jwksUri: `${ISSUER}/jwks`, allowedDomain: 'acme.com' },
      capabilityScopes: { update_case: 'write' },
      maxRequestBytes: 256,
      policy: definePolicy({
        roles: { reader: ['cases:read'] },
        rules: [{ match: { domain: 'acme.com' }, role: 'reader' }],
      }),
      createServer: () => stubServer(),
    });

  const post = (body: string, headers: Record<string, string> = {}) =>
    scoped()(
      new Request(RESOURCE.href, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body,
      }),
    );

  it('never parses a body for a caller it has not authenticated', async ({ task }) => {
    story.init(task, { tags: ['security', 'operations'], covers: ['src/handler.ts'] });

    story.given('per-capability scopes, whose selection needs the capability name from the body');
    story.note(
      'The scope is checked against the token this request already carries, not by the ' +
        'bearer gate itself, so the read can wait until a valid token has proved somebody ' +
        'is entitled to make this process do work.',
    );
    stubJwks();

    story.when('an unauthenticated caller posts far more than the cap');
    const oversized = await post(JSON.stringify({ jsonrpc: '2.0', id: 1, pad: 'x'.repeat(4096) }));

    story.then('the bearer gate refuses it without reading a byte of the body');
    expect(oversized.status).toBe(401);

    story.and('the cap still bounds an authenticated caller');
    const bearer = { Authorization: `Bearer ${await token()}` };
    const authenticated = await post(
      JSON.stringify({ jsonrpc: '2.0', id: 1, pad: 'x'.repeat(4096) }),
      bearer,
    );
    expect(authenticated.status).toBe(413);

    story.and('a body that is not JSON at all is a 415 rather than a parse error');
    story.note('The SDK asks hand-wired compositions to answer 415 themselves.');
    const wrongType = await post('id=1', {
      ...bearer,
      'Content-Type': 'application/x-www-form-urlencoded',
    });
    expect(wrongType.status).toBe(415);

    story.and('malformed JSON within the cap is still a parse error');
    const malformed = await post('{ not json', bearer);
    const failure = (await malformed.json()) as { error: { code: number } };
    expect(failure.error.code).toBe(-32_700);
  });

  it('never lets an unvalidated header pick the scope on a request with no body', async ({ task }) => {
    story.init(task, { tags: ['security'], covers: ['src/handler.ts'] });

    story.given('a GET, which carries no body for its routing headers to disagree with');
    stubJwks();

    story.when('it arrives claiming a cheap capability');
    const response = await scoped()(
      new Request(RESOURCE.href, {
        method: 'GET',
        headers: { Accept: 'text/event-stream', 'Mcp-Method': 'tools/call', 'Mcp-Name': 'get_case' },
      }),
    );

    story.then('the baseline scope applies and the bearer gate still refuses it');
    story.note(
      'Only a POST can be checked body against headers, so anything else is held to the ' +
        'baseline rather than to what its headers asked for.',
    );
    expect(response.status).toBe(401);
  });

  it('survives a routed capability when the resolver mode has no principal', async ({ task }) => {
    story.init(task, { tags: ['resolver'], covers: ['src/handler.ts', 'src/ladder.ts'] });
    stubJwks();

    story.given('a server whose capabilities carry route permissions');
    const policy = definePolicy({
      roles: { editor: ['cases:write'] },
      rules: [{ role: 'editor' }],
    });
    const { tool, server } = authz(policy);
    const createServer = server(
      [
        tool('update_case', { permission: 'cases:write' }, async () => ({
          content: [{ type: 'text' as const, text: 'updated' }],
        })),
      ],
      { name: 'test', version: '1.0.0' },
    );

    story.and('a gate wired in resolver mode, which decides access itself and has no principal');
    const fetchHandler = createMcpFetch({
      resourceServerUrl: RESOURCE,
      oauthMetadata: {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        response_types_supported: ['code'],
      },
      verifier: { jwksUri: `${ISSUER}/jwks` },
      resolve: () =>
        createPrincipal<'cases:write'>(
          { issuer: ISSUER, sub: 'dana', email: 'dana@acme.com', emailVerified: true, claims: {} },
          ['editor'],
          ['cases:write'],
        ),
      createServer,
    });

    story.when('somebody calls the routed tool');
    const response = await fetchHandler(
      call(
        `Bearer ${await token()}`,
        {},
        {
          method: 'tools/call',
          params: { name: 'update_case', arguments: {} },
        },
      ),
    );

    story.then('the request is answered rather than crashing on the missing principal');
    expect(response.status).toBeLessThan(500);
  });

  it('requires the step-up scope on a resource reached through a URI template', async ({ task }) => {
    story.init(task, { tags: ['scopes', 'resources'], covers: ['src/handler.ts', 'src/scopes.ts'] });
    stubJwks();

    story.given('a templated resource priced for a scope beyond the baseline');
    const policy = definePolicy({
      roles: { reader: ['cases:read'] },
      rules: [{ match: { email: 'dana@acme.com' }, role: 'reader' }],
    });
    const { resource, server } = authz(policy);
    const createServer = server(
      [
        resource(
          'case',
          {
            permission: 'cases:read',
            uri: new ResourceTemplate('cases://case/{id}', { list: undefined }),
          },
          async (uri) => ({ contents: [{ uri: uri.href, text: 'one case' }] }),
        ),
      ],
      { name: 'test', version: '1.0.0' },
    );

    const fetchHandler = createMcpFetch({
      resourceServerUrl: RESOURCE,
      oauthMetadata: {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        response_types_supported: ['code'],
      },
      verifier: { jwksUri: `${ISSUER}/jwks` },
      policy,
      capabilityScopes: { 'resource:cases://case/{id}': 'cases:sensitive' },
      createServer,
    });

    story.when('a reader holding only the baseline scope reads one instance of it');
    const response = await fetchHandler(
      call(
        `Bearer ${await token()}`,
        {},
        {
          method: 'resources/read',
          params: { uri: 'cases://case/C1' },
        },
      ),
    );
    story.code({
      label: 'Challenge',
      content: response.headers.get('WWW-Authenticate') ?? '(none)',
      lang: 'text',
    });

    story.then('the step-up is demanded, even though the key is a template and the request a URI');
    story.note(
      'The scope map is keyed by the template as registered; the request carries one concrete ' +
        'URI. An exact-string lookup between the two silently skips the step-up.',
    );
    expect(response.status).toBe(403);
    expect(response.headers.get('WWW-Authenticate')).toMatch(/insufficient_scope/);
  });
});
