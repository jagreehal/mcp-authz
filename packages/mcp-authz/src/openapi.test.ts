import { describe, expect, it } from 'vitest';
import { createPrincipal } from './policy';
import { createOpenApiFetch, filterSpec, recordOperations, type OpenApiDocument } from './openapi';

/**
 * The refusals and the boot checks. The walkthrough lives in
 * `openapi.story.test.ts`; what is here is every way this is asked to say no.
 */

const ISSUER = 'https://auth.acme.com';
const RESOURCE = new URL('https://api.acme.com');
const AS_METADATA = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/authorize`,
  token_endpoint: `${ISSUER}/token`,
  jwks_uri: `${ISSUER}/jwks`,
  response_types_supported: ['code'],
};

const SPEC: OpenApiDocument = {
  openapi: '3.1.0',
  paths: {
    '/cases': { get: { operationId: 'listCases' } },
    '/cases/{id}': { get: { operationId: 'getCase' }, delete: { operationId: 'deleteCase' } },
  },
};
const PERMISSIONS = { listCases: 'cases:read', getCase: 'cases:read', deleteCase: 'cases:delete' };

const identity = (sub: string, email?: string) => ({
  issuer: ISSUER,
  sub,
  ...(email ? { email } : {}),
  emailVerified: true,
  claims: {},
});

const reader = createPrincipal(identity('u1', 'dana@acme.com'), ['reader'], ['cases:read']);

function build(overrides: Record<string, unknown> = {}) {
  return createOpenApiFetch({
    spec: SPEC,
    permissions: PERMISSIONS,
    resourceServerUrl: RESOURCE,
    oauthMetadata: AS_METADATA,
    authorize: () => reader,
    tokenVerifier: {
      verifyAccessToken: async (token: string) => ({
        token,
        clientId: 'agent',
        scopes: ['api'],
        expiresAt: Math.floor(Date.now() / 1000) + 300,
        resource: RESOURCE,
        extra: { issuer: ISSUER, sub: 'u1', email: 'dana@acme.com', emailVerified: true, claims: {} },
      }),
    },
    upstream: () => Response.json({ ok: true }),
    ...overrides,
  } as Parameters<typeof createOpenApiFetch>[0]);
}

const call = (fetchApi: ReturnType<typeof build>, method: string, path: string, bearer = 'token') =>
  fetchApi(new Request(new URL(path, RESOURCE), { method, headers: { Authorization: `Bearer ${bearer}` } }));

describe('recordOperations', () => {
  it('names every operation the document describes, sorted', () => {
    expect(recordOperations(SPEC).names).toEqual(['deleteCase', 'getCase', 'listCases']);
  });

  it('refuses an operation with no operationId rather than inventing one', () => {
    expect(() => recordOperations({ paths: { '/x': { get: { summary: 'no id' } } } })).toThrow(
      /GET \/x has no operationId/,
    );
  });

  it('refuses one id used by two routes, because the map could not say which', () => {
    expect(() =>
      recordOperations({
        paths: { '/a': { get: { operationId: 'same' } }, '/b': { get: { operationId: 'same' } } },
      }),
    ).toThrow(/used by both GET \/a and GET \/b/);
  });

  it('ignores path items that are not operations', () => {
    const record = recordOperations({
      paths: { '/x': { parameters: [], summary: 'nothing callable' }, '/y': undefined },
    });
    expect(record.names).toEqual([]);
  });
});

describe('filterSpec', () => {
  it('drops a path item left with no operations, and keeps the rest of the document', () => {
    const filtered = filterSpec(SPEC, reader, PERMISSIONS);
    expect(Object.keys(filtered.paths ?? {})).toEqual(['/cases', '/cases/{id}']);
    expect(filtered.paths?.['/cases/{id}']).toHaveProperty('get');
    expect(filtered.paths?.['/cases/{id}']).not.toHaveProperty('delete');
    expect(filtered.openapi).toBe('3.1.0');

    const nothing = filterSpec(SPEC, createPrincipal(identity('u2'), [], ['other:read']), PERMISSIONS);
    expect(nothing.paths).toEqual({});
  });
});

describe('the boot checks', () => {
  it('refuses an operation the map does not price', () => {
    expect(() => build({ permissions: { listCases: 'cases:read' } })).toThrow(
      /puts no price on 'deleteCase'/,
    );
  });

  it('refuses a map entry naming an operation the document does not have', () => {
    expect(() => build({ permissions: { ...PERMISSIONS, closeCase: 'cases:write' } })).toThrow(
      /prices 'closeCase'/,
    );
  });

  it('refuses both a policy and an authorize, and neither', () => {
    const policy = Object.assign(() => reader, { roles: new Map(), explain: () => ({}) });
    expect(() => build({ policy })).toThrow(/either `policy` or `authorize`/);
    expect(() => build({ authorize: undefined })).toThrow(/needs a `policy` or an `authorize`/);
  });
});

describe('the refusals', () => {
  it('challenges a request with no token', async () => {
    const response = await build()(new Request(new URL('/cases', RESOURCE)));
    expect(response.status).toBe(401);
    expect(response.headers.get('WWW-Authenticate')).toContain('resource_metadata');
  });

  it('refuses a caller the authorizer grants nothing', async () => {
    const api = build({ authorize: () => createPrincipal(identity('u3'), [], []) });
    const response = await call(api, 'GET', '/cases');
    expect(response.status).toBe(403);
    expect(await response.text()).toContain('policy_denied');
  });

  it('explains a path outside the URL its tokens are bound to', async () => {
    const api = createOpenApiFetch({
      spec: SPEC,
      permissions: PERMISSIONS,
      resourceServerUrl: new URL('https://api.acme.com/v1'),
      oauthMetadata: AS_METADATA,
      authorize: () => reader,
      verifier: { jwksUri: `${ISSUER}/jwks` },
      upstream: () => Response.json({ ok: true }),
    });
    const response = await api(new Request('https://api.acme.com/cases'));
    expect(response.status).toBe(404);
    expect(await response.text()).toContain('/v1');
  });

  it('matches a concrete path ahead of a template that would also fit', async () => {
    const seen: string[] = [];
    const api = build({
      spec: {
        paths: {
          '/cases/{id}': { get: { operationId: 'getCase' } },
          '/cases/search': { get: { operationId: 'searchCases' } },
        },
      },
      permissions: { getCase: 'cases:read', searchCases: 'cases:read' },
      upstream: (request: Request) => {
        seen.push(new URL(request.url).pathname);
        return Response.json({ ok: true });
      },
    });
    expect((await call(api, 'GET', '/cases/search')).status).toBe(200);
    expect(seen).toEqual(['/cases/search']);
  });

  it('does not let a template swallow a deeper path nobody priced', async () => {
    const response = await call(build(), 'GET', '/cases/C1/notes');
    expect(response.status).toBe(404);
  });
});

describe('the audit trail', () => {
  it('refuses the call when the attempt write is rejected', async () => {
    const api = build({
      onAudit: () => {
        throw new Error('audit store unavailable');
      },
      upstream: () => {
        throw new Error('should never run');
      },
    });
    const response = await call(api, 'GET', '/cases');
    expect(response.status).toBe(503);
  });

  it('records a failure when the API answers with one, and does not change the answer', async () => {
    const events: { phase: string; error?: string }[] = [];
    const api = build({
      onAudit: (event: { phase: string; error?: string }) => events.push(event),
      upstream: () => Response.json({ error: 'nope' }, { status: 409 }),
    });
    const response = await call(api, 'GET', '/cases');
    expect(response.status).toBe(409);
    expect(events.map((event) => event.phase)).toEqual(['attempt', 'failure']);
    expect(events.at(-1)?.error).toBe('HTTP 409');
  });

  it('records a failure when the API throws, and still throws', async () => {
    const events: { phase: string }[] = [];
    const failures: unknown[] = [];
    const api = build({
      onAudit: (event: { phase: string }) => {
        events.push(event);
        if (event.phase === 'failure') throw new Error('sink down');
      },
      onAuditError: (failure: unknown) => failures.push(failure),
      upstream: () => {
        throw new Error('upstream exploded');
      },
    });
    await expect(call(api, 'GET', '/cases')).rejects.toThrow('upstream exploded');
    expect(events.map((event) => event.phase)).toEqual(['attempt', 'failure']);
    expect(failures).toHaveLength(1);
  });
});
