import { story } from 'executable-stories-vitest';
import { exportJWK, generateKeyPair, SignJWT, type JWK, type KeyObject } from 'jose';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createOpenApiFetch, recordOperations, type OpenApiDocument } from './openapi';
import { toPermissionsModule } from './permissions-module';
import { definePolicy } from './policy';
import type { AuditEvent } from './tools';

/**
 * The OpenAPI half, told the same way as the MCP one.
 *
 * The claim under test is the same claim: what a caller may not do is not in
 * the catalogue they are handed, and is refused when they name it anyway. Only
 * the catalogue has changed — an OpenAPI document instead of `tools/list`.
 */

const RESOURCE = new URL('https://api.acme.com');
const ISSUER = 'https://auth.acme.com';

const AS_METADATA = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/authorize`,
  token_endpoint: `${ISSUER}/token`,
  jwks_uri: `${ISSUER}/jwks`,
  response_types_supported: ['code'],
};

const SPEC: OpenApiDocument = {
  openapi: '3.1.0',
  info: { title: 'case-tracker', version: '3.2.0' },
  paths: {
    '/cases': {
      get: { operationId: 'listCases', summary: 'List cases' },
      post: { operationId: 'createCase', summary: 'Open a case' },
    },
    // Listed before the template on purpose: a document is written for people,
    // and the matcher may not depend on which order they chose.
    '/cases/search': { get: { operationId: 'searchCases', summary: 'Search cases' } },
    '/cases/{id}': {
      parameters: [{ name: 'id', in: 'path', required: true }],
      get: { operationId: 'getCase', summary: 'Read a case' },
      delete: { operationId: 'deleteCase', summary: 'Delete a case' },
    },
  },
};

const PERMISSIONS = {
  listCases: 'cases:read',
  searchCases: 'cases:read',
  getCase: 'cases:read',
  createCase: 'cases:write',
  deleteCase: 'cases:delete',
} as const;

const policy = definePolicy({
  roles: {
    reader: ['cases:read'],
    lead: ['cases:read', 'cases:write', 'cases:delete'],
  },
  rules: [
    { match: { email: 'dana@acme.com' }, role: 'reader' },
    { match: { email: 'alice@acme.com' }, role: 'lead' },
  ],
});

let privateKey: KeyObject;
let publicJwk: JWK;
let restoreFetch: (() => void) | undefined;

beforeAll(async () => {
  const pair = await generateKeyPair('RS256', { extractable: true });
  privateKey = pair.privateKey as KeyObject;
  publicJwk = await exportJWK(pair.publicKey);
  publicJwk.kid = 'openapi-key';
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

async function token(email: string) {
  return new SignJWT({ email, email_verified: true, scope: 'api', client_id: 'agent' })
    .setProtectedHeader({ alg: 'RS256', kid: 'openapi-key' })
    .setSubject(`auth0|${email}`)
    .setIssuer(ISSUER)
    .setAudience(RESOURCE.href)
    .setExpirationTime('5m')
    .sign(privateKey);
}

/** The API itself: it never learns that any of this happened. */
const upstream = (request: Request) =>
  Response.json({ served: `${request.method} ${new URL(request.url).pathname}` });

function gatedApi(onAudit?: (event: AuditEvent) => void) {
  return createOpenApiFetch({
    spec: SPEC,
    permissions: PERMISSIONS,
    resourceServerUrl: RESOURCE,
    oauthMetadata: AS_METADATA,
    policy,
    upstream,
    ...(onAudit ? { onAudit } : {}),
  });
}

async function call(
  fetchApi: (request: Request) => Promise<Response>,
  method: string,
  path: string,
  bearer: string,
) {
  return fetchApi(
    new Request(new URL(path, RESOURCE), { method, headers: { Authorization: `Bearer ${bearer}` } }),
  );
}

async function documentFor(fetchApi: (request: Request) => Promise<Response>, bearer: string) {
  const response = await call(fetchApi, 'GET', '/openapi.json', bearer);
  const document = (await response.json()) as OpenApiDocument;
  return Object.entries(document.paths ?? {}).flatMap(([path, item]) =>
    Object.entries(item ?? {})
      .filter(([, value]) => (value as { operationId?: string })?.operationId)
      .map(([method]) => `${method.toUpperCase()} ${path}`),
  );
}

describe('An API you already have, gated per person', () => {
  it('hands each caller a document that stops at what they may do', async ({ task }) => {
    story.init(task, { tags: ['openapi'], covers: ['src/openapi.ts'] });

    story.given('case-tracker 3.2.0, described by the OpenAPI document it already ships', {
      json: { label: 'Operations in the document', value: recordOperations(SPEC).names },
      note:
        'No server is introspected and nothing is generated: the document is the catalogue, and it ' +
        'is already in the repository.',
    });
    stubJwks();

    story.given('a permission map that puts a price on every operation', {
      json: { label: 'Permission map', value: PERMISSIONS },
      note: 'An operation missing from this map fails the boot, so a new route cannot arrive unpriced.',
    });
    const api = gatedApi();

    story.when('Dana the reader and Alice the lead each fetch the document');
    const dana = await documentFor(api, await token('dana@acme.com'));
    const alice = await documentFor(api, await token('alice@acme.com'));
    story.table({
      label: 'One document, two readers',
      columns: ['Caller', 'What the document offers'],
      rows: [
        ['Dana (reader)', dana.join(', ')],
        ['Alice (lead)', alice.join(', ')],
      ],
    });

    story.then('Dana is offered the three reads and nothing else');
    expect(dana).toEqual(['GET /cases', 'GET /cases/search', 'GET /cases/{id}']);

    story.and('Alice, from the same document, is offered the write and the delete too');
    expect(alice).toContain('POST /cases');
    expect(alice).toContain('DELETE /cases/{id}');

    story.and('what the document offers, the API actually serves');
    const read = await call(api, 'GET', '/cases/C1234', await token('dana@acme.com'));
    story.state({ label: 'GET /cases/C1234', value: await read.json() });
    expect(read.status).toBe(200);
  });

  it('refuses the operation an agent never saw, when it names it anyway', async ({ task }) => {
    story.init(task, { tags: ['openapi', 'security'], covers: ['src/openapi.ts'] });

    story.given('the same reader, and a client that never fetched the document', {
      note:
        'A smaller document is a context saving, not a boundary. An agent that guessed the path, or ' +
        'a client written against last month`s spec, never asks.',
    });
    stubJwks();
    const api = gatedApi();

    story.when('she deletes a case anyway');
    const response = await call(api, 'DELETE', '/cases/C1234', await token('dana@acme.com'));
    story.state({ label: 'What she got back', value: await response.clone().json() });

    story.then('the request is refused, naming the permission she lacks');
    expect(response.status).toBe(403);
    expect(await response.text()).toContain('cases:delete');
  });

  it('refuses a route the document does not describe', async ({ task }) => {
    story.init(task, { tags: ['openapi', 'security'], covers: ['src/openapi.ts'] });

    story.given('an endpoint somebody added to the app and left out of the spec', {
      note:
        'The failure this prevents is the quiet one: a route nobody described is a route nobody ' +
        'priced, and passing it through would make the undescribed case the unguarded case.',
    });
    stubJwks();
    const api = gatedApi();

    story.when('the lead, who may do everything, calls it');
    const response = await call(api, 'POST', '/cases/C1234/export', await token('alice@acme.com'));
    story.state({ label: 'What she got back', value: await response.clone().json() });

    story.then('it is refused even for her, and the refusal says what to do about it');
    expect(response.status).toBe(404);
    expect(await response.text()).toContain('Describe it in the OpenAPI document');
  });

  it('will not start when the document describes an operation nobody priced', async ({ task }) => {
    story.init(task, { tags: ['openapi', 'boot'], covers: ['src/openapi.ts'] });

    story.given('a document that grew an operation, and a map that did not', {
      note: 'The everyday drift: somebody adds a route, and the map that prices it is a separate file.',
    });
    const grown: OpenApiDocument = {
      ...SPEC,
      paths: { ...SPEC.paths, '/cases/{id}/close': { post: { operationId: 'closeCase' } } },
    };

    story.when('the server is built');
    const boot = () =>
      createOpenApiFetch({
        spec: grown,
        permissions: PERMISSIONS,
        resourceServerUrl: RESOURCE,
        oauthMetadata: AS_METADATA,
        policy,
        upstream,
      });

    story.then('it refuses to boot, naming the operation');
    expect(boot).toThrow(/closeCase/);

    story.and('the map you start from is generated from the document, priced so it cannot be forgotten');
    const scaffold = toPermissionsModule(recordOperations(grown));
    story.code({ label: 'toPermissionsModule(recordOperations(spec))', content: scaffold, lang: 'ts' });
    expect(scaffold).toContain('closeCase: "TODO:unassigned"');
  });

  it('records who called what, in the same event shape as the MCP side', async ({ task }) => {
    story.init(task, { tags: ['openapi', 'audit'], covers: ['src/openapi.ts', 'src/tools.ts'] });

    story.given('an audit sink, and a downstream API that sees one service account', {
      note:
        'This event is the only place the person appears. The API behind it was called by the ' +
        'gateway, with the gateway`s credential.',
    });
    stubJwks();
    const events: AuditEvent[] = [];
    const api = gatedApi((event) => events.push(event));

    story.when('Alice opens a case');
    const response = await call(api, 'POST', '/cases', await token('alice@acme.com'));
    expect(response.status).toBe(200);
    story.state({ label: 'What was recorded', value: events });

    story.then('the trail names her, the operation, and what it cost');
    expect(events.map((event) => event.phase)).toEqual(['attempt', 'success']);

    story.and('both events of the call carry one id, which is what joins them later');
    story.note(
      'Correlating an attempt with its outcome by identity and timestamp breaks under exactly the ' +
        'concurrency that makes the question worth asking.',
    );
    expect(new Set(events.map((event) => event.callId)).size).toBe(1);
    expect(events.at(-1)).toMatchObject({
      type: 'mcp_authz.audit.v1',
      kind: 'operation',
      email: 'alice@acme.com',
      name: 'createCase',
      permission: 'cases:write',
      resource: '/cases',
    });
  });
});
