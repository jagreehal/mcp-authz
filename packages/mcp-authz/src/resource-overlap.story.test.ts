import { ResourceTemplate } from '@modelcontextprotocol/server';
import { story } from 'executable-stories-vitest';
import { describe, expect, it } from 'vitest';
import { createMcpFetch } from './handler';
import { definePolicy } from './policy';
import { authz } from './tools';

/**
 * An exact resource and a template can both cover one URI. The SDK serves the
 * exact one whichever was registered first, so the gate has to price every
 * registration that matches, not just the first it finds.
 */

const RESOURCE = new URL('https://mcp.acme.com/mcp');
const ISSUER = 'https://auth.acme.com';

const ORDERS = ['broad first', 'exact first'] as const;
type Order = (typeof ORDERS)[number];

function serve(options: { order: Order; grants: ('read' | 'admin')[]; scopes: string[] }) {
  const policy = definePolicy({
    roles: { reader: ['read'], admin: ['read', 'admin'] },
    rules: [{ role: options.grants.includes('admin') ? 'admin' : 'reader' }],
  });
  const { resource, server } = authz(policy);
  const broad = resource(
    'broad',
    { uri: new ResourceTemplate('secret://{+rest}', { list: undefined }), permission: 'read' },
    async (uri) => ({ contents: [{ uri: uri.href, text: 'broad' }] }),
  );
  const payroll = resource('payroll', { uri: 'secret://payroll', permission: 'admin' }, async (uri) => ({
    contents: [{ uri: uri.href, text: 'payroll-secret' }],
  }));
  const definitions = options.order === 'broad first' ? [broad, payroll] : [payroll, broad];

  return createMcpFetch({
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
        scopes: options.scopes,
        expiresAt: Math.floor(Date.now() / 1000) + 60,
        resource: RESOURCE,
      }),
    },
    identityFromAuth: () => ({ issuer: ISSUER, sub: 'dana', emailVerified: false, claims: {} }),
    policy,
    createServer: server(definitions, { name: 'test', version: '0.0.0' }),
    capabilityScopes: { 'resource:secret://payroll': 'payroll', 'resource:secret://{+rest}': 'secrets' },
  });
}

function read(uri: string) {
  return new Request(RESOURCE, {
    method: 'POST',
    headers: {
      authorization: 'Bearer token',
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'mcp-protocol-version': '2026-07-28',
      'mcp-method': 'resources/read',
      'mcp-name': uri,
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'resources/read',
      params: {
        uri,
        _meta: {
          'io.modelcontextprotocol/protocolVersion': '2026-07-28',
          'io.modelcontextprotocol/clientInfo': { name: 'test', version: '0.0.0' },
          'io.modelcontextprotocol/clientCapabilities': {},
        },
      },
    }),
  });
}

describe('Reading a URI that an exact resource and a template both cover', () => {
  for (const order of ORDERS) {
    it(`demands the exact resource’s scope too, registered ${order}`, async ({ task }) => {
      story.init(task, { tags: ['oauth', 'scopes', 'security'], covers: ['src/tools.ts', 'src/handler.ts'] });

      story.given('Dana holds both permissions but only the broad template’s scope');
      const fetch = serve({ order, grants: ['read', 'admin'], scopes: ['mcp', 'secrets'] });

      story.when('she reads the URI the exact payroll resource serves');
      const response = await fetch(read('secret://payroll'));

      story.then('the gate challenges for the payroll scope instead of running the exact handler');
      expect(response.status).toBe(403);
      expect(response.headers.get('WWW-Authenticate')).toMatch(/insufficient_scope/);
      expect(response.headers.get('WWW-Authenticate')).toMatch(/payroll/);
      expect(await response.text()).not.toContain('payroll-secret');

      story.and('the payroll scope alone is not enough either: the template’s scope is demanded too');
      const partial = serve({ order, grants: ['read', 'admin'], scopes: ['mcp', 'payroll'] });
      const refused = await partial(read('secret://payroll'));
      expect(refused.status).toBe(403);
      expect(refused.headers.get('WWW-Authenticate')).toMatch(/secrets/);

      story.and('with every matching scope she gets the payroll contents');
      const stepped = serve({ order, grants: ['read', 'admin'], scopes: ['mcp', 'secrets', 'payroll'] });
      const allowed = await stepped(read('secret://payroll'));
      expect(allowed.status).toBe(200);
      expect(await allowed.text()).toContain('payroll-secret');
    });
  }

  for (const order of ORDERS) {
    it(`refuses a principal missing the exact resource’s permission, registered ${order}`, async ({
      task,
    }) => {
      story.init(task, { tags: ['access', 'security'], covers: ['src/tools.ts', 'src/handler.ts'] });

      story.given('a reader granted only the broad template’s permission, holding every scope');
      const fetch = serve({ order, grants: ['read'], scopes: ['mcp', 'secrets', 'payroll'] });

      story.when('she reads the payroll URI');
      const response = await fetch(read('secret://payroll'));

      story.then('the policy refuses naming the unmet admin permission');
      expect(response.status).toBe(403);
      expect(await response.text()).toContain("'admin'");
    });
  }

  it('serves a URI only the template covers on the template’s scope alone', async ({ task }) => {
    story.init(task, { tags: ['oauth', 'scopes'], covers: ['src/tools.ts', 'src/handler.ts'] });

    story.given('a reader holding only the template’s permission and scope');
    const fetch = serve({ order: 'broad first', grants: ['read'], scopes: ['mcp', 'secrets'] });

    story.when('she reads a URI the exact resource does not cover');
    const response = await fetch(read('secret://holidays'));

    story.then('the template serves it, with no payroll scope or admin permission asked for');
    expect(response.status).toBe(200);
    expect(await response.text()).toContain('broad');
  });
});
