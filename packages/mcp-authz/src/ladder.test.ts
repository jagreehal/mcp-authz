import { describe, expect, it } from 'vitest';
import { permissionForFlatMap, capabilityLabel, policyDenied, runScopedGate } from './ladder';
import { AccessDeniedError } from './identity';
import { scopesForCapability } from './scopes';
import { createPrincipal } from './policy';
import type { TrustedMcpRoute } from './routing';

describe('capabilityLabel', () => {
  it('labels tools with bare names and prefixes the rest', () => {
    expect(capabilityLabel('tool', 'search_cases')).toBe('search_cases');
    expect(capabilityLabel('prompt', 'triage')).toBe('prompt:triage');
    expect(capabilityLabel('resource', 'cases')).toBe('resource:cases');
  });
});

describe('permissionForFlatMap', () => {
  const permissions = new Map([
    ['search_cases', 'cases:read'],
    ['prompt:triage', 'cases:read'],
    ['resource:cases', 'cases:read'],
  ]);

  const route = (method: string, name?: string): TrustedMcpRoute => ({
    kind: 'modern',
    body: {},
    method,
    ...(name ? { name } : {}),
  });

  it('resolves bare tool names from a flat map', () => {
    expect(permissionForFlatMap(permissions, route('tools/call', 'search_cases'))).toBe('cases:read');
  });

  it('resolves prefixed prompt names', () => {
    expect(permissionForFlatMap(permissions, route('prompts/get', 'triage'))).toBe('cases:read');
  });

  it('resolves a resource by the URI the request carries, not by its label', () => {
    const resources = [
      { label: 'resource:cases', permission: 'cases:read', matches: (uri: string) => uri === 'cases://all' },
      {
        label: 'resource:case',
        permission: 'cases:read',
        matches: (uri: string) => uri.startsWith('cases://case/'),
      },
    ];
    expect(permissionForFlatMap(permissions, route('resources/read', 'cases://all'), resources)).toBe(
      'cases:read',
    );
    expect(permissionForFlatMap(permissions, route('resources/read', 'cases://case/C1'), resources)).toBe(
      'cases:read',
    );

    // The label is what the map is keyed by, and it is never what a read sends.
    expect(permissionForFlatMap(permissions, route('resources/read', 'cases'), resources)).toBeUndefined();
    expect(
      permissionForFlatMap(permissions, route('resources/read', 'secrets://payroll'), resources),
    ).toBeUndefined();
  });

  it('returns undefined when the capability is not priced', () => {
    expect(permissionForFlatMap(permissions, route('tools/call', 'close_run'))).toBeUndefined();
    expect(permissionForFlatMap(permissions, route('tools/list'))).toBeUndefined();
  });
});

describe('policyDenied', () => {
  it('returns a 403 with a policy reason', async () => {
    const response = policyDenied(AccessDeniedError.notPermitted('dana@acme.com'));
    expect(response.status).toBe(403);
    expect(((await response.json()) as { reason: string }).reason).toBe('policy_denied');
  });
});

describe('runScopedGate', () => {
  it('refuses when the principal lacks the priced permission', async () => {
    const principal = createPrincipal(
      {
        issuer: 'https://auth.acme.com',
        sub: 'dana',
        email: 'dana@acme.com',
        emailVerified: true,
        claims: {},
      },
      ['reader'],
      ['cases:read'],
    );
    const request = new Request('https://mcp.acme.com/mcp', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
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
          arguments: {},
          _meta: {
            'io.modelcontextprotocol/protocolVersion': '2026-07-28',
            'io.modelcontextprotocol/clientCapabilities': {},
          },
        },
      }),
    });

    const result = await runScopedGate({
      request,
      auth: { token: 't', clientId: 'c', scopes: ['mcp'], expiresAt: 0 },
      principal,
      maxRequestBytes: 1_048_576,
      requiredScopes: ['mcp'],
      scoped: false,
      routed: true,
      resolvePermission: () => 'cases:write',
      resourceMetadataUrl: 'https://mcp.acme.com/.well-known/oauth-protected-resource',
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.response.status).toBe(403);
  });

  it('challenges when scoped capability scopes are missing from the token', async () => {
    const request = new Request('https://mcp.acme.com/mcp', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
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
          arguments: {},
          _meta: {
            'io.modelcontextprotocol/protocolVersion': '2026-07-28',
            'io.modelcontextprotocol/clientCapabilities': {},
          },
        },
      }),
    });

    const result = await runScopedGate({
      request,
      auth: { token: 't', clientId: 'c', scopes: ['mcp'], expiresAt: 0 },
      principal: createPrincipal(
        {
          issuer: 'https://auth.acme.com',
          sub: 'alice',
          email: 'alice@acme.com',
          emailVerified: true,
          claims: {},
        },
        ['lead'],
        ['cases:read', 'cases:write'],
      ),
      maxRequestBytes: 1_048_576,
      requiredScopes: ['mcp'],
      scoped: true,
      routed: true,
      scopeMap: { update_case: 'cases:write' },
      resolvePermission: () => 'cases:write',
      resourceMetadataUrl: 'https://mcp.acme.com/.well-known/oauth-protected-resource',
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.response.status).toBe(403);
      expect(result.response.headers.get('WWW-Authenticate')).toMatch(/insufficient_scope/);
    }
  });
});

describe('scopesForCapability', () => {
  it('does not read inherited properties for a capability named __proto__', () => {
    const scopeMap = { update_case: 'cases:write' };

    // `scopeMap['__proto__']` is Object.prototype, not undefined, so a lookup
    // that tests for undefined finds a match that was never configured — and
    // then tries to read scopes out of it.
    expect(() => scopesForCapability('tools/call', '__proto__', scopeMap, 'mcp')).not.toThrow();
    expect(scopesForCapability('tools/call', '__proto__', scopeMap, 'mcp')).toEqual(['mcp']);
  });

  it('still honours a scope deliberately set for that name', () => {
    const scopeMap = Object.assign(Object.create(null) as Record<string, string>, {
      ['__proto__']: 'cases:admin',
    });
    expect(scopesForCapability('tools/call', '__proto__', scopeMap, 'mcp')).toEqual(['cases:admin']);
  });
});
