import { readFileSync } from 'node:fs';
import { Client } from '@modelcontextprotocol/client';
import { InMemoryTransport } from '@modelcontextprotocol/server';
import { describe, expect, it } from 'vitest';
import type { Identity } from './identity';
import { definePolicy, type Policy } from './policy';
import { emitDecision, type AuthorizationDecisionEvent } from './decision';
import { classifyScopedRequest } from './routing';
import { scopesForCapability, scopesFromMcpHeaders, type CapabilityScopeMap } from './scopes';
import { authz, type AuditEvent } from './tools';
import { z } from 'zod';

type DecisionFixtures = {
  policy: unknown;
  cases: {
    name: string;
    identity: Identity;
    expected: { roles: string[]; permissions: string[]; can: string[]; cannot: string[] };
  }[];
};

type ExplanationFixtures = {
  policy: { rules: { match?: unknown }[] };
  cases: {
    name: string;
    identity: Identity;
    expected: {
      matched: { index: number; roles: string[]; deny: boolean }[];
      deniedBy: number | null;
      roles: string[];
      permissions: string[];
    };
  }[];
};

type ValidationFixtures = {
  cases: { name: string; policy: unknown; errorIncludes: string }[];
};

type EventFixtures = {
  audit: { type: string; keys: string[]; required: string[]; kinds: string[]; phases: string[] };
  decision: { type: string; keys: string[]; required: string[] };
};

/** Keys carried with an undefined value are absent once serialised. */
const wireKeys = (event: object): string[] =>
  Object.entries(event)
    .filter(([, value]) => value !== undefined)
    .map(([key]) => key);

type ScopeFixtures = {
  baseline: string;
  map: CapabilityScopeMap;
  cases: {
    name: string;
    method: string;
    capabilityName?: string;
    headerName?: string;
    expected: string[];
  }[];
};

type RoutingFixtures = {
  cases: {
    name: string;
    headers: Record<string, string>;
    body: unknown;
    expected:
      | { kind: 'modern'; method: string; name?: string }
      | { kind: 'reject'; code: number }
      | { kind: 'legacy' };
  }[];
};

const fixture = <T>(path: string): T =>
  JSON.parse(readFileSync(new URL(`../../../conformance/v1/${path}`, import.meta.url), 'utf8')) as T;

describe('the cross-language policy contract', () => {
  const decisions = fixture<DecisionFixtures>('policy/decisions.json');
  const validation = fixture<ValidationFixtures>('policy/validation.json');

  it.each(decisions.cases)('$name', ({ identity, expected }) => {
    const policy = definePolicy(decisions.policy as never) as unknown as Policy<string>;
    const principal = policy(identity);

    expect(principal.roles).toEqual(expected.roles);
    expect(principal.permissions).toEqual(expected.permissions);
    for (const permission of expected.can) expect(principal.can(permission)).toBe(true);
    for (const permission of expected.cannot) expect(principal.can(permission)).toBe(false);
  });

  const explanations = fixture<ExplanationFixtures>('policy/explanations.json');

  it.each(explanations.cases)('explains: $name', ({ identity, expected }) => {
    const policy = definePolicy(explanations.policy as never) as unknown as Policy<string>;
    const { principal, matched, deniedBy } = policy.explain(identity);

    expect(matched.map((rule) => ({ index: rule.index, roles: rule.roles, deny: rule.deny }))).toEqual(
      expected.matched,
    );
    expect(deniedBy?.index ?? null).toEqual(expected.deniedBy);

    // An index that does not point at the rule it claims is worse than no index.
    for (const rule of matched) {
      expect(rule.match).toEqual(explanations.policy.rules[rule.index]?.match ?? {});
    }

    // The explanation and the decision are the same answer, reached twice.
    expect(principal.roles).toEqual(expected.roles);
    expect(principal.permissions).toEqual(expected.permissions);
    expect(policy(identity).permissions).toEqual(principal.permissions);
  });

  it.each(validation.cases)('rejects $name', ({ policy, errorIncludes }) => {
    expect(() => definePolicy(policy as never)).toThrow(errorIncludes);
  });
});

describe('the cross-language scope contract', () => {
  const scopes = fixture<ScopeFixtures>('protocol/scopes.json');

  it.each(scopes.cases)('$name', ({ method, capabilityName, headerName, expected }) => {
    if (headerName) {
      const request = new Request('https://mcp.example/mcp', {
        headers: { 'Mcp-Method': method, 'Mcp-Name': headerName },
      });
      expect(scopesFromMcpHeaders(request, scopes.map, scopes.baseline)).toEqual(expected);
      return;
    }
    expect(scopesForCapability(method, capabilityName, scopes.map, scopes.baseline)).toEqual(expected);
  });
});

describe('the cross-language trusted-routing contract', () => {
  const routing = fixture<RoutingFixtures>('protocol/routing.json');

  it.each(routing.cases)('$name', ({ headers, body, expected }) => {
    const request = new Request('https://mcp.example/mcp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify(body),
    });
    const route = classifyScopedRequest(request, body);

    expect(route.kind).toBe(expected.kind);
    if (route.kind === 'modern' && expected.kind === 'modern') {
      expect(route.method).toBe(expected.method);
      expect(route.name).toBe(expected.name);
    }
    if (route.kind === 'reject' && expected.kind === 'reject') expect(route.code).toBe(expected.code);
  });
});

describe('the cross-language event contract', () => {
  const events = fixture<EventFixtures>('audit/events.json');

  it('emits the audit record both packages agreed on', async () => {
    const seen: AuditEvent[] = [];
    const { tool, server } = authz(
      definePolicy({
        roles: { reader: ['cases:read'] },
        rules: [{ match: { domain: 'acme.com' }, role: 'reader' }],
      }),
    );
    const createServer = server(
      [
        tool(
          'read_case',
          {
            permission: 'cases:read',
            inputSchema: z.object({ id: z.string() }),
            audit: ({ id }) => `case:${id}`,
          },
          async () => ({ content: [{ type: 'text' as const, text: 'read' }] }),
        ),
      ],
      { name: 'conformance', version: '1.0.0', onAudit: (event) => void seen.push(event) },
    );
    const built = createServer({
      issuer: 'https://auth.example.com',
      sub: 'user-1',
      email: 'reader@acme.com',
      roles: ['reader'],
      permissions: ['cases:read'],
      can: () => true,
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await built.connect(serverTransport);
    const client = new Client({ name: 'conformance', version: '1.0.0' });
    await client.connect(clientTransport);
    await client.callTool({ name: 'read_case', arguments: { id: 'C1' } });
    await client.close();

    const success = seen.at(-1)!;
    expect(success.type).toBe(events.audit.type);
    expect(wireKeys(success)).toEqual(expect.arrayContaining(events.audit.required));
    expect(wireKeys(success).filter((key) => !events.audit.keys.includes(key))).toEqual([]);
    expect(events.audit.kinds).toContain(success.kind);
    for (const event of seen) expect(events.audit.phases).toContain(event.phase);

    // One call, two events, one id — which is what a dashboard joins them on.
    expect(new Set(seen.map((event) => event.callId)).size).toBe(1);
    expect(success.callId).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('emits the decision record both packages agreed on', async () => {
    const decisions: AuthorizationDecisionEvent[] = [];
    await emitDecision(
      (event) => void decisions.push(event),
      {
        issuer: 'https://auth.example.com',
        sub: 'user-1',
        email: 'reader@acme.com',
        roles: ['reader'],
        permissions: ['cases:read'],
        can: () => true,
      },
      'deny',
      'not_permitted',
    );

    const decision = decisions[0]!;
    expect(decision.type).toBe(events.decision.type);
    expect(wireKeys(decision)).toEqual(expect.arrayContaining(events.decision.required));
    expect(wireKeys(decision).filter((key) => !events.decision.keys.includes(key))).toEqual([]);
  });
});
