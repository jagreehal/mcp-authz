import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { Identity } from './identity';
import { definePolicy, type Policy } from './policy';
import { classifyScopedRequest } from './routing';
import { scopesForCapability, scopesFromMcpHeaders, type CapabilityScopeMap } from './scopes';

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
