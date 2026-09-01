import { describe, expect, it } from 'vitest';
import { filterListingResult, filterToolsList } from './catalogue';
import { createPrincipal } from './policy';

const principal = createPrincipal(
  { issuer: 'https://auth.acme.com', sub: 'dana', email: 'dana@acme.com', emailVerified: true, claims: {} },
  ['reader'],
  ['cases:read'],
);

const permissions = new Map([
  ['search_cases', 'cases:read'],
  ['update_case', 'cases:write'],
  ['ghost_tool', 'cases:admin'],
]);

describe('filterToolsList', () => {
  it('hides capabilities with no map entry or permission grant', () => {
    const tools = [{ name: 'search_cases' }, { name: 'update_case' }, { name: 'ghost_tool' }];
    expect(filterToolsList(tools, principal, permissions).map((tool) => tool.name)).toEqual(['search_cases']);
  });
});

describe('filterListingResult', () => {
  it('filters the tools field on a JSON-RPC result object', () => {
    const result = filterListingResult(
      'tools/list',
      { tools: [{ name: 'search_cases' }, { name: 'update_case' }] },
      principal,
      permissions,
    );
    expect(result.tools).toEqual([{ name: 'search_cases' }]);
  });

  it('filters prompts, resources and templates', () => {
    expect(
      filterListingResult(
        'prompts/list',
        { prompts: [{ name: 'triage' }, { name: 'secret' }] },
        principal,
        new Map([['prompt:triage', 'cases:read']]),
      ).prompts,
    ).toEqual([{ name: 'triage' }]);
    expect(
      filterListingResult(
        'resources/list',
        { resources: [{ name: 'cases' }, { name: 'secret' }] },
        principal,
        new Map([['resource:cases', 'cases:read']]),
      ).resources,
    ).toEqual([{ name: 'cases' }]);
    expect(
      filterListingResult(
        'resources/templates/list',
        { resourceTemplates: [{ name: 'case' }, { name: 'secret' }] },
        principal,
        new Map([['resource:case', 'cases:read']]),
      ).resourceTemplates,
    ).toEqual([{ name: 'case' }]);
  });
});
