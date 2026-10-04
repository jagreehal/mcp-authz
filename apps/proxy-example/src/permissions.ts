/**
 * Permission map for the upstream catalogue.
 *
 * Generate or refresh with:
 *
 *   npx mcp-authz record --upstream "$UPSTREAM_URL" --token "$UPSTREAM_TOKEN" --out src/permissions.ts
 *
 * Price every `TODO:unassigned` entry, then commit the file.
 */
export const PERMISSIONS = {
  search_cases: 'cases:read',
  get_case: 'cases:read',
  update_case: 'cases:write',
  'prompt:triage': 'cases:read',
  'resource:cases': 'cases:read',
  'resource:case': 'cases:read',
} as const;

/**
 * Where each resource answers.
 *
 * A `resources/list` names a resource; a `resources/read` names a URI, so the
 * proxy cannot price a read from the labels above alone. `record` writes this
 * for you, templates included, and the proxy refuses to boot without it.
 */
export const RESOURCE_URIS = {
  'resource:cases': 'cases://all',
  'resource:case': 'cases://case/{id}',
} as const;

/**
 * What each capability said to the model when the map was recorded.
 *
 * A permission prices a name; the upstream decides what stands behind it. The
 * proxy hides a capability whose definition no longer matches this, so the
 * upstream cannot keep an approved name and rewrite what it tells the model.
 * `record` writes this from the live upstream; re-record to approve a change.
 */
export const DEFINITIONS = {
  search_cases: {
    description: 'Find cases',
    inputSchema: { properties: { q: { type: 'string' } }, type: 'object' },
    name: 'search_cases',
  },
  get_case: {
    description: 'One case',
    inputSchema: { properties: { id: { type: 'string' } }, required: ['id'], type: 'object' },
    name: 'get_case',
  },
  update_case: {
    description: 'Change a case',
    inputSchema: { properties: { id: { type: 'string' } }, required: ['id'], type: 'object' },
    name: 'update_case',
  },
  'prompt:triage': { description: 'Walk a failure', name: 'triage' },
  'resource:cases': { mimeType: 'text/plain', name: 'cases', uri: 'cases://all' },
  'resource:case': { mimeType: 'text/plain', name: 'case', uriTemplate: 'cases://case/{id}' },
};
