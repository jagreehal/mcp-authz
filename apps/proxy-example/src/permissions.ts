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
