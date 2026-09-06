/**
 * Rendering a permission map as source, shared by everything that records a
 * catalogue.
 *
 * Its own module because the MCP recorder needs an optional peer dependency to
 * talk to a server, and the OpenAPI one only needs a file it was handed. A
 * caller after the scaffold should not have to install a client to get it.
 */

export type PermissionMapRecord = {
  /** Every capability, sorted, labelled the way the gate labels it. */
  names: string[];
  /** A digest per capability, when the source can produce one. */
  fingerprints?: Record<string, string>;
  /** `resource:` labels to the URI or template each answers on. */
  resourceUris?: Record<string, string>;
};

/**
 * A permission map to start from, priced so it cannot be forgotten.
 *
 * Every capability gets a placeholder no role grants, which `reconcile` reports
 * as unreachable and the boot refuses. The scaffold is deliberately useless
 * until a person has decided what each capability costs — that decision is the
 * whole point of the file, and a default would quietly make it for them.
 *
 * Returned as source rather than written, so the caller chooses where it lands.
 */
export const UNASSIGNED = 'TODO:unassigned';

export function toPermissionsModule(record: PermissionMapRecord): string {
  const entries = record.names.map((label) => `  ${quote(label)}: ${literal(UNASSIGNED)},`);
  return [
    '// Generated from a recorded catalogue. Replace every TODO with a real permission.',
    '',
    'export const PERMISSIONS = {',
    ...entries,
    '} as const;',
    '',
    'export type Permission = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];',
    ...fingerprintLines(record),
    ...resourceUriLines(record.resourceUris ?? {}),
    '',
  ].join('\n');
}

/**
 * Only emitted when the recorder could produce digests. An OpenAPI document is
 * already a file in the repository, diffed on the pull request by whoever
 * changed it, so there is nothing for a second baseline to catch.
 */
function fingerprintLines(record: PermissionMapRecord): string[] {
  const fingerprints = record.fingerprints ?? {};
  if (Object.keys(fingerprints).length === 0) return [];
  return [
    '',
    '// What each capability looked like when this was recorded. A separate export',
    '// because gate() takes the flat map above; this is the baseline CI compares.',
    'export const FINGERPRINTS = {',
    ...record.names.map((label) => `  ${quote(label)}: ${literal(fingerprints[label] ?? '')},`),
    '} as const;',
  ];
}

/**
 * Only emitted when the server has resources, so a tools-only map stays a map.
 * `createMcpProxy` needs this to price a read, which names a URI and never a
 * label; `gate()` never sees it.
 */
function resourceUriLines(resourceUris: Record<string, string>): string[] {
  const labels = Object.keys(resourceUris).sort();
  if (labels.length === 0) return [];
  return [
    '',
    '// Where each resource answers. createMcpProxy() matches a read against these,',
    '// templates included, because a resources/read carries a URI and not a label.',
    'export const RESOURCE_URIS = {',
    ...labels.map((label) => `  ${quote(label)}: ${literal(resourceUris[label] ?? '')},`),
    '} as const;',
  ];
}

/**
 * Bare where it is a valid identifier, quoted where the label carries a prefix.
 *
 * `__proto__` gets neither. In an object literal it sets the prototype instead
 * of creating a property — as an identifier *and* as a string key — so a
 * capability by that name would silently vanish from the map that prices it.
 * Only a computed key makes an own property.
 */
function quote(label: string): string {
  if (label === '__proto__') return `[${literal(label)}]`;
  return /^[A-Za-z_$][\w$]*$/.test(label) ? label : literal(label);
}

/**
 * A string literal, escaped.
 *
 * Names and URIs come from the server being recorded, not from us. A quote or a
 * backslash in either one would otherwise close the literal early and emit a
 * module that does not parse — or, worse, one that parses into something else.
 */
function literal(value: string): string {
  return JSON.stringify(value);
}
