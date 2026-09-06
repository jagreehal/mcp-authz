import { createHash } from 'node:crypto';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { InMemoryTransport, type McpServer } from '@modelcontextprotocol/server';

/**
 * What a caller can reach, read from the server rather than from your notes.
 *
 * A permission map has to name every capability a server registers, and nothing
 * generates that list today — you write it by hand and hope. This connects a
 * real client to your own server over an in-memory pair and asks it, so the
 * answer is the one a caller would get.
 *
 * Build the server *ungated* here. A gated server answers per principal, so
 * listing one would hand you a map missing exactly the capabilities that most
 * need a price.
 */

export type CapabilityRecord = {
  /** Every capability, labelled as `gate()` labels them, sorted. */
  names: string[];
  /** A digest per capability, so a snapshot can catch one changing under you. */
  fingerprints: Record<string, string>;
  /**
   * `resource:` labels to the URI or URI template each answers on.
   *
   * A listing names a resource; a read names a URI, and only the server knows
   * which URIs a label covers. `createMcpProxy` authorizes reads by URI, so it
   * needs this alongside the permission map — and refuses to boot without it.
   */
  resourceUris: Record<string, string>;
};

function digest(parts: unknown): string {
  return createHash('sha256')
    .update(JSON.stringify(canonical(parts)))
    .digest('hex')
    .slice(0, 16);
}

/**
 * Key order is an accident of how a value was built, so sort it away. Without
 * this an SDK that emitted the same definition in a different order would churn
 * every fingerprint in a snapshot and teach people to ignore the diff.
 */
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([key, inner]) => [key, canonical(inner)]),
    );
  }
  return value;
}

export async function recordCapabilities(
  factory: () => McpServer | Promise<McpServer>,
): Promise<CapabilityRecord> {
  const server = await factory();
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: 'mcp-authz-record-capabilities', version: '1.0.0' });
  await client.connect(clientTransport);

  try {
    return await listFrom(client);
  } finally {
    await client.close();
    await server.close();
  }
}

/**
 * Record a server you can only reach by URL.
 *
 * The objection that rules out listing a *gated* server does not apply here: an
 * upstream reached with a service credential answers with everything it has, so
 * the map is complete. Pass `fetch` to drive a handler directly instead of a
 * socket.
 */
export async function recordUpstream(
  url: string | URL,
  options: { bearer?: string; fetch?: typeof fetch } = {},
): Promise<CapabilityRecord> {
  const transport = new StreamableHTTPClientTransport(new URL(url), {
    ...(options.fetch ? { fetch: options.fetch } : {}),
    ...(options.bearer ? { authProvider: { token: async () => options.bearer as string } } : {}),
  });
  const client = new Client({ name: 'mcp-authz-record-capabilities', version: '1.0.0' });
  await client.connect(transport);
  try {
    return await listFrom(client);
  } finally {
    await client.close();
  }
}

async function listFrom(client: Client): Promise<CapabilityRecord> {
  {
    // Ask only for what the server said it has. The SDK answers an unadvertised
    // list with a warning and an empty result, and that warning is written to
    // stdout — which is the generated module when the caller redirects it.
    const advertised = client.getServerCapabilities() ?? {};
    const none = { tools: [], prompts: [], resources: [], resourceTemplates: [] };
    const [tools, prompts, resources, templates] = await Promise.all([
      advertised.tools ? client.listTools() : none,
      advertised.prompts ? client.listPrompts() : none,
      advertised.resources ? client.listResources() : none,
      advertised.resources ? client.listResourceTemplates() : none,
    ]);
    const labelled: [string, unknown][] = [
      ...tools.tools.map((tool) => [tool.name, tool] as [string, unknown]),
      ...prompts.prompts.map((prompt) => [`prompt:${prompt.name}`, prompt] as [string, unknown]),
      ...resources.resources.map((resource) => [`resource:${resource.name}`, resource] as [string, unknown]),
      ...templates.resourceTemplates.map(
        (template) => [`resource:${template.name}`, template] as [string, unknown],
      ),
    ];
    const resourceUris = Object.fromEntries([
      ...resources.resources.map((resource) => [`resource:${resource.name}`, resource.uri] as const),
      ...templates.resourceTemplates.map(
        (template) => [`resource:${template.name}`, template.uriTemplate] as const,
      ),
    ]);
    const names = labelled.map(([label]) => label).sort();
    const byLabel = new Map(labelled);
    // Built from entries rather than by assignment. A server may advertise a
    // capability called `__proto__`, and `dict['__proto__'] = digest` runs the
    // inherited setter instead of storing anything — losing exactly the record
    // that would have caught that capability changing under you. `fromEntries`
    // defines own properties, so the digest survives, while the result stays an
    // ordinary object: callers still get `hasOwnProperty` and everything else
    // they would expect on a `Record`.
    const fingerprints = Object.fromEntries(
      // The whole definition as served, not a chosen handful of fields. A tool
      // has an inputSchema, a prompt has arguments, a resource template has a
      // uriTemplate — and picking fields by hand means the next kind of change
      // is the one nobody fingerprinted.
      names.map((label) => [label, digest({ label, definition: byLabel.get(label) })] as const),
    );
    return { names, fingerprints, resourceUris };
  }
}

export { toPermissionsModule, UNASSIGNED, type PermissionMapRecord } from './permissions-module';
