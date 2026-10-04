import { definitionOf, INSTRUCTIONS, listCatalogue, type Definition } from './definitions';
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
  /**
   * What each capability says to the model, as served. A snapshot catches one
   * changing under you, `record --check` shows the words that changed, and
   * `createMcpProxy` hides a capability that no longer matches.
   */
  definitions: Record<string, Definition>;
  /**
   * `resource:` labels to the URI or URI template each answers on.
   *
   * A listing names a resource; a read names a URI, and only the server knows
   * which URIs a label covers. `createMcpProxy` authorizes reads by URI, so it
   * needs this alongside the permission map — and refuses to boot without it.
   */
  resourceUris: Record<string, string>;
};

/**
 * An upstream is recorded in 2026-07-28 and nothing older: the proxy that
 * enforces the record speaks only that, and a record read through another
 * dialect could differ from what the proxy later compares it against. Your own
 * server, connected in process, is recorded in whichever era it offers.
 */
const MODERN = { versionNegotiation: { mode: { pin: '2026-07-28' } } } as const;
const EITHER = { versionNegotiation: { mode: 'auto' } } as const;

export async function recordCapabilities(
  factory: () => McpServer | Promise<McpServer>,
): Promise<CapabilityRecord> {
  const server = await factory();
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: 'mcp-authz-record-capabilities', version: '1.0.0' }, EITHER);
  try {
    return recordFrom(await listCatalogue(client, clientTransport));
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
  const client = new Client({ name: 'mcp-authz-record-capabilities', version: '1.0.0' }, MODERN);
  try {
    return recordFrom(await listCatalogue(client, transport));
  } finally {
    await client.close();
  }
}

/**
 * The record, built from the listings as the server wrote them, which is what
 * the proxy will compare against later.
 *
 * Built from entries rather than by assignment. A server may advertise a
 * capability called `__proto__`, and `dict['__proto__'] = definition` runs the
 * inherited setter instead of storing anything — losing exactly the record that
 * would have caught that capability changing under you. `fromEntries` defines
 * own properties, while the result stays an ordinary object.
 */
function recordFrom(listed: ReadonlyMap<string, Record<string, unknown>>): CapabilityRecord {
  const names = [...listed.keys()].filter((label) => label !== INSTRUCTIONS).sort();
  const definitions = Object.fromEntries(
    [...listed].map(([label, item]) => [label, definitionOf(item)] as const),
  );
  const resourceUris = Object.fromEntries(
    names
      .filter((label) => label.startsWith('resource:'))
      .map((label) => [label, String(listed.get(label)!.uri ?? listed.get(label)!.uriTemplate)] as const),
  );
  return { names, definitions, resourceUris };
}

export { toPermissionsModule, UNASSIGNED, type PermissionMapRecord } from './permissions-module';
