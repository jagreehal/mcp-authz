import { createHash } from 'node:crypto';
import { Client } from '@modelcontextprotocol/client';
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
};

function digest(parts: unknown): string {
  return createHash('sha256').update(JSON.stringify(parts)).digest('hex').slice(0, 16);
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
    const [tools, prompts, resources, templates] = await Promise.all([
      client.listTools(),
      client.listPrompts(),
      client.listResources(),
      client.listResourceTemplates(),
    ]);
    const labelled: [string, unknown][] = [
      ...tools.tools.map((tool) => [tool.name, tool] as [string, unknown]),
      ...prompts.prompts.map((prompt) => [`prompt:${prompt.name}`, prompt] as [string, unknown]),
      ...resources.resources.map((resource) => [`resource:${resource.name}`, resource] as [string, unknown]),
      ...templates.resourceTemplates.map(
        (template) => [`resource:${template.name}`, template] as [string, unknown],
      ),
    ];
    const names = labelled.map(([label]) => label).sort();
    const byLabel = new Map(labelled);
    const fingerprints: Record<string, string> = {};
    for (const label of names) {
      const entry = byLabel.get(label) as { description?: string; inputSchema?: unknown } | undefined;
      // Named fields in a fixed order rather than the whole entry: an SDK that
      // adds or reorders a key must not churn every fingerprint in the snapshot.
      fingerprints[label] = digest({
        name: label,
        description: entry?.description,
        inputSchema: entry?.inputSchema,
      });
    }
    return { names, fingerprints };
  } finally {
    await client.close();
    await server.close();
  }
}
