import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { changedFields, definitionOf, INSTRUCTIONS, listCatalogue, type Definition } from './definitions';
import type { UpstreamConfig } from './upstream';

/**
 * An upstream held to the definitions recorded when its permission map was
 * approved.
 *
 * Every capability starts unchecked. A listing that passes through the proxy
 * checks what it carries, and an invocation of anything not checked recently
 * makes the proxy list the upstream itself first, because a client may call
 * without listing, or from a catalogue it cached before the upstream changed.
 * A capability is only ever called after its live definition matched.
 */
export type UpstreamRecord = {
  /** Whether a listed item matches its record, noting the answer. Unrecorded items pass: pricing decides those. */
  matches(label: string, item: Record<string, unknown>): boolean;
  /** Why these labels may not be invoked, or `undefined` when each is recorded, checked and unchanged. */
  refuse(labels: readonly string[]): Promise<string | undefined>;
  /** The instructions to pass on: the live ones when they match the record, otherwise none. */
  instructions(live: unknown): unknown;
};

// How long a checked definition stays trusted before a call checks it again.
const FRESH_MS = 60_000;

export function holdToRecord(
  definitions: ReadonlyMap<string, Definition>,
  upstream: UpstreamConfig,
  list: () => Promise<Map<string, Record<string, unknown>>> = () => listUpstream(upstream),
): UpstreamRecord {
  const checkedAt = new Map<string, number>();
  const changed = new Map<string, string[]>();
  const fresh = (label: string) => Date.now() - (checkedAt.get(label) ?? -Infinity) < FRESH_MS;

  const matches = (label: string, item: Record<string, unknown>): boolean => {
    const recorded = definitions.get(label);
    if (!recorded) return true;
    const fields = changedFields(recorded, definitionOf(item));
    if (fields.length === 0) {
      changed.delete(label);
      checkedAt.set(label, Date.now());
      return true;
    }
    if (!changed.has(label)) {
      console.warn(
        `mcp-authz proxy: hid ${label}: its ${fields.join(', ')} changed since it was recorded. ` +
          'Review with mcp-authz record --upstream <url> --check <permissions.ts>, then re-record to approve.',
      );
    }
    changed.set(label, fields);
    checkedAt.delete(label);
    return false;
  };

  // One listing at a time, however many calls are waiting on it.
  let listing: Promise<void> | undefined;
  const relist = () =>
    (listing ??= list()
      .then((listed) => {
        for (const [label, item] of listed) if (label !== INSTRUCTIONS) matches(label, item);
      })
      .finally(() => (listing = undefined)));

  let warnedInstructions: unknown;
  return {
    matches,
    async refuse(labels) {
      const recorded = labels.filter((label) => definitions.has(label));
      if (recorded.some((label) => !changed.has(label) && !fresh(label))) {
        try {
          await relist();
        } catch (error) {
          const reason = error instanceof Error ? error.message : String(error);
          return `the upstream's catalogue could not be read to check it (${reason})`;
        }
      }
      for (const label of recorded) {
        const fields = changed.get(label);
        if (fields) return `'${label}', whose ${fields.join(', ')} changed since it was recorded`;
        if (!fresh(label)) return `'${label}', which the upstream no longer lists`;
      }
      return undefined;
    },
    instructions(live) {
      if (live === undefined || live === definitions.get(INSTRUCTIONS)?.instructions) return live;
      if (warnedInstructions !== live) {
        warnedInstructions = live;
        console.warn(
          "mcp-authz proxy: removed the upstream's instructions: they differ from the recorded ones. " +
            'Review with mcp-authz record --upstream <url> --check <permissions.ts>, then re-record to approve.',
        );
      }
      return undefined;
    },
  };
}

/** The upstream's catalogue, read with the service credential as a 2026-07-28 client. */
async function listUpstream(upstream: UpstreamConfig): Promise<Map<string, Record<string, unknown>>> {
  const bearer = typeof upstream.bearer === 'function' ? upstream.bearer : () => upstream.bearer as string;
  const transport = new StreamableHTTPClientTransport(new URL(upstream.url), {
    ...(upstream.fetch ? { fetch: upstream.fetch } : {}),
    authProvider: { token: async () => bearer() },
  });
  const client = new Client(
    { name: 'mcp-authz-proxy', version: '1.0.0' },
    { versionNegotiation: { mode: { pin: '2026-07-28' } } },
  );
  try {
    return await listCatalogue(client, transport);
  } finally {
    await client.close();
  }
}
