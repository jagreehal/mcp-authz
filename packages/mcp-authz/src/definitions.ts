/**
 * What a capability says to the model, and whether that has changed.
 *
 * A name is not consent to whatever a server later puts behind it. A server can
 * keep an approved tool's name and rewrite its description to steer the model,
 * or add an argument to carry data out. So the definition is recorded when a
 * person approves it, and held to that record from then on: by `wrap` for a
 * stdio server, by `createMcpProxy` for a remote one.
 *
 * No SDK and no `node:` imports, so the proxy can use it on any runtime.
 */

import type { Client, Transport } from '@modelcontextprotocol/client';

/**
 * Left out of a definition: servers stamp these per build, the model does not
 * read them, and a record that churns teaches people to ignore its diff. Every
 * other field is kept, so the next field the spec adds is covered by default.
 */
const UNRECORDED = new Set(['_meta', 'icons']);

export type Definition = Record<string, unknown>;

/**
 * Where a server's own `instructions` are recorded: beside its capabilities,
 * because they reach the model the same way a description does, and a server
 * that keeps every tool identical could otherwise change what it tells the
 * model there instead.
 */
export const INSTRUCTIONS = 'server:instructions';

/** The labels a record must cover and does not, so a gap fails loudly rather than passing unchecked. */
export function missingDefinitions(
  labels: Iterable<string>,
  definitions: ReadonlyMap<string, unknown>,
): string[] {
  return [...labels].filter((label) => {
    const definition = definitions.get(label);
    return typeof definition !== 'object' || definition === null || Array.isArray(definition);
  });
}

/** The parts of a listed tool, prompt or resource that are held to the record. */
export function definitionOf(item: Record<string, unknown>): Definition {
  return canonical(
    Object.fromEntries(Object.entries(item).filter(([field]) => !UNRECORDED.has(field))),
  ) as Definition;
}

/** The fields that differ, compared regardless of key order. */
export function changedFields(recorded: Definition, live: Definition): string[] {
  const fields = new Set([...Object.keys(recorded), ...Object.keys(live)].filter((f) => !UNRECORDED.has(f)));
  const same = (a: unknown, b: unknown) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
  return [...fields].sort().filter((field) => !same(recorded[field], live[field]));
}

/**
 * Key order is an accident of how a value was built, so sort it away. Without
 * this an SDK that emitted the same definition in a different order would churn
 * every record, and teach people to ignore the diff.
 */
export function canonical(value: unknown): unknown {
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

/**
 * Characters a person reviewing the text cannot see but a model reads:
 * zero-width characters, bidirectional overrides that reorder what is
 * displayed, and the Unicode tag block, which can spell out a whole hidden
 * sentence. Not U+200D, the joiner inside every family or flag emoji: flagging
 * it would flag honest output until nobody reads the flag.
 */
const INVISIBLE =
  /[\u200B\u200C\u200E\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]|[\u{E0000}-\u{E007F}]/u;

/**
 * Wording seen in published tool-poisoning attacks: text addressed to the model
 * rather than describing the tool. A short list on purpose. It flags a
 * definition for a closer read and decides nothing, and a long list would flag
 * honest tools until nobody reads the flag.
 */
const ADDRESSED_TO_MODEL = [
  /ignore (all |any )?(previous|prior|above) (instructions|prompts)/i,
  /<\/?(important|system|instructions?)>/i,
  /do not (tell|inform|mention|alert|notify) the user/i,
  /without (telling|informing|asking) the user/i,
  /\bid_rsa\b|~\/\.ssh|\.aws\/credentials/i,
];

/**
 * Text with each invisible character spelled out as `\u{200B}`, so a person
 * reading a listing or a diff sees what the model will read.
 */
export function reveal(text: string): string {
  return text.replace(new RegExp(INVISIBLE.source, 'gu'), (char) => {
    return `\\u{${char.codePointAt(0)!.toString(16).toUpperCase()}}`;
  });
}

/** Why a definition deserves a closer read before it is approved, if it does. */
export function suspicious(definition: Definition): string[] {
  const text = JSON.stringify(definition);
  const reasons: string[] = [];
  if (INVISIBLE.test(text)) reasons.push('contains invisible characters');
  if (ADDRESSED_TO_MODEL.some((pattern) => pattern.test(text))) {
    reasons.push('contains text addressed to the model');
  }
  return reasons;
}

const LISTED = [
  ['tools', ''],
  ['prompts', 'prompt:'],
  ['resources', 'resource:'],
  ['resourceTemplates', 'resource:'],
] as const;

/**
 * Every listing that arrives on a client transport, as the server wrote it and
 * keyed by the label `gate()` gives it. A record is compared against what the
 * proxy and `wrap` read off the wire, so it is taken from the wire too, not from
 * what the SDK parsed it into. Install after `client.connect`, which sets the
 * handler this wraps.
 */
export function captureListings(transport: Transport): Map<string, Record<string, unknown>> {
  const listed = new Map<string, Record<string, unknown>>();
  const deliver = transport.onmessage;
  transport.onmessage = (message, ...rest) => {
    const result = (message as { result?: Record<string, unknown> }).result;
    for (const [field, prefix] of LISTED) {
      const items = result?.[field];
      if (!Array.isArray(items)) continue;
      for (const item of items as Record<string, unknown>[])
        listed.set(`${prefix}${String(item.name)}`, item);
    }
    deliver?.(message, ...rest);
  };
  return listed;
}

/**
 * Connect a client and list everything the server advertises, returning each
 * item as the server wrote it, keyed by label, with its instructions under
 * `server:instructions`. One function for recording a catalogue and for
 * checking it later, so the two cannot read a server differently.
 *
 * Only what the server says it has is asked for: the SDK answers an
 * unadvertised list with a warning on stdout, which is the generated module
 * when a caller redirects it. The SDK follows `nextCursor` itself.
 */
export async function listCatalogue(
  client: Client,
  transport: Transport,
): Promise<Map<string, Record<string, unknown>>> {
  const listed = captureListings(transport);
  await client.connect(transport);
  // Read from the client rather than the wire: version negotiation can answer
  // `server/discover` before the transport hands anything on. A string comes
  // through parsing unchanged, so this is what the server said.
  const instructions = client.getInstructions();
  if (instructions !== undefined) listed.set(INSTRUCTIONS, { instructions });
  const advertised = client.getServerCapabilities() ?? {};
  await Promise.all([
    advertised.tools && client.listTools(),
    advertised.prompts && client.listPrompts(),
    advertised.resources && client.listResources(),
    advertised.resources && client.listResourceTemplates(),
  ]);
  return listed;
}
