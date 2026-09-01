#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { definePolicy, reconcile, type Identity, type MatchedRule, type PolicySpec } from './policy';

/**
 * Two questions a policy file cannot answer by being read.
 *
 * `check` runs the same reconciliation the server runs at boot, without booting
 * it, so CI catches drift on the pull request rather than on deploy. `explain`
 * answers "why can Alice do this", which nothing else answers at all: the
 * decision carries the permissions, and only `policy.explain` carries the rules
 * that produced them.
 *
 * Deliberately no colour library and no argument parser. `node:util` has one,
 * and a dependency here would be a dependency in every install of the package.
 */

const USAGE = `mcp-authz — inspect a policy without running a server

  mcp-authz check <policy.json> [--capabilities <map.json>]
  mcp-authz record <connector.ts> [--out <permissions.ts>]
  mcp-authz explain <policy.json> --identity <identity.json>|- [--capabilities <map.json>]

Files
  <policy.json>     the object you would hand definePolicy
  --capabilities    { "get_case": "cases:read", "prompt:triage": "cases:write" }
  --identity        an Identity, or a decoded token payload (iss, sub, email,
                    email_verified, hd). Use - to read it from stdin.

Exit codes
  0  fine, warnings included
  1  the policy is invalid, or a capability no role can reach
`;

export function main(argv: readonly string[]): number | Promise<number> {
  const { values, positionals } = parseArgs({
    args: [...argv],
    allowPositionals: true,
    options: {
      capabilities: { type: 'string' },
      identity: { type: 'string' },
      out: { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
  });

  const [command, policyPath] = positionals;
  if (values.help || !command) {
    process.stdout.write(USAGE);
    return values.help ? 0 : 1;
  }
  // `record` takes a module rather than a policy, so it branches before the
  // policy file is read.
  if (command === 'record') {
    if (!policyPath) {
      process.stderr.write('record needs a path to a module whose default export builds the server.\n');
      return 1;
    }
    return record(policyPath, values.out);
  }
  if (!policyPath) {
    process.stderr.write(`${command} needs a path to a policy file.\n`);
    return 1;
  }

  const policy = definePolicy(readJson(policyPath) as PolicySpec);
  const capabilities = values.capabilities
    ? new Map(Object.entries(readJson(values.capabilities) as Record<string, string>))
    : undefined;

  if (command === 'check') return check(policy, capabilities);
  if (command === 'explain') {
    if (!values.identity) {
      process.stderr.write('explain needs --identity <file>, or - for stdin.\n');
      return 1;
    }
    return explain(policy, identityFrom(readJson(values.identity)), capabilities);
  }

  process.stderr.write(`Unknown command '${command}'.\n\n${USAGE}`);
  return 1;
}

/**
 * Read the capabilities off a connector and write the map to start from.
 *
 * `mcp-authz/testing` is imported lazily, and the client it needs is an optional
 * peer, so the other commands keep the CLI's no-dependency property and only
 * somebody running `record` is asked to install anything.
 */
async function record(modulePath: string, out: string | undefined): Promise<number> {
  let toolkit: typeof import('./testing');
  try {
    toolkit = await import('./testing');
  } catch {
    process.stderr.write(
      'record needs @modelcontextprotocol/client, which is an optional peer.\n' +
        '  npm install -D @modelcontextprotocol/client\n',
    );
    return 1;
  }

  const loaded = (await import(pathToFileURL(resolve(modulePath)).href)) as {
    default?: () => unknown;
  };
  if (typeof loaded.default !== 'function') {
    process.stderr.write(`${modulePath} must default-export a function that builds the server.\n`);
    return 1;
  }

  const capabilities = await toolkit.recordCapabilities(loaded.default as never);
  const source = toolkit.toPermissionsModule(capabilities);
  if (out) writeFileSync(out, source);
  else process.stdout.write(source);
  return 0;
}

function check(
  policy: ReturnType<typeof definePolicy>,
  capabilities: ReadonlyMap<string, string> | undefined,
): number {
  const lines = [
    `${policy.roles.size} role${policy.roles.size === 1 ? '' : 's'}`,
    `${policy.permissions.length} permission${policy.permissions.length === 1 ? '' : 's'}`,
  ];
  if (capabilities) lines.push(`${capabilities.size} capabilities`);
  for (const line of lines) process.stdout.write(`  ok  ${line}\n`);

  if (!capabilities) {
    process.stdout.write('\nPass --capabilities to reconcile the policy against the tools that use it.\n');
    return 0;
  }

  // The same call the server makes at boot, so the two cannot disagree.
  const { error, warning } = reconcile(policy.roles, capabilities);
  if (warning) process.stdout.write(`\n${warning}\n`);
  if (error) {
    process.stderr.write(`\n${error}\n`);
    return 1;
  }
  return 0;
}

function explain(
  policy: ReturnType<typeof definePolicy>,
  identity: Identity,
  capabilities: ReadonlyMap<string, string> | undefined,
): number {
  const { principal, matched, deniedBy } = policy.explain(identity);
  process.stdout.write(`${identity.email ?? identity.sub}\n\n`);

  process.stdout.write('Matched rules\n');
  if (matched.length === 0) {
    process.stdout.write('  none, so this caller holds nothing\n');
  }
  for (const rule of matched) {
    const verdict = rule.deny ? 'DENY' : rule.roles.join(', ');
    process.stdout.write(`  rule ${rule.index}  ${describe(rule)} -> ${verdict}\n`);
  }

  if (deniedBy) {
    process.stdout.write(`\nRule ${deniedBy.index} denies, which empties the grant whatever else matched.\n`);
  }

  process.stdout.write(`\nEffective roles\n  ${list(principal.roles)}\n`);
  const permissions = principal.permissions.map((p) => (p === '*' ? '* (every permission)' : p));
  process.stdout.write(`\nPermissions\n  ${list(permissions)}\n`);

  if (capabilities) {
    const usable = [...capabilities]
      .filter(([, permission]) => principal.can(permission))
      .map(([capability]) => capability);
    process.stdout.write(`\nCapabilities\n  ${list(usable)}\n`);
  }
  return 0;
}

/** Every field of a match, so a rule that matched on two things reads as two. */
function describe(rule: MatchedRule): string {
  const parts = Object.entries(rule.match).flatMap(([field, value]) =>
    field === 'claim'
      ? Object.entries(value as Record<string, string>).map(([path, want]) => `${path}=${want}`)
      : [`${field}=${String(value)}`],
  );
  return parts.length > 0 ? parts.join(' and ') : 'every caller';
}

function list(values: readonly string[]): string {
  return values.length > 0 ? values.join('\n  ') : 'none';
}

/**
 * An Identity as written, or a decoded token payload.
 *
 * This mirrors what the verifier produces, for a caller who has not been
 * verified: `explain` answers a what-if, so it trusts the file it was handed.
 */
function identityFrom(value: unknown): Identity {
  if (typeof value !== 'object' || value === null) throw new Error('Identity must be an object.');
  const raw = value as Record<string, unknown>;
  const issuer = str(raw.issuer) ?? str(raw.iss);
  const sub = str(raw.sub);
  if (!issuer || !sub) throw new Error("Identity needs an issuer ('iss') and a subject ('sub').");
  return {
    issuer,
    sub,
    email: str(raw.email),
    emailVerified: raw.emailVerified === true || raw.email_verified === true,
    domain: str(raw.domain) ?? str(raw.hd),
    claims: (typeof raw.claims === 'object' && raw.claims !== null ? raw.claims : raw) as Record<
      string,
      unknown
    >,
  };
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path === '-' ? 0 : path, 'utf8'));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    process.exitCode = await main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
