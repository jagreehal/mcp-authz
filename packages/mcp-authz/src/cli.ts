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
  mcp-authz record --upstream <url> [--token <bearer>] [--out <permissions.ts>]
  mcp-authz record <connector.ts|--upstream <url>> --check <permissions.ts>
  mcp-authz explain <policy.json> --identity <identity.json>|- [--capabilities <map.json>]

Files
  <policy.json>     the object you would hand definePolicy
  --capabilities    a .json map, or a .ts/.js module exporting PERMISSIONS,
                    which is what record writes
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
      upstream: { type: 'string' },
      token: { type: 'string' },
      check: { type: 'string' },
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
    if (values.upstream) {
      return record({ upstream: values.upstream, token: values.token }, values.out, values.check);
    }
    if (!policyPath) {
      process.stderr.write(
        'record needs a module whose default export builds the server, or --upstream <url>.\n',
      );
      return 1;
    }
    return record({ module: policyPath }, values.out, values.check);
  }
  if (!policyPath) {
    process.stderr.write(`${command} needs a path to a policy file.\n`);
    return 1;
  }

  const policy = definePolicy(readJson(policyPath) as PolicySpec);

  const run = (capabilities: ReadonlyMap<string, string> | undefined): number => {
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
  };

  if (!values.capabilities) return run(undefined);
  // `record` writes a module, so reading only JSON here left the documented loop
  // open: you could generate a map and then not check it. A .json path stays
  // synchronous, which is what every other command is.
  if (values.capabilities.endsWith('.json')) {
    return run(new Map(Object.entries(readJson(values.capabilities) as Record<string, string>)));
  }
  return importCapabilities(values.capabilities).then(run);
}

/** Read the map out of a module `record` produced, or one written by hand. */
async function importCapabilities(path: string): Promise<ReadonlyMap<string, string>> {
  const loaded = (await import(pathToFileURL(resolve(path)).href)) as Record<string, unknown>;
  const map = (loaded.PERMISSIONS ?? loaded.default) as Record<string, string> | undefined;
  if (!map || typeof map !== 'object') {
    throw new Error(`${path} must export PERMISSIONS, or default, mapping each capability to a permission.`);
  }
  return new Map(Object.entries(map));
}

/**
 * Read the capabilities off a connector and write the map to start from.
 *
 * `mcp-authz/testing` is imported lazily, and the client it needs is an optional
 * peer, so the other commands keep the CLI's no-dependency property and only
 * somebody running `record` is asked to install anything.
 */
type RecordSource = { module: string } | { upstream: string; token?: string };

async function record(
  source: RecordSource,
  out: string | undefined,
  against: string | undefined,
): Promise<number> {
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

  let capabilities;
  if ('upstream' in source) {
    // Only a URL and a credential: the case the library has always told people
    // to solve with a gateway. Reading it is not enforcing it.
    capabilities = await toolkit.recordUpstream(source.upstream, { bearer: source.token });
  } else {
    const loaded = (await import(pathToFileURL(resolve(source.module)).href)) as {
      default?: () => unknown;
    };
    if (typeof loaded.default !== 'function') {
      process.stderr.write(`${source.module} must default-export a function that builds the server.\n`);
      return 1;
    }
    capabilities = await toolkit.recordCapabilities(loaded.default as never);
  }
  if (against) return drift(capabilities, against);

  const generated = toolkit.toPermissionsModule(capabilities);
  if (out) writeFileSync(out, generated);
  else process.stdout.write(generated);
  return 0;
}

/**
 * Compare what the server has now against the map somebody committed.
 *
 * The snapshot story needs a test runner, and the upstream path has none — this
 * is what lets a URL-only server be watched from CI at all.
 */
async function drift(
  live: { names: string[]; fingerprints: Record<string, string> },
  path: string,
): Promise<number> {
  const loaded = (await import(pathToFileURL(resolve(path)).href)) as {
    PERMISSIONS?: Record<string, string>;
    FINGERPRINTS?: Record<string, string>;
  };
  const priced = Object.keys(loaded.PERMISSIONS ?? {});
  const recorded = loaded.FINGERPRINTS ?? {};

  const added = live.names.filter((name) => !priced.includes(name));
  const removed = priced.filter((name) => !live.names.includes(name));
  const changed = live.names.filter(
    (name) => priced.includes(name) && recorded[name] && recorded[name] !== live.fingerprints[name],
  );

  // A map with no baseline can still be checked for names, but not for a
  // capability that changed under one. Silence there reads as a pass.
  const unbaselined =
    Object.keys(recorded).length === 0
      ? ` — ${path} carries no FINGERPRINTS, so definitions were not compared; re-record to add one`
      : '';

  if (added.length === 0 && removed.length === 0 && changed.length === 0) {
    process.stdout.write(`${live.names.length} capabilities, names unchanged since ${path}${unbaselined}\n`);
    return 0;
  }

  const lines = ['The server no longer matches the recorded capabilities:', ''];
  for (const name of added)
    lines.push(`  + ${name}`, '      never priced, so nobody decided who may reach it');
  for (const name of removed)
    lines.push(`  - ${name}`, '      priced here, but the server no longer offers it');
  for (const name of changed)
    lines.push(`  ~ ${name}`, '      same name, different definition than the one recorded');
  if (unbaselined) lines.push('', `Note:${unbaselined.slice(3)}`);
  lines.push('', 'Re-record when the change is expected, and review the diff.', '');
  process.stdout.write(lines.join('\n'));
  return 1;
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
