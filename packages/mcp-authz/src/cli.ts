#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { definePolicy, reconcile, type Identity, type MatchedRule, type PolicySpec } from './policy';
import { wrap } from './wrap';
import {
  clientEntry,
  discover as discoverTools,
  writeClientConfig,
  parseJsonc,
  readWrapConfig,
  recordedTools,
  schemaPathFor,
  writeWrapConfig,
} from './wrap-config';

/**
 * Two questions a policy file cannot answer by being read.
 *
 * `check` runs the same reconciliation the server runs at boot, without booting
 * it, so CI catches drift on the pull request rather than on deploy. `explain`
 * answers "why can Alice do this", which nothing else answers at all: the
 * decision carries the permissions, and only `policy.explain` carries the rules
 * that produced them.
 *
 * `tools` and `wrap` answer a third: which of a server's tools should this
 * session see. `wrap` reads JSON lines and nothing more, so it works in front of
 * any stdio server; `tools` is the one command that speaks MCP as a client.
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
  mcp-authz tools -- <command> [args...]
  mcp-authz tools --out <name.jsonc> [--client-out <mcp.json>] -- <command> [args...]
  mcp-authz tools --config <name.jsonc> --refresh
  mcp-authz wrap [--allow <a,b> | --deny <a,b>] -- <command> [args...]
  mcp-authz wrap --config <name.jsonc>
  mcp-authz tools --check <name.jsonc>

Files
  <policy.json>     the object you would hand definePolicy
  --capabilities    a .json map, or a .ts/.js module exporting PERMISSIONS,
                    which is what record writes
  --identity        an Identity, or a decoded token payload (iss, sub, email,
                    email_verified, hd). Use - to read it from stdin.

wrap
  Runs a stdio MCP server and hides tools from whoever connects. Put it in
  front of the server in your client's MCP config. With neither flag every
  tool passes through; names are exact and comma-separated.

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
      allow: { type: 'string' },
      deny: { type: 'string' },
      config: { type: 'string' },
      refresh: { type: 'boolean' },
      'client-out': { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
  });

  const [command, policyPath] = positionals;
  // For `tools` and `wrap`, everything after `--` is the server to run, flags
  // included. Other commands keep the usual meaning: a path that starts with -.
  const dashes = argv.indexOf('--');
  const upstream = dashes === -1 ? [] : argv.slice(dashes + 1);
  if (values.help || !command) {
    process.stdout.write(USAGE);
    return values.help ? 0 : 1;
  }
  if (command === 'tools') {
    if (values.check) return checkWrapConfig(values.check, upstream);
    return listTools(upstream, values);
  }
  if (command === 'wrap') return runWrap(upstream, values);
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

  // `check` reads files and starts nothing. Comparing a wrap config with its
  // server means running the command the file names, which belongs to `tools`.
  if (command === 'check' && isWrapConfig(policyPath)) {
    process.stderr.write(
      `${policyPath} is a wrap config. To compare it with its server, which starts the command it ` +
        `names, run: mcp-authz tools --check ${policyPath}\n`,
    );
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

/**
 * Print the names `wrap` takes, with the hints that help choose between them,
 * and with --out or --refresh save them as a config `wrap --config` runs.
 */
function listTools(
  upstream: readonly string[],
  flags: { out?: string; config?: string; refresh?: boolean; 'client-out'?: string },
): number | Promise<number> {
  const refuse = (message: string) => (process.stderr.write(`${message}\n`), 1);
  if (flags.refresh && !flags.config) {
    return refuse('--refresh rewrites a saved config: tools --config <name>.jsonc --refresh');
  }
  if (flags.config && upstream.length > 0) {
    return refuse('tools takes --config or a command after --, not both: the config names its server.');
  }
  // A saved config already holds the command, arguments and directory, so a
  // refresh reruns exactly what was saved rather than asking for it again.
  const saved = flags.config ? readWrapConfig(flags.config) : undefined;
  const [command, ...args] = saved ? [saved.command, ...saved.args] : upstream;
  const cwd = saved?.cwd ?? process.cwd();
  if (saved) announce(saved, flags.config!);
  if (!command) {
    return refuse('tools needs the server command after --, e.g. tools -- npx -y some-mcp');
  }
  const target = flags.refresh ? flags.config : flags.out;
  return discover(command, args, cwd).then((tools) => {
    if (tools === undefined) return 1;
    const width = Math.max(...tools.map((tool) => tool.name.length));
    for (const tool of tools) {
      process.stdout.write(
        `${tool.name.padEnd(width)}  ${tool.hint.padEnd(11)}  ${tool.description}`.trimEnd() + '\n',
      );
    }
    if (!target) {
      // On stderr, so a script reading the list gets only the list.
      process.stderr.write('\nSave these as a config wrap can run: tools --out <name>.jsonc -- ...\n');
      return 0;
    }
    const previous = existsSync(target)
      ? { options: readWrapConfig(target), recorded: recordedTools(target) }
      : undefined;
    const { allowed, commented, added } = writeWrapConfig(target, { command, args, cwd }, tools, previous);
    const summary = previous
      ? `${allowed} allowed, ${commented} commented out, ${added} new since last saved, left commented out`
      : `${allowed} allowed, ${commented} destructive commented out`;
    const lines = ['', `Saved ${target} (${summary}) and ${schemaPathFor(target)}.`];
    if (flags['client-out']) {
      writeClientConfig(flags['client-out'], target);
      lines.push(`Added it to ${flags['client-out']}; give it the env the server needs there.`);
    }
    lines.push(
      "Add this to your client's mcpServers, with the env the server needs:",
      '',
      clientEntry(target),
      '',
    );
    process.stdout.write(lines.join('\n'));
    return 0;
  });
}

/**
 * Discovery with a next step for the two common stops: a command that is not
 * installed, and a server that exits at once, which usually means it wants an
 * API key. The server's own message is already on stderr above this one.
 */
async function discover(command: string, args: readonly string[], cwd?: string) {
  try {
    return await discoverTools(command, args, cwd);
  } catch (error) {
    const code = (error as { code?: unknown }).code;
    process.stderr.write(
      code === 'ENOENT'
        ? `Could not start ${command}: command not found. Install it, or give its full path.\n`
        : 'The server exited before listing its tools. Its own error, if it printed one, is above.\n' +
            'If it needs credentials, export them in this shell first: the env in your client\n' +
            'config is not seen here.\n',
    );
    return undefined;
  }
}

/** Say what is about to run when the command comes from a file. */
function announce(options: { command: string; args: readonly string[] }, path: string): void {
  process.stderr.write(`Running ${[options.command, ...options.args].join(' ')} from ${path}\n`);
}

function isWrapConfig(path: string): boolean {
  if (path === '-') return false;
  try {
    const value = parseJsonc(readFileSync(path, 'utf8'));
    return typeof value === 'object' && value !== null && 'server' in value;
  } catch {
    return false;
  }
}

/**
 * Ask the server what it offers now, and compare it with the config and with
 * the catalogue recorded beside it. Exits 1 on any difference, the way
 * `record --check` does, so CI notices an upgrade that renamed a tool.
 */
async function checkWrapConfig(path: string, upstream: readonly string[]): Promise<number> {
  if (upstream.length > 0) {
    process.stderr.write(
      'tools --check runs the server its config names, so it takes no command after --.\n',
    );
    return 1;
  }
  const options = readWrapConfig(path);
  announce(options, path);
  const discovered = await discover(options.command, options.args, options.cwd);
  if (discovered === undefined) return 1;
  const live = discovered.map((tool) => tool.name);
  const recorded = recordedTools(path);
  const listed = options.allow ?? options.deny ?? [];

  const missing = listed.filter((name) => !live.includes(name));
  const added = recorded ? live.filter((name) => !recorded.includes(name)) : [];
  const removed = recorded ? recorded.filter((name) => !live.includes(name)) : [];

  if (missing.length === 0 && added.length === 0 && removed.length === 0) {
    const against = recorded ? `as recorded in ${schemaPathFor(path)}` : `every name in ${path} found`;
    process.stdout.write(`${live.length} tools, ${against}\n`);
    return 0;
  }
  const lines = [`${path} does not match the server:`, ''];
  for (const name of missing) {
    lines.push(
      `  ? ${name}`,
      `      in "${options.allow ? 'allow' : 'deny'}", but the server has no such tool`,
    );
  }
  for (const name of added) {
    lines.push(
      `  + ${name}`,
      `      new since last saved; ${options.allow ? 'hidden, since it is not in "allow"' : 'shown'}`,
    );
  }
  for (const name of removed) lines.push(`  - ${name}`, '      recorded, but the server no longer offers it');
  lines.push(
    '',
    missing.length > 0
      ? `Fix or remove the "?" names in ${path}, then run tools --config ${path} --refresh to record the rest.`
      : `Run tools --config ${path} --refresh to record the change. Your choices are kept; new tools stay off.`,
    '',
  );
  process.stdout.write(lines.join('\n'));
  return 1;
}

function runWrap(
  upstream: readonly string[],
  { allow, deny, config }: { allow?: string; deny?: string; config?: string },
): number | Promise<number> {
  const refuse = (message: string) => (process.stderr.write(`${message}\n`), 1);
  if (allow !== undefined && deny !== undefined) return refuse('wrap takes --allow or --deny, not both.');
  if (config !== undefined) {
    if (upstream.length > 0) return refuse('wrap takes --config or a command after --, not both.');
    if (allow !== undefined || deny !== undefined) {
      return refuse('wrap takes --config or --allow/--deny, not both: the list lives in the file.');
    }
  }
  const names = (list?: string) =>
    list
      ?.split(',')
      .map((name) => name.trim())
      .filter(Boolean);
  const [command, ...args] = upstream;
  if (config === undefined && !command) {
    return refuse('wrap needs the server command after --, e.g. wrap --deny x -- npx -y some-mcp');
  }
  // Reading the file can throw, with a message that names it and the field.
  const options = config
    ? readWrapConfig(config)
    : { command: command!, args, allow: names(allow), deny: names(deny) };
  // When the client stops this process, wrap stops the server with it.
  const stopped = new AbortController();
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) process.once(signal, () => stopped.abort());
  return wrap(options, {
    input: process.stdin,
    output: process.stdout,
    log: (line) => process.stderr.write(`${line}\n`),
    signal: stopped.signal,
  }).then((code) => {
    // The client can still hold stdin open after the server exits. Releasing it
    // lets this process exit, which tells the client the server has stopped.
    process.stdin.destroy();
    return code;
  });
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
 * `mcp-authz/testing` is imported lazily, so the other commands do not load an
 * MCP client to read a JSON file.
 */
type RecordSource = { module: string } | { upstream: string; token?: string };

async function record(
  source: RecordSource,
  out: string | undefined,
  against: string | undefined,
): Promise<number> {
  const toolkit = await import('./testing');

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
