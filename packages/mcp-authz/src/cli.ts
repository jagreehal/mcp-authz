#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { definePolicy, reconcile, type Identity, type MatchedRule, type PolicySpec } from './policy';
import {
  changedFields,
  INSTRUCTIONS,
  missingDefinitions,
  reveal,
  suspicious,
  type Definition,
} from './definitions';
import { formatTokens, wrap } from './wrap';
import {
  clientEntry,
  discover as discoverTools,
  writeClientConfig,
  parseJsonc,
  readWrapConfig,
  recordedToolsIfAny,
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
  mcp-authz tools --check <name.jsonc>
  mcp-authz tools --refresh <name.jsonc>
  mcp-authz wrap <name.jsonc>
  mcp-authz wrap [--allow <a,b> | --deny <a,b>] -- <command> [args...]

Files
  <policy.json>     the object you would hand definePolicy
  --capabilities    a .json map, or a .ts/.js module exporting PERMISSIONS,
                    which is what record writes
  --identity        an Identity, or a decoded token payload (iss, sub, email,
                    email_verified, hd). Use - to read it from stdin.

wrap
  Runs a stdio MCP server and hides tools from whoever connects. Put it in
  front of the server in your client's MCP config. With neither flag every
  tool passes through; names are exact and comma-separated. For a remote
  server, wrap the bridge: -- npx -y mcp-remote <url>

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
      refresh: { type: 'string' },
      'client-out': { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
  });

  const [command, policyPath] = positionals;
  // For `tools` and `wrap`, everything after `--` is the server to run, flags
  // included. Other commands keep the usual meaning: a path that starts with -.
  const dashes = argv.indexOf('--');
  const upstream = dashes === -1 ? [] : argv.slice(dashes + 1);
  // parseArgs counts those as positionals too; `wrap <file>` wants only its own.
  const [, ownPath] = positionals.slice(0, positionals.length - upstream.length);
  if (values.help || !command) {
    process.stdout.write(USAGE);
    return values.help ? 0 : 1;
  }
  if (command === 'tools') {
    if (values.check) return checkWrapConfig(values.check, upstream);
    return listTools(upstream, values);
  }
  if (command === 'wrap') return runWrap(upstream, { ...values, config: ownPath });
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
 * and with --out or --refresh save them as a config `wrap <file>` runs.
 */
function listTools(
  upstream: readonly string[],
  flags: { out?: string; refresh?: string; 'client-out'?: string },
): number | Promise<number> {
  const refuse = (message: string) => (process.stderr.write(`${message}\n`), 1);
  if (flags.refresh && upstream.length > 0) {
    return refuse('tools --refresh reruns the server its config names, so it takes no command after --.');
  }
  if (flags.refresh && flags.out) return refuse('tools takes --out or --refresh, not both.');
  // A saved config already holds the command, arguments and directory, so a
  // refresh reruns exactly what was saved rather than asking for it again.
  // Without its record: a refresh is how a missing or damaged one is replaced.
  const saved = flags.refresh ? readWrapConfig(flags.refresh, { record: false }) : undefined;
  const [command, ...args] = saved ? [saved.command, ...saved.args] : upstream;
  const cwd = saved?.cwd ?? process.cwd();
  if (saved) announce(saved, flags.refresh!);
  if (!command) {
    return refuse('tools needs the server command after --, e.g. tools -- npx -y some-mcp');
  }
  const target = flags.refresh ?? flags.out;
  return discover(command, args, cwd).then((discovered) => {
    if (discovered === undefined) return 1;
    const { tools, instructions } = discovered;
    const width = Math.max(...tools.map((tool) => tool.name.length));
    const cost = tools.map((tool) => `${formatTokens(tool.tokens)} tokens`);
    const costWidth = Math.max(...cost.map((text) => text.length));
    tools.forEach((tool, i) => {
      process.stdout.write(
        `${tool.name.padEnd(width)}  ${tool.hint.padEnd(11)}  ${cost[i]!.padStart(costWidth)}  ${tool.description}`.trimEnd() +
          '\n',
      );
    });
    // On stderr, so a script reading the list gets only the list.
    for (const tool of tools.filter((t) => t.warnings.length > 0)) {
      process.stderr.write(
        `⚠ ${tool.name} ${tool.warnings.join(' and ')}: read its definition before you allow it.\n`,
      );
    }
    if (instructions !== undefined) {
      process.stderr.write(
        `\nThe server's instructions to the model, which wrap holds to this record:\n  ${reveal(instructions)}\n`,
      );
      for (const warning of suspicious({ instructions })) {
        process.stderr.write(`⚠ the instructions ${warning}: read them before you use this server.\n`);
      }
    }
    if (!target) {
      process.stderr.write('\nSave these as a config wrap can run: tools --out <name>.jsonc -- ...\n');
      return 0;
    }
    const recorded = existsSync(target) ? recordedToolsIfAny(target) : undefined;
    // Saving is approving, and instructions have no line to leave commented
    // out, so a change to them is shown here, word for word, before it is kept.
    const approved = recorded?.get(INSTRUCTIONS) ?? {};
    const live = instructions === undefined ? {} : { instructions };
    if (recorded && changedFields(approved, live).length > 0) {
      process.stderr.write(
        [
          '',
          ...describeChange('server instructions', approved, live, 'recorded by this refresh').map((line) =>
            line.replace('until you approve it', 'and approved by saving: read it'),
          ),
          '',
        ].join('\n'),
      );
    }
    const previous = existsSync(target)
      ? { options: readWrapConfig(target, { record: false }), ...(recorded ? { recorded } : {}) }
      : undefined;
    const { allowed, commented, added, changed, tokens } = writeWrapConfig(
      target,
      { command, args, cwd },
      discovered,
      previous,
    );
    const summary = !previous
      ? `${allowed} read-only allowed, ${commented} commented out for you to choose`
      : recorded
        ? `${allowed} allowed, ${commented} commented out, ${added} new and ${changed} changed since last saved, left commented out`
        : `no record to compare against, so all ${commented} commented out for you to approve again`;
    const lines = [
      '',
      `Saved ${target} (${summary}) and ${schemaPathFor(target)}.`,
      `The model sees ${formatTokens(tokens.allowed)} of ${formatTokens(tokens.total)} tokens of tool definitions.`,
    ];
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
  const found = await discover(options.command, options.args, options.cwd);
  if (found === undefined) return 1;
  const discovered = found.tools;
  const live = discovered.map((tool) => tool.name);
  // readWrapConfig has already refused a config without a record.
  const recorded = options.pinned!;
  const recordedNames = [...recorded.keys()].filter((name) => name !== INSTRUCTIONS);
  const listed = options.allow ?? options.deny ?? [];

  const missing = listed.filter((name) => !live.includes(name));
  const added = live.filter((name) => !recorded.has(name));
  const removed = recordedNames.filter((name) => !live.includes(name));
  const changed = discovered.flatMap((tool) => {
    const approved = recorded.get(tool.name);
    const fields = approved ? changedFields(approved, tool.pin) : [];
    return fields.length > 0 ? [{ name: tool.name, approved: approved!, live: tool.pin, fields }] : [];
  });
  const approvedInstructions = recorded.get(INSTRUCTIONS) ?? {};
  const liveInstructions = found.instructions === undefined ? {} : { instructions: found.instructions };
  const instructionsChanged = changedFields(approvedInstructions, liveInstructions).length > 0;

  if (
    missing.length === 0 &&
    added.length === 0 &&
    removed.length === 0 &&
    changed.length === 0 &&
    !instructionsChanged
  ) {
    process.stdout.write(`${live.length} tools, as recorded in ${schemaPathFor(path)}\n`);
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
  for (const tool of changed) {
    const state = options.allow?.includes(tool.name) ? 'hidden by wrap' : 'not in use';
    lines.push(...describeChange(tool.name, tool.approved, tool.live, state));
  }
  if (instructionsChanged) {
    lines.push(
      ...describeChange('server instructions', approvedInstructions, liveInstructions, 'removed by wrap'),
    );
  }
  lines.push(
    '',
    missing.length > 0
      ? `Fix or remove the "?" names in ${path}, then run tools --refresh ${path} to record the rest.`
      : `Run tools --refresh ${path} to record the change. Your choices are kept; new and changed tools stay off until you switch them on.`,
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
    if (upstream.length > 0) return refuse('wrap takes a config or a command after --, not both.');
    if (allow !== undefined || deny !== undefined) {
      return refuse('wrap takes a config or --allow/--deny, not both: the list lives in the file.');
    }
  }
  const names = (list?: string) =>
    list
      ?.split(',')
      .map((name) => name.trim())
      .filter(Boolean);
  const [command, ...args] = upstream;
  if (config === undefined && !command) {
    return refuse(
      'wrap needs a config, e.g. wrap cases.jsonc, or the server command after --, e.g. wrap --deny x -- npx -y some-mcp',
    );
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
  live: { names: string[]; definitions: Record<string, Definition> },
  path: string,
): Promise<number> {
  const loaded = (await import(pathToFileURL(resolve(path)).href)) as {
    PERMISSIONS?: Record<string, string>;
    DEFINITIONS?: Record<string, Definition>;
  };
  const priced = Object.keys(loaded.PERMISSIONS ?? {});
  const recorded = new Map(Object.entries(loaded.DEFINITIONS ?? {}));

  const added = live.names.filter((name) => !priced.includes(name));
  const removed = priced.filter((name) => !live.names.includes(name));
  // The proxy refuses to boot without a definition for every priced
  // capability, so a record with a gap is a failure here too, not a pass that
  // checked less than it says.
  const unrecorded = missingDefinitions(
    priced.filter((name) => live.names.includes(name)),
    recorded,
  );
  const changed = live.names.filter(
    (name) =>
      priced.includes(name) &&
      recorded.has(name) &&
      changedFields(recorded.get(name)!, live.definitions[name]!).length > 0,
  );
  const approvedInstructions = recorded.get(INSTRUCTIONS) ?? {};
  const liveInstructions = live.definitions[INSTRUCTIONS] ?? {};
  const instructionsChanged = changedFields(approvedInstructions, liveInstructions).length > 0;

  if (
    added.length === 0 &&
    removed.length === 0 &&
    changed.length === 0 &&
    unrecorded.length === 0 &&
    !instructionsChanged
  ) {
    process.stdout.write(`${live.names.length} capabilities, unchanged since ${path}\n`);
    return 0;
  }

  const lines = ['The server no longer matches the recorded capabilities:', ''];
  for (const name of added)
    lines.push(`  + ${name}`, '      never priced, so nobody decided who may reach it');
  for (const name of removed)
    lines.push(`  - ${name}`, '      priced here, but the server no longer offers it');
  for (const name of unrecorded) {
    lines.push(
      `  ? ${name}`,
      '      priced, but DEFINITIONS has no record of it, so a change would go unseen',
    );
  }
  for (const name of changed) {
    lines.push(
      ...describeChange(name, recorded.get(name)!, live.definitions[name]!, 'hidden by createMcpProxy'),
    );
  }
  if (instructionsChanged) {
    lines.push(
      ...describeChange(
        'server instructions',
        approvedInstructions,
        liveInstructions,
        'removed by createMcpProxy',
      ),
    );
  }
  lines.push('', 'Re-record when the change is expected, and review the diff.', '');
  process.stdout.write(lines.join('\n'));
  return 1;
}

/**
 * A changed definition, with the words themselves: a changed description is
 * how a server steers the model, and "definition changed" alone gives you
 * nothing to judge.
 */
function describeChange(name: string, recorded: Definition, live: Definition, state: string): string[] {
  const fields = changedFields(recorded, live);
  return [
    `  ~ ${name}`,
    `      ${fields.join(', ')} changed since recorded; ${state} until you approve it`,
    ...fields.flatMap((field) => [
      `      ${field} was: ${reveal(JSON.stringify(recorded[field]) ?? '(absent)')}`,
      `      ${field} now: ${reveal(JSON.stringify(live[field]) ?? '(absent)')}`,
    ]),
    ...suspicious(live).map((warning) => `      ⚠ now ${warning}`),
  ];
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
