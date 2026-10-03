import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, extname, join, relative, resolve } from 'node:path';
import type { WrapOptions } from './wrap';

/**
 * The file `mcp-authz tools --out` writes and `mcp-authz wrap --config` runs.
 *
 * JSONC, so each tool can carry its description and hint as a comment, and a
 * tool can be switched off by commenting it out rather than by deleting the
 * record that it exists. Next to it sits a JSON Schema listing every tool the
 * server offered, which is what gives an editor completion and typo squiggles,
 * and what `check` compares the live server against.
 */

export type Hint = 'read-only' | 'destructive' | 'unknown';
export type DiscoveredTool = {
  name: string;
  hint: Hint;
  description: string;
  /** Argument names, required ones marked: `id (required)`. */
  params: string[];
};

/** Ask a stdio server for its tools, the way a client would. */
export async function discover(
  command: string,
  args: readonly string[],
  cwd?: string,
): Promise<DiscoveredTool[]> {
  // Imported here so check and explain do not load an MCP client to read JSON.
  const { Client } = await import('@modelcontextprotocol/client');
  const { StdioClientTransport } = await import('@modelcontextprotocol/client/stdio');
  const client = new Client({ name: 'mcp-authz-tools', version: '1.0.0' });
  // The SDK passes a child only PATH, HOME and a few others unless told
  // otherwise, and a server that reads its API key from the shell would then
  // start without one. `wrap` inherits everything; discovery has to match it.
  const env = Object.fromEntries(
    Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] !== undefined),
  );
  await client.connect(new StdioClientTransport({ command, args: [...args], env, ...(cwd ? { cwd } : {}) }));
  try {
    const tools: DiscoveredTool[] = [];
    let cursor: string | undefined;
    do {
      const page = await client.listTools(cursor ? { cursor } : undefined);
      for (const tool of page.tools) {
        tools.push({
          name: tool.name,
          // What the server claims, shown to help you choose. `wrap` filters by
          // name alone, and a tool that declares nothing is labelled unknown.
          hint: tool.annotations?.readOnlyHint
            ? 'read-only'
            : tool.annotations?.destructiveHint
              ? 'destructive'
              : 'unknown',
          description: tool.description?.split('\n')[0]?.trim() ?? '',
          params: Object.keys(tool.inputSchema.properties ?? {}).map((param) =>
            tool.inputSchema.required?.includes(param) ? `${param} (required)` : param,
          ),
        });
      }
      cursor = page.nextCursor;
    } while (cursor);
    return tools.sort((a, b) => a.name.localeCompare(b.name));
  } finally {
    await client.close();
  }
}

/** Where the schema for a config lives: beside it, named after it. */
export function schemaPathFor(configPath: string): string {
  return join(dirname(configPath), `${basename(configPath, extname(configPath))}.schema.json`);
}

/**
 * Write the config and its schema.
 *
 * In a fresh config, destructive tools start commented out. Over an existing
 * config, the choices in it are kept and a tool the server added since starts
 * commented out, so a refresh keeps your edits and waits for you to switch new
 * tools on.
 */
export function writeWrapConfig(
  configPath: string,
  server: { command: string; args: readonly string[]; cwd: string },
  tools: readonly DiscoveredTool[],
  previous?: { options: WrapOptions; recorded?: readonly string[] },
): { allowed: number; commented: number; added: number } {
  const schemaPath = schemaPathFor(configPath);
  const isNew = (name: string) => previous?.recorded !== undefined && !previous.recorded.includes(name);
  const chosen = (tool: DiscoveredTool) => {
    if (!previous) return tool.hint !== 'destructive';
    if (isNew(tool.name)) return false;
    const { allow, deny } = previous.options;
    return allow ? allow.includes(tool.name) : !deny?.includes(tool.name);
  };
  const on = tools.filter(chosen);
  const off = tools.filter((tool) => !chosen(tool));
  const note = (tool: DiscoveredTool) =>
    ` // ${tool.hint}${tool.description ? ` · ${clip(tool.description)}` : ''}`;

  const entries = [
    // A comma after every entry, switched on or not, so uncommenting any line
    // leaves the file parseable. parseJsonc accepts the trailing one.
    ...on.map((tool) => `    ${JSON.stringify(tool.name)},${note(tool)}`),
    ...off.map((tool) => `    // ${JSON.stringify(tool.name)},${note(tool)}`),
  ];
  const text = [
    '{',
    `  "$schema": ${JSON.stringify(`./${basename(schemaPath)}`)},`,
    '  // The server `mcp-authz wrap` runs. Its env comes from your client config.',
    `  "server": {`,
    `    "command": ${JSON.stringify(server.command)},`,
    `    "args": [${server.args.map((arg) => JSON.stringify(arg)).join(', ')}],`,
    '    // Where the server runs, relative to this file, so relative paths in',
    '    // "args" mean the same wherever the client starts it.',
    `    "cwd": ${JSON.stringify(storedCwd(configPath, server.cwd))}`,
    '  },',
    '  // The tools this session may see. Anything not listed is hidden, including',
    '  // tools the server adds later. Uncomment a line to switch a tool on.',
    '  "allow": [',
    ...entries,
    '  ]',
    '}',
    '',
  ].join('\n');
  writeFileSync(configPath, text);
  writeFileSync(schemaPath, `${JSON.stringify(schemaFor(tools), null, 2)}\n`);
  return {
    allowed: on.length,
    commented: off.length,
    added: tools.filter((tool) => isNew(tool.name)).length,
  };
}

function schemaFor(tools: readonly DiscoveredTool[]) {
  const names = { type: 'array', items: { $ref: '#/definitions/tool' }, uniqueItems: true };
  return {
    $schema: 'http://json-schema.org/draft-07/schema#',
    title: 'mcp-authz wrap config',
    type: 'object',
    required: ['server'],
    additionalProperties: false,
    not: { required: ['allow', 'deny'] },
    properties: {
      $schema: { type: 'string' },
      server: {
        type: 'object',
        required: ['command'],
        additionalProperties: false,
        properties: {
          command: { type: 'string' },
          args: { type: 'array', items: { type: 'string' } },
          cwd: { type: 'string', description: 'Where the server runs, relative to this file or absolute.' },
        },
      },
      allow: { ...names, description: 'Only these tools are shown.' },
      deny: { ...names, description: 'Every tool but these is shown.' },
    },
    definitions: {
      // `const` with a description, rather than a bare enum, so an editor shows
      // what each tool does while you pick it.
      // A server with no tools still gets a valid schema: `anyOf` may not be
      // empty, and `not: {}` is the schema that accepts nothing.
      tool:
        tools.length > 0
          ? { anyOf: tools.map((tool) => ({ const: tool.name, description: note(tool) })) }
          : { not: {} },
    },
  };
  // Only the editor shows this, so it can carry what the file has no room for:
  // the arguments, which say more about what a tool can do than its name.
  function note(tool: DiscoveredTool) {
    const said = tool.description ? `${tool.hint} · ${tool.description}` : tool.hint;
    return tool.params.length > 0 ? `${said}\n\nTakes: ${tool.params.join(', ')}` : said;
  }
}

/** Every tool name the schema beside a config recorded, if it is there. */
export function recordedTools(configPath: string): string[] | undefined {
  try {
    const schema = JSON.parse(readFileSync(schemaPathFor(configPath), 'utf8')) as {
      definitions?: { tool?: { anyOf?: { const: string }[] } };
    };
    const tool = schema.definitions?.tool;
    // A recorded catalogue of no tools is still a record, not a missing one.
    return tool ? (tool.anyOf ?? []).map((entry) => entry.const) : undefined;
  } catch {
    return undefined;
  }
}

/** Read a config into what `wrap` takes, saying which file is wrong and how. */
export function readWrapConfig(configPath: string): WrapOptions {
  const fail = (problem: string): never => {
    throw new Error(`${configPath}: ${problem}`);
  };
  let text: string;
  try {
    text = readFileSync(configPath, 'utf8');
  } catch {
    return fail(`cannot read it. Create it with: mcp-authz tools --out ${configPath} -- <server command>`);
  }
  let value: unknown;
  try {
    value = parseJsonc(text);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return fail(
      `not valid JSONC (${reason}). Look for a missing comma or quote, or start again: ` +
        `move it aside (mv ${configPath} ${configPath}.bak), then run ` +
        `mcp-authz tools --out ${configPath} -- <server command>`,
    );
  }
  const config = value as {
    server?: { command?: unknown; args?: unknown; cwd?: unknown };
    allow?: unknown;
    deny?: unknown;
  };
  // Unknown keys are refused, matching the schema, so a misspelled "allow"
  // stops wrap with a message instead of running with no list.
  const unknown = (object: unknown, known: readonly string[], prefix = '') => {
    if (typeof object !== 'object' || object === null) return;
    for (const key of Object.keys(object)) {
      if (!known.includes(key)) {
        fail(`unknown key "${prefix}${key}"; expected one of: ${known.join(', ')}.`);
      }
    }
  };
  unknown(config, ['$schema', 'server', 'allow', 'deny']);
  unknown(config?.server, ['command', 'args', 'cwd'], 'server.');
  const strings = (list: unknown): list is string[] =>
    Array.isArray(list) && list.every((item) => typeof item === 'string');

  if (typeof config?.server?.command !== 'string') fail('"server.command" must be a string.');
  const cwd = config.server!.cwd ?? '.';
  if (typeof cwd !== 'string') fail('"server.cwd" must be a path.');
  const args = config.server!.args ?? [];
  if (!strings(args)) fail('"server.args" must be a list of strings.');
  if (config.allow !== undefined && config.deny !== undefined) fail('use "allow" or "deny", not both.');
  for (const key of ['allow', 'deny'] as const) {
    if (config[key] !== undefined && !strings(config[key])) fail(`"${key}" must be a list of tool names.`);
  }
  return {
    command: config.server!.command as string,
    args: args as string[],
    cwd: resolve(dirname(resolve(configPath)), cwd as string),
    ...(config.allow ? { allow: config.allow as string[] } : {}),
    ...(config.deny ? { deny: config.deny as string[] } : {}),
  };
}

function entryFor(configPath: string) {
  return {
    name: basename(configPath, extname(configPath)),
    entry: { command: 'npx', args: ['-y', 'mcp-authz', 'wrap', '--config', resolve(configPath)] },
  };
}

/**
 * Add the entry to a client's MCP config file, creating it if need be. Only how
 * the server starts changes. Other servers, and every other setting on this one
 * (`env`, `disabled`, `timeout`, whatever the client supports), stay as they
 * were, so a rerun keeps your API key and your on/off choice.
 */
export function writeClientConfig(clientPath: string, configPath: string): void {
  const { name, entry } = entryFor(configPath);
  let existing: { mcpServers?: Record<string, Record<string, unknown>> } = {};
  if (existsSync(clientPath)) {
    try {
      existing = parseJsonc(readFileSync(clientPath, 'utf8')) as typeof existing;
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      throw new Error(`${clientPath}: not valid JSON (${reason}). Fix it, or pass --client-out a new file.`, {
        cause: error,
      });
    }
  }
  // A remote entry's `url`, and a `type` other than stdio, describe a different
  // transport from the command written here, so those two are dropped.
  const kept = { ...existing.mcpServers?.[name] };
  delete kept.url;
  if (kept.type !== undefined && kept.type !== 'stdio') delete kept.type;
  const merged = {
    ...existing,
    mcpServers: { ...existing.mcpServers, [name]: { ...kept, ...entry } },
  };
  writeFileSync(clientPath, `${JSON.stringify(merged, null, 2)}\n`);
}

/** The `mcpServers` entry that runs a config, ready to paste. */
export function clientEntry(configPath: string): string {
  const { name, entry } = entryFor(configPath);
  const args = entry.args.map((arg) => JSON.stringify(arg));
  return [`${JSON.stringify(name)}: {`, '  "command": "npx",', `  "args": [${args.join(', ')}]`, '}'].join(
    '\n',
  );
}

/**
 * JSON with comments and trailing commas, which is what a person editing the
 * file will produce. Strings are copied whole, so `//` inside one is safe.
 */
export function parseJsonc(text: string): unknown {
  let out = '';
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (char === '"') {
      let end = i + 1;
      while (end < text.length && text[end] !== '"') end += text[end] === '\\' ? 2 : 1;
      out += text.slice(i, end + 1);
      i = end;
    } else if (char === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++;
      out += '\n';
    } else if (char === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      i = end === -1 ? text.length : end + 1;
    } else {
      // Comments and strings are already out of the way, so a comma at the end
      // of `out` is a trailing comma.
      if (char === ']' || char === '}') out = out.replace(/,\s*$/, '');
      out += char;
    }
  }
  return JSON.parse(out);
}

/**
 * Relative to the config when that is the shorter way to say it, as it is for
 * a config kept beside its server in a repo; otherwise absolute, so a copied
 * file still finds the server.
 */
function storedCwd(configPath: string, cwd: string): string {
  const relativeTo = relative(dirname(resolve(configPath)), cwd) || '.';
  return relativeTo.length <= cwd.length ? relativeTo : cwd;
}

/** The first sentence, and no more than a line's worth of it. */
function clip(text: string, max = 80): string {
  const sentence = /^.*?[.!?](?=\s|$)/.exec(text)?.[0] ?? text;
  return sentence.length > max ? `${sentence.slice(0, max - 1)}…` : sentence;
}
