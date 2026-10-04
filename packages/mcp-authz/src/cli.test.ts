import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { z } from 'zod';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { main } from './cli';
import { Ajv } from 'ajv';
import { parseJsonc, readWrapConfig, writeWrapConfig } from './wrap-config';

const dir = mkdtempSync(join(tmpdir(), 'mcp-authz-cli-'));

function file(name: string, value: unknown): string {
  const path = join(dir, name);
  writeFileSync(path, JSON.stringify(value));
  return path;
}

const POLICY = file('policy.json', {
  roles: { reader: ['cases:read'], editor: ['cases:read', 'cases:write'] },
  rules: [
    { match: { domain: 'acme.com' }, role: 'reader' },
    { match: { email: 'alice@acme.com' }, role: 'editor' },
    { match: { sub: 'auth0|gone' }, deny: true },
  ],
});

const CAPABILITIES = file('caps.json', {
  get_case: 'cases:read',
  update_case: 'cases:write',
});

const ALICE = file('alice.json', {
  iss: 'https://auth.acme.com',
  sub: 'auth0|alice',
  email: 'alice@acme.com',
  email_verified: true,
  hd: 'acme.com',
});

let out: string;
let err: string;

beforeEach(() => {
  out = '';
  err = '';
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => ((out += chunk), true));
  vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => ((err += chunk), true));
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

it('prints usage for --help', () => {
  expect(main(['--help'])).toBe(0);
  expect(out).toContain('mcp-authz check');
  expect(err).toBe('');
});

describe('check', () => {
  it('reconciles the policy against the capabilities that use it', () => {
    expect(main(['check', POLICY, '--capabilities', CAPABILITIES])).toBe(0);
    expect(out).toContain('2 roles');
    expect(out).toContain('2 permissions');
  });

  it('fails on a capability no role can reach, naming it', () => {
    const orphan = file('orphan.json', { get_case: 'cases:read', wipe: 'cases:delete' });

    expect(main(['check', POLICY, '--capabilities', orphan])).toBe(1);
    expect(err).toContain('wipe');
    expect(err).toContain('cases:delete');
  });

  it('warns about a permission no capability requires, without failing', () => {
    const partial = file('partial.json', { get_case: 'cases:read' });

    expect(main(['check', POLICY, '--capabilities', partial])).toBe(0);
    expect(out).toContain('cases:write');
    expect(out).toContain('no registered capability');
  });
});

describe('explain', () => {
  it('names every rule that matched, not just the outcome', () => {
    expect(main(['explain', POLICY, '--identity', ALICE, '--capabilities', CAPABILITIES])).toBe(0);

    expect(out).toContain('rule 0');
    expect(out).toContain('domain=acme.com');
    expect(out).toContain('rule 1');
    expect(out).toContain('email=alice@acme.com');
    expect(out).toContain('cases:write');
    expect(out).toContain('update_case');
  });

  it('shows a caller who matched nothing holding nothing', () => {
    const outsider = file('sam.json', {
      iss: 'https://auth.acme.com',
      sub: 'auth0|sam',
      email: 'sam@other.com',
      email_verified: true,
    });

    expect(main(['explain', POLICY, '--identity', outsider])).toBe(0);
    expect(out).toContain('none, so this caller holds nothing');
  });

  it('points at the deny rule when one empties the grant', () => {
    const departed = file('gone.json', {
      iss: 'https://auth.acme.com',
      sub: 'auth0|gone',
      email: 'gone@acme.com',
      email_verified: true,
      hd: 'acme.com',
    });

    expect(main(['explain', POLICY, '--identity', departed])).toBe(0);
    expect(out).toContain('Rule 2 denies');
    expect(out).toMatch(/Permissions\n {2}none/);
  });
});

describe('record', () => {
  it('writes a permission map naming what the connector registers', async () => {
    const out = join(dir, 'permissions.ts');

    const code = await main(['record', 'src/__fixtures__/connector.ts', '--out', out]);

    expect(code).toBe(0);
    const generated = (await import(pathToFileURL(out).href)) as { PERMISSIONS: Record<string, string> };
    expect(generated.PERMISSIONS).toEqual({
      get_case: 'TODO:unassigned',
      'prompt:triage': 'TODO:unassigned',
      update_case: 'TODO:unassigned',
    });
  });

  it('prints only the module, so `record > permissions.ts` is a valid file', async () => {
    expect(await main(['record', 'src/__fixtures__/connector.ts'])).toBe(0);

    // The fixture advertises no resources. Anything the SDK says about that lands
    // in the redirected file and makes it fail to parse.
    expect(out).not.toContain('does not advertise');
    expect(out.trimStart().startsWith('//')).toBe(true);
  });

  it('records an upstream nobody can wrap, given only its URL', async () => {
    const upstream = createMcpHandler(() => {
      const server = new McpServer({ name: 'vendor', version: '9.9.9' }, { capabilities: { tools: {} } });
      server.registerTool(
        'get_case',
        { description: 'Read one case', inputSchema: { id: z.string() } },
        async () => ({ content: [] }),
      );
      return server;
    });
    const http = createServer(toNodeHandler(upstream));
    await new Promise<void>((ready) => http.listen(0, '127.0.0.1', ready));
    const { port } = http.address() as AddressInfo;
    const out = join(dir, 'upstream-permissions.ts');

    try {
      const code = await main([
        'record',
        '--upstream',
        `http://127.0.0.1:${port}/mcp`,
        '--token',
        'service-token',
        '--out',
        out,
      ]);

      expect(code).toBe(0);
      const generated = (await import(pathToFileURL(out).href)) as { PERMISSIONS: Record<string, string> };
      expect(generated.PERMISSIONS).toEqual({ get_case: 'TODO:unassigned' });
    } finally {
      await new Promise<void>((closed) => http.close(() => closed()));
    }
  });

  it('checks a policy against the TypeScript map that record wrote', async () => {
    // record emits a module; check took JSON only, so the documented loop —
    // record, price the TODOs, check against the policy — could not close.
    const map = join(dir, 'priced-permissions.ts');
    writeFileSync(
      map,
      "export const PERMISSIONS = { get_case: 'cases:read', update_case: 'cases:write' } as const;\n",
    );

    const code = await main(['check', POLICY, '--capabilities', map]);

    expect(code).toBe(0);
    expect(out).toContain('2 permissions');
  });

  it('fails CI when the live capabilities no longer match the committed map', async () => {
    const map = join(dir, 'stale-permissions.ts');
    writeFileSync(
      map,
      [
        "export const PERMISSIONS = { get_case: 'cases:read', 'prompt:triage': 'cases:read' } as const;",
        "export const DEFINITIONS = { get_case: { name: 'get_case', description: 'Old words' }, 'prompt:triage': {} };",
      ].join('\n'),
    );

    const code = await main(['record', 'src/__fixtures__/connector.ts', '--check', map]);

    expect(code).toBe(1);
    // update_case exists on the server and was never priced.
    expect(out).toContain('update_case');
    // get_case is priced, but is not the tool that was recorded, and the
    // output says what moved rather than only that something did.
    expect(out).toContain('~ get_case');
    expect(out).toContain('description was: "Old words"');
  });

  it('fails a map whose record misses a priced capability, whole or in part', async () => {
    // Written by hand, or with an entry lost. A check that skipped what it
    // cannot compare would read as a pass while comparing less than it says.
    const map = join(dir, 'gap.ts');
    writeFileSync(
      map,
      "export const PERMISSIONS = { get_case: 'cases:read', update_case: 'cases:write', 'prompt:triage': 'cases:read' } as const;\n",
    );

    expect(await main(['record', 'src/__fixtures__/connector.ts', '--check', map])).toBe(1);
    expect(out).toContain('? get_case');
    expect(out).toContain('priced, but DEFINITIONS has no record of it');

    out = '';
    const full = join(dir, 'full.ts');
    await main(['record', 'src/__fixtures__/connector.ts', '--out', full]);
    const { PERMISSIONS, DEFINITIONS } = (await import(pathToFileURL(full).href)) as {
      PERMISSIONS: Record<string, string>;
      DEFINITIONS: Record<string, unknown>;
    };
    const kept = { ...DEFINITIONS };
    delete kept.update_case;
    const partial = join(dir, 'partial.ts');
    writeFileSync(
      partial,
      `export const PERMISSIONS = ${JSON.stringify(PERMISSIONS)};\nexport const DEFINITIONS = ${JSON.stringify(kept)};\n`,
    );
    out = '';
    expect(await main(['record', 'src/__fixtures__/connector.ts', '--check', partial])).toBe(1);
    expect(out).toContain('? update_case');
  });
});

it('still takes a path after --, for the commands that are not wrap or tools', () => {
  expect(main(['check', '--', POLICY])).toBe(0);
  expect(out).toContain('2 roles');
});

describe('wrap', () => {
  it('is in the usage', () => {
    main(['--help']);
    expect(out).toContain('mcp-authz wrap [--allow <a,b> | --deny <a,b>] -- <command> [args...]');
  });

  it('refuses --allow and --deny together, since one has to win', () => {
    expect(main(['wrap', '--allow', 'a', '--deny', 'b', '--', 'node', 'server.js'])).toBe(1);
    expect(err).toContain('--allow or --deny, not both');
  });

  it('needs the upstream command after --', () => {
    expect(main(['wrap', '--deny', 'a'])).toBe(1);
    expect(err).toContain('wrap needs a config, e.g. wrap cases.jsonc, or the server command after --');
  });
});

describe('tools', () => {
  it('lists what a stdio server offers, with its hints, so you know what to pass wrap', async () => {
    const upstream = fileURLToPath(new URL('./__fixtures__/stdio-upstream.mjs', import.meta.url));

    expect(await main(['tools', '--', process.execPath, upstream])).toBe(0);

    expect(out.split('\n').filter(Boolean)).toEqual([
      'delete_case   destructive  ~35 tokens  Remove a case',
      'search_cases  read-only    ~34 tokens  Find cases',
      'update_case   unknown      ~65 tokens  Change a case',
    ]);
  });

  it("hands the server this shell's environment, credentials included", async () => {
    const upstream = fileURLToPath(new URL('./__fixtures__/stdio-upstream.mjs', import.meta.url));
    vi.stubEnv('CASE_TRACKER_TOKEN', 'secret');

    expect(await main(['tools', '--', process.execPath, upstream])).toBe(0);

    expect(out).toContain('export_cases');
  });

  it('needs the server command after --', () => {
    expect(main(['tools'])).toBe(1);
    expect(err).toContain('tools needs the server command after --');
  });
});

describe('a saved wrap config', () => {
  it('tools --refresh reruns the saved server, keeping choices and leaving new tools off', async () => {
    const config = join(dir, 'refresh.jsonc');
    await main(['tools', '--out', config, '--', process.execPath, upstream]);
    // The person switches update_case on and search_cases off.
    writeFileSync(
      config,
      readFileSync(config, 'utf8')
        .replace('// "update_case",', '"update_case",')
        .replace('    "search_cases",', '    // "search_cases",'),
    );
    // The server is upgraded and gains a tool.
    vi.stubEnv('CASE_TRACKER_TOKEN', 'secret');
    out = '';

    expect(await main(['tools', '--refresh', config])).toBe(0);

    expect(readWrapConfig(config).allow).toEqual(['update_case']);
    expect(readFileSync(config, 'utf8')).toContain('// "export_cases",');
    expect(out).toContain('1 new and 0 changed since last saved, left commented out');
  });

  it('--refresh takes the server from the file, so -- is not needed as well', () => {
    expect(main(['tools', '--refresh', 'x.jsonc', '--', 'npx', 'other'])).toBe(1);
    expect(err).toContain('takes no command after --');
  });

  it('--client-out writes the mcpServers file, keeping other servers and the env you added', async () => {
    const config = join(dir, 'cases.jsonc');
    const client = join(dir, 'mcp.json');
    writeFileSync(
      client,
      JSON.stringify({
        mcpServers: {
          other: { command: 'other-mcp' },
          cases: {
            command: 'old',
            args: ['old-arg'],
            env: { CASE_TRACKER_TOKEN: 'kept' },
            disabled: true,
            timeout: 60,
          },
        },
      }),
    );

    expect(
      await main(['tools', '--out', config, '--client-out', client, '--', process.execPath, upstream]),
    ).toBe(0);

    expect(JSON.parse(readFileSync(client, 'utf8'))).toEqual({
      mcpServers: {
        other: { command: 'other-mcp' },
        // Only how it starts changes; a disabled server stays disabled.
        cases: {
          command: 'npx',
          args: ['-y', 'mcp-authz', 'wrap', config],
          env: { CASE_TRACKER_TOKEN: 'kept' },
          disabled: true,
          timeout: 60,
        },
      },
    });
    // Still printed, for the clients whose config is not a file you can name.
    expect(out).toContain('"cases": {');
  });

  it('keeps the directory discovery ran in, so a relative server path still resolves', async () => {
    // The config is saved far from the server; it must still run there.
    const config = join(dir, 'relative.jsonc');

    await main(['tools', '--out', config, '--', process.execPath, 'src/__fixtures__/stdio-upstream.mjs']);

    expect(readWrapConfig(config).cwd).toBe(process.cwd());
  });

  it('check passes a config that matches the server', async () => {
    const config = join(dir, 'fresh.jsonc');
    await main(['tools', '--out', config, '--', process.execPath, upstream]);
    out = '';

    expect(await main(['tools', '--check', config])).toBe(0);
    expect(out).toContain('3 tools, as recorded in');
  });

  it('check fails on a listed name the server lacks, and on tools that came or went', async () => {
    const config = join(dir, 'drifted.jsonc');
    await main(['tools', '--out', config, '--', process.execPath, upstream]);
    // As if saved against an older server: no delete_case then, export_cases since removed.
    const schemaPath = join(dir, 'drifted.schema.json');
    const schema = JSON.parse(readFileSync(schemaPath, 'utf8'));
    const pins = schema['x-mcp-authz-tools'];
    schema['x-mcp-authz-tools'] = {
      export_cases: { description: 'Export every case' },
      search_cases: pins.search_cases,
      update_case: pins.update_case,
    };
    writeFileSync(schemaPath, JSON.stringify(schema));
    // export_cases was approved then, and is still allowed.
    writeFileSync(
      config,
      readFileSync(config, 'utf8').replace('"search_cases",', '"search_cases", "export_cases",'),
    );
    out = '';

    expect(await main(['tools', '--check', config])).toBe(1);
    expect(out).toContain('? export_cases');
    expect(out).toContain('+ delete_case');
    expect(out).toContain('- export_cases');
  });

  it('tools --out on an existing config keeps your choices and adds new tools switched off', async () => {
    const config = join(dir, 'kept.jsonc');
    writeFileSync(
      config,
      `{ "server": { "command": ${JSON.stringify(process.execPath)} }, "allow": ["search_cases", "delete_case"] }`,
    );
    // Recorded as the server served them then, before update_case existed.
    await main(['tools', '--out', join(dir, 'then.jsonc'), '--', process.execPath, upstream]);
    const { search_cases, delete_case } = JSON.parse(readFileSync(join(dir, 'then.schema.json'), 'utf8'))[
      'x-mcp-authz-tools'
    ];
    writeFileSync(
      join(dir, 'kept.schema.json'),
      JSON.stringify({ 'x-mcp-authz-tools': { search_cases, delete_case } }),
    );

    expect(await main(['tools', '--out', config, '--', process.execPath, upstream])).toBe(0);

    // delete_case stays on because you turned it on; update_case is new, so off.
    expect(readWrapConfig(config).allow).toEqual(['delete_case', 'search_cases']);
    expect(readFileSync(config, 'utf8')).toContain('// "update_case",');
    expect(out).toContain('1 new and 0 changed since last saved, left commented out');
  });

  it('reads the file as a person leaves it: comments, // in strings, a trailing comma', () => {
    const config = join(dir, 'edited.jsonc');
    writeFileSync(
      config,
      [
        '{',
        '  /* the server */ "server": { "command": "npx", "args": ["-y", "https://x.dev//mcp"] },',
        '  "allow": [',
        '    "search_cases", // read-only',
        '    "delete_case", // uncommented, and the comma left behind',
        '  ],',
        '}',
      ].join('\n'),
    );

    expect(readWrapConfig(config, { record: false })).toEqual({
      command: 'npx',
      args: ['-y', 'https://x.dev//mcp'],
      // No cwd given: the config's own directory, never the client's.
      cwd: dir,
      allow: ['search_cases', 'delete_case'],
    });
  });

  it('refuses a name the record lacks, rather than hiding a typo at runtime', async () => {
    const config = join(dir, 'typo-name.jsonc');
    await main(['tools', '--out', config, '--', process.execPath, upstream]);
    writeFileSync(config, readFileSync(config, 'utf8').replace('"search_cases",', '"serch_cases",'));

    expect(() => readWrapConfig(config)).toThrow('"serch_cases" not in the record beside it');
  });

  it('refuses to run without its record, rather than filtering by name alone', async () => {
    const config = join(dir, 'lost-record.jsonc');
    await main(['tools', '--out', config, '--', process.execPath, upstream]);
    rmSync(join(dir, 'lost-record.schema.json'));

    expect(() => readWrapConfig(config)).toThrow('lost-record.schema.json: missing');
    writeFileSync(join(dir, 'lost-record.schema.json'), '{"x-mcp-authz-tools": {"search_cases": "x"}}');
    expect(() => readWrapConfig(config)).toThrow('the record for "search_cases" is not a definition');

    // A refresh writes a new record, and with nothing to compare against,
    // approves nothing on your behalf.
    expect(await main(['tools', '--refresh', config])).toBe(0);
    expect(readWrapConfig(config).allow).toEqual([]);
    expect(out).toContain('no record to compare against');
  });

  it('names the file and the field when the config is wrong', () => {
    const config = join(dir, 'wrong.jsonc');
    writeFileSync(config, '{ "server": { "command": "npx" }, "allow": ["a"], "deny": ["b"] }');

    expect(() => readWrapConfig(config)).toThrow(`${config}: use "allow" or "deny", not both.`);
  });

  it('writes a valid schema for a server with no tools, one that accepts no names', () => {
    const config = join(dir, 'empty.jsonc');

    writeWrapConfig(config, { command: 'npx', args: [], cwd: dir }, { tools: [] });

    const schema = JSON.parse(readFileSync(join(dir, 'empty.schema.json'), 'utf8'));
    const validate = new Ajv({ strict: false }).compile(schema);
    expect(validate(parseJsonc(readFileSync(config, 'utf8')))).toBe(true);
    expect(validate({ server: { command: 'npx' }, allow: ['anything'] })).toBe(false);
  });

  it('refuses a key it does not know, so a misspelled "allow" cannot show everything', () => {
    const config = join(dir, 'typo.jsonc');
    writeFileSync(config, '{ "server": { "command": "npx" }, "alow": ["read"] }');

    expect(() => readWrapConfig(config)).toThrow(`${config}: unknown key "alow"`);
  });

  it('wrap <file> takes the server from the file, so -- is not needed as well', () => {
    expect(main(['wrap', 'x.jsonc', '--', 'npx', 'other'])).toBe(1);
    expect(err).toContain('wrap takes a config or a command after --, not both.');
  });

  const upstream = fileURLToPath(new URL('./__fixtures__/stdio-upstream.mjs', import.meta.url));

  it('tools --out saves what it found as a config wrap can run, and says how to use it', async () => {
    const config = join(dir, 'cases.jsonc');

    expect(await main(['tools', '--out', config, '--', process.execPath, upstream])).toBe(0);

    // Destructive tools start commented out: visible, one keystroke from on.
    expect(readWrapConfig(config)).toEqual({
      command: process.execPath,
      args: [upstream],
      cwd: process.cwd(),
      // Only what the server marks read-only starts on: update_case says nothing.
      allow: ['search_cases'],
      pinned: expect.any(Map),
    });
    const text = readFileSync(config, 'utf8');
    expect(text).toContain('// "delete_case", // destructive · ~');
    expect(text).toContain('"search_cases", // read-only · ~');
    // Every entry ends in a comma, so uncommenting any line, as the file
    // invites, leaves it parseable.
    writeFileSync(config, text.replace('// "delete_case",', '"delete_case",'));
    expect(readWrapConfig(config).allow).toEqual(['search_cases', 'delete_case']);

    // The schema lists every tool, so an editor completes names and flags typos.
    const schema = JSON.parse(readFileSync(join(dir, 'cases.schema.json'), 'utf8'));
    expect(schema.definitions.tool.anyOf.map((t: { const: string }) => t.const)).toEqual([
      'delete_case',
      'search_cases',
      'update_case',
    ]);
    // What the editor will check: the file as generated passes its own schema,
    // and a misspelled tool does not.
    const validate = new Ajv({ strict: false }).compile(schema);
    const saved = parseJsonc(text) as { allow: string[] };
    expect(validate(saved)).toBe(true);
    expect(validate({ ...saved, allow: [...saved.allow, 'serch_cases'] })).toBe(false);

    // Hovering a name shows what it does and what it takes; a tool that takes
    // nothing says nothing about arguments.
    const described = Object.fromEntries(
      schema.definitions.tool.anyOf.map((t: { const: string; description: string }) => [
        t.const,
        t.description,
      ]),
    );
    expect(described.update_case).toMatch(
      /^unknown · ~\d+ tokens · Change a case\n\nTakes: id \(required\), title$/,
    );
    expect(described.search_cases).toMatch(/^read-only · ~\d+ tokens · Find cases$/);
    // What the choice costs, so the big tools are the easy ones to spot.
    expect(out).toMatch(/The model sees ~\d+ of ~\d+ tokens of tool definitions/);

    // The client entry names the config by absolute path: clients start
    // servers from a working directory nobody chose.
    expect(out).toContain('"cases": {');
    expect(out).toContain(`"args": ["-y", "mcp-authz", "wrap", ${JSON.stringify(config)}]`);
  });
});

describe('check reads files and runs nothing', () => {
  const upstream = fileURLToPath(new URL('./__fixtures__/stdio-upstream.mjs', import.meta.url));

  it('refuses a wrap config, pointing at the command that starts servers', async () => {
    const config = join(dir, 'never-run.jsonc');
    const marker = join(dir, 'ran');
    writeFileSync(
      config,
      JSON.stringify({
        server: {
          command: process.execPath,
          args: ['-e', `require('fs').writeFileSync(${JSON.stringify(marker)}, '')`],
        },
      }),
    );

    expect(await main(['check', config])).toBe(1);

    expect(err).toContain(`tools --check ${config}`);
    expect(existsSync(marker)).toBe(false);
  });

  it('tools says which command it is about to run from a file', async () => {
    const config = join(dir, 'announced.jsonc');
    await main(['tools', '--out', config, '--', process.execPath, upstream]);
    err = '';

    await main(['tools', '--check', config]);

    expect(err).toContain(`Running ${process.execPath} ${upstream} from ${config}`);
  });
});

describe('errors say what to do next', () => {
  it('a command that is not installed', async () => {
    expect(await main(['tools', '--', 'mcp-authz-no-such-server'])).toBe(1);
    expect(err).toContain('Could not start mcp-authz-no-such-server: command not found.');
    expect(err).toContain('Install it, or give its full path.');
  });

  it('a server that exits before listing, as one missing its API key does', async () => {
    expect(await main(['tools', '--', process.execPath, '-e', 'process.exit(3)'])).toBe(1);
    expect(err).toContain('The server exited before listing its tools.');
    expect(err).toContain('export them in this shell');
  });

  it('a config that is not valid JSONC', () => {
    const config = join(dir, 'malformed.jsonc');
    writeFileSync(config, '{ "server": { "command": "npx" } "allow": [] }');

    expect(() => readWrapConfig(config)).toThrow(
      /malformed\.jsonc: not valid JSONC .*Look for a missing comma or quote/,
    );
    // The suggested recovery has to work on the file as it is: tools --out reads it.
    expect(() => readWrapConfig(config)).toThrow(`move it aside (mv ${config} ${config}.bak)`);
  });

  it('a key it does not know, naming the ones it does', () => {
    const config = join(dir, 'unknown.jsonc');
    writeFileSync(config, '{ "server": { "command": "npx" }, "alow": [] }');

    expect(() => readWrapConfig(config)).toThrow('expected one of: $schema, server, allow, deny');
  });
});
