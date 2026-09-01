import { mkdtempSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { z } from 'zod';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { main } from './cli';

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
afterEach(() => vi.restoreAllMocks());

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
        "export const FINGERPRINTS = { get_case: 'stale', 'prompt:triage': 'stale' } as const;",
      ].join('\n'),
    );

    const code = await main(['record', 'src/__fixtures__/connector.ts', '--check', map]);

    expect(code).toBe(1);
    // update_case exists on the server and was never priced.
    expect(out).toContain('update_case');
    // get_case is priced, but is not the tool that was recorded.
    expect(out).toContain('get_case');
  });

  it('says so when the committed map carries no baseline to compare against', async () => {
    // A map written before FINGERPRINTS existed, or by hand. Names can still be
    // compared; definitions cannot, and a silent partial check in CI is worse
    // than no check, because it reads as a pass.
    const map = join(dir, 'baseline-less.ts');
    writeFileSync(
      map,
      "export const PERMISSIONS = { get_case: 'cases:read', update_case: 'cases:write', 'prompt:triage': 'cases:read' } as const;\n",
    );

    const code = await main(['record', 'src/__fixtures__/connector.ts', '--check', map]);

    expect(code).toBe(0);
    expect(out).toContain('no FINGERPRINTS');
  });
});
