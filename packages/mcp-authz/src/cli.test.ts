import { mkdtempSync, writeFileSync } from 'node:fs';
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
