import { describe, expect, it } from 'vitest';
import { policy } from './policy';
import { buildExampleServer, tools } from './server';

describe('buildExampleServer', () => {
  it('registers only the tools the caller may use', () => {
    const reader = policy({
      issuer: 'https://auth.example.com',
      sub: 'u1',
      email: 'dana@acme.com',
      emailVerified: true,
      claims: {},
    });
    const editor = policy({
      issuer: 'https://auth.example.com',
      sub: 'u2',
      email: 'alice@acme.com',
      emailVerified: true,
      claims: {},
    });

    expect(reader.can('cases:write')).toBe(false);
    expect(editor.can('cases:write')).toBe(true);
    expect(buildExampleServer(reader)).toBeDefined();
    expect(buildExampleServer(editor)).toBeDefined();
  });

  it('declares a permission for every tool, prompt and resource', () => {
    expect(tools.map((definition) => definition.label).sort()).toEqual([
      'get_case',
      'prompt:triage_case',
      'resource:cases',
      'update_case',
      'whoami',
    ]);
    expect(buildExampleServer.permissions.get('update_case')).toBe('cases:write');
    expect(buildExampleServer.permissions.get('prompt:triage_case')).toBe('cases:write');
  });
});
