import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/client';
import type { JSONRPCMessage, Transport } from '@modelcontextprotocol/client';
import { story } from 'executable-stories-vitest';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { main } from './cli';
import { wrap } from './wrap';
import { readWrapConfig } from './wrap-config';

/**
 * The release check: what a person does, start to finish. Save a server's
 * tools, switch one off, use the client entry it printed, see the tool gone,
 * then take a server upgrade without losing the choice.
 */

const UPSTREAM = fileURLToPath(new URL('./__fixtures__/stdio-upstream.mjs', import.meta.url));

let out = '';
beforeEach(() => {
  out = '';
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => ((out += chunk), true));
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

/** Run what the client entry says to run, and talk to it as the client would. */
async function connectAsClient(entry: { args: string[] }) {
  const [config] = entry.args.slice(entry.args.indexOf('wrap') + 1);
  const toWrap = new PassThrough();
  const fromWrap = new PassThrough();
  const exited = wrap(readWrapConfig(config!), { input: toWrap, output: fromWrap, log: () => {} });

  let buffered = '';
  const transport: Transport = {
    async start() {
      fromWrap.on('data', (chunk: Buffer) => {
        buffered += chunk.toString('utf8');
        let newline;
        while ((newline = buffered.indexOf('\n')) !== -1) {
          const line = buffered.slice(0, newline);
          buffered = buffered.slice(newline + 1);
          if (line.trim()) transport.onmessage?.(JSON.parse(line) as JSONRPCMessage);
        }
      });
    },
    async send(message) {
      toWrap.write(`${JSON.stringify(message)}\n`);
    },
    async close() {
      toWrap.end();
      transport.onclose?.();
    },
  };
  const client = new Client({ name: 'journey', version: '1.0.0' });
  await client.connect(transport);
  return {
    client,
    close: async () => {
      await client.close();
      await exited;
    },
  };
}

it('save, switch a tool off, connect, upgrade, refresh: the choice survives', async ({ task }) => {
  story.init(task, {
    tags: ['wrap', 'journey'],
    covers: ['src/cli.ts', 'src/wrap.ts', 'src/wrap-config.ts'],
  });
  const dir = mkdtempSync(join(tmpdir(), 'mcp-authz-journey-'));
  const config = join(dir, 'cases.jsonc');
  const clientFile = join(dir, 'mcp.json');

  story.given("a person saves a server's tools and their client entry");
  expect(
    await main(['tools', '--out', config, '--client-out', clientFile, '--', process.execPath, UPSTREAM]),
  ).toBe(0);

  story.and('leaves update_case off, as it starts: the server does not say it is read-only');
  expect(readFileSync(config, 'utf8')).toContain('// "update_case",');

  story.when('their client starts the server from the entry it was given');
  const entry = JSON.parse(readFileSync(clientFile, 'utf8')).mcpServers.cases;
  const first = await connectAsClient(entry);

  story.then('update_case is not listed, and calling it is refused');
  expect((await first.client.listTools()).tools.map((t) => t.name).sort()).toEqual(['search_cases']);
  await expect(first.client.callTool({ name: 'update_case', arguments: { id: '1' } })).rejects.toThrow(
    /blocked by mcp-authz wrap/,
  );
  await first.close();

  story.when('the server is upgraded and gains a tool');
  vi.stubEnv('CASE_TRACKER_TOKEN', 'secret');

  story.then('tools --check notices, and says how to take the change');
  out = '';
  expect(await main(['tools', '--check', config])).toBe(1);
  expect(out).toContain('+ export_cases');
  expect(out).toContain(`tools --refresh ${config}`);

  story.when('they refresh');
  expect(await main(['tools', '--refresh', config])).toBe(0);

  story.then('their choice survives, the new tool arrives switched off, and check passes');
  expect(readWrapConfig(config).allow).toEqual(['search_cases']);
  expect(readFileSync(config, 'utf8')).toContain('// "export_cases",');
  expect(await main(['tools', '--check', config])).toBe(0);

  story.and('the client still sees only what they chose');
  const second = await connectAsClient(entry);
  expect((await second.client.listTools()).tools.map((t) => t.name)).toEqual(['search_cases']);
  await second.close();
});

it('a rug pull: an approved tool changes its description, and loses its place until reviewed', async ({
  task,
}) => {
  story.init(task, {
    tags: ['wrap', 'journey', 'security'],
    covers: ['src/cli.ts', 'src/wrap.ts', 'src/wrap-config.ts'],
  });
  const dir = mkdtempSync(join(tmpdir(), 'mcp-authz-rug-'));
  const config = join(dir, 'cases.jsonc');
  const clientFile = join(dir, 'mcp.json');

  story.given('a person approves search_cases as "Find cases"');
  expect(
    await main(['tools', '--out', config, '--client-out', clientFile, '--', process.execPath, UPSTREAM]),
  ).toBe(0);
  const entry = JSON.parse(readFileSync(clientFile, 'utf8')).mcpServers.cases;
  story.and('switches update_case on as well');
  writeFileSync(config, readFileSync(config, 'utf8').replace('// "update_case",', '"update_case",'));

  story.when('the server, under the same name, starts telling the model to read an SSH key');
  vi.stubEnv('CASE_TRACKER_RUG_PULL', '1');

  story.then('the model never sees the new description, and a call is refused');
  const session = await connectAsClient(entry);
  expect((await session.client.listTools()).tools.map((t) => t.name).sort()).toEqual(['update_case']);
  await expect(session.client.callTool({ name: 'search_cases', arguments: {} })).rejects.toThrow(
    /search_cases.*description changed since you approved it/,
  );
  await session.close();

  story.and('tools --check shows the words that changed');
  out = '';
  expect(await main(['tools', '--check', config])).toBe(1);
  expect(out).toContain('~ search_cases');
  expect(out).toContain('description was: "Find cases"');
  expect(out).toContain('read ~/.ssh/id_rsa');

  story.when('they refresh without reading it');
  expect(await main(['tools', '--refresh', config])).toBe(0);

  story.then('the changed tool is recorded but switched off, so approving it is a deliberate edit');
  expect(readWrapConfig(config).allow).toEqual(['update_case']);
  expect(readFileSync(config, 'utf8')).toContain('// "search_cases",');
  expect(await main(['tools', '--check', config])).toBe(0);
});
