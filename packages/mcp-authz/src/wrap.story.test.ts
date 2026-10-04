import { PassThrough, Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/client';
import type { JSONRPCMessage, Transport } from '@modelcontextprotocol/client';
import { story } from 'executable-stories-vitest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { wrap, type WrapOptions } from './wrap';

/**
 * `wrap` in front of a real stdio server, driven by a real SDK client. The only
 * thing faked is the parent process: the client talks to `wrap` over streams
 * rather than over the stdin/stdout a desktop client would hand it.
 */

const UPSTREAM = fileURLToPath(new URL('./__fixtures__/stdio-upstream.mjs', import.meta.url));

/** The client end of a pair of streams, as the SDK expects a transport to be. */
function streamTransport(input: PassThrough, output: PassThrough): Transport {
  let buffered = '';
  const transport: Transport = {
    async start() {
      input.on('data', (chunk: Buffer) => {
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
      output.write(`${JSON.stringify(message)}\n`);
    },
    async close() {
      output.end();
      transport.onclose?.();
    },
  };
  return transport;
}

const running: { client: Client; exited: Promise<number> }[] = [];

afterEach(async () => {
  for (const { client, exited } of running.splice(0)) {
    await client.close();
    await exited;
  }
});

async function connect(filter: Pick<WrapOptions, 'allow' | 'deny' | 'pinned'>) {
  const toWrap = new PassThrough();
  const fromWrap = new PassThrough();
  let log = '';
  const exited = wrap(
    { command: process.execPath, args: [UPSTREAM], ...filter },
    { input: toWrap, output: fromWrap, log: (line) => (log += `${line}\n`) },
  );
  const client = new Client({ name: 'test-client', version: '1.0.0' });
  await client.connect(streamTransport(fromWrap, toWrap));
  running.push({ client, exited });
  return { client, log: () => log, exited };
}

describe('wrap', () => {
  it('hides a denied tool from the listing', async ({ task }) => {
    story.init(task, { tags: ['wrap'], covers: ['src/wrap.ts'] });

    story.given('a stdio server with three tools, wrapped with --deny delete_case');
    const { client } = await connect({ deny: ['delete_case'] });

    story.when('the client lists tools');
    const { tools } = await client.listTools();

    story.then('the denied tool is not there and the others are');
    expect(tools.map((t) => t.name).sort()).toEqual(['search_cases', 'update_case']);
  });

  it('refuses a call to a hidden tool without reaching the upstream', async ({ task }) => {
    story.init(task, { tags: ['wrap', 'security'], covers: ['src/wrap.ts'] });

    story.given('a wrapped server with delete_case denied');
    const { client, log } = await connect({ deny: ['delete_case'] });

    story.when('the client names the hidden tool anyway');
    const refused = client.callTool({ name: 'delete_case', arguments: {} });

    story.then('it gets an error that says wrap blocked it');
    await expect(refused).rejects.toThrow(/delete_case.*blocked by mcp-authz wrap/);

    story.and('a visible tool still runs, and only it reached the upstream');
    const result = await client.callTool({ name: 'search_cases', arguments: {} });
    expect(result.content).toEqual([{ type: 'text', text: 'search_cases done' }]);
    expect(log()).toContain('upstream ran search_cases');
    expect(log()).not.toContain('upstream ran delete_case');
  });

  it('shows only allowed tools, says what it hid, and names a typo', async ({ task }) => {
    story.init(task, { tags: ['wrap', 'dx'], covers: ['src/wrap.ts'] });

    story.given('a wrapped server with --allow search_cases,serch_cases');
    const { client, log } = await connect({ allow: ['search_cases', 'serch_cases'] });

    story.when('the client lists tools');
    const { tools } = await client.listTools();

    story.then('only the allowed tool is listed');
    expect(tools.map((t) => t.name)).toEqual(['search_cases']);

    story.and('stderr says what was hidden, and that one name matched nothing');
    expect(log()).toMatch(
      /mcp-authz wrap: 1\/3 tools exposed \(~\d+ of ~\d+ tokens\), hidden: delete_case, update_case/,
    );
    expect(log()).toContain('mcp-authz wrap: no tool named serch_cases');
  });

  it('with recorded definitions, hides an allowed tool the record never saw', async ({ task }) => {
    story.init(task, { tags: ['wrap', 'security'], covers: ['src/wrap.ts'] });

    story.given('an allow list naming update_case, and a record that predates it');
    const { client, log } = await connect({
      allow: ['search_cases', 'update_case'],
      pinned: new Map([
        [
          'search_cases',
          { name: 'search_cases', description: 'Find cases', annotations: { readOnlyHint: true } },
        ],
      ]),
    });

    story.when('the client lists tools');
    const names = (await client.listTools()).tools.map((t) => t.name);

    story.then('only the tool whose definition was approved is shown');
    // search_cases's pin omits inputSchema, which the server sends, so it
    // too reads as changed: a pin covers every field the model reads.
    expect(names).toEqual([]);
    expect(log()).toContain('hid update_case: it was not offered when you approved this list');
    expect(log()).toContain('hid search_cases: its inputSchema changed since you approved it');
  });

  it('checks a definition before a call made without listing first', async ({ task }) => {
    story.init(task, { tags: ['wrap', 'security'], covers: ['src/wrap.ts'] });

    story.given('search_cases approved as something other than what the server now says');
    const { client, log } = await connect({
      allow: ['search_cases', 'update_case'],
      pinned: new Map([
        ['search_cases', { name: 'search_cases', description: 'Approved words' }],
        ['update_case', { name: 'update_case' }],
      ]),
    });

    story.when('the client calls it without ever listing');
    const refused = client.callTool({ name: 'search_cases', arguments: {} });

    story.then('wrap lists the server itself, refuses the call, and the server never runs it');
    await expect(refused).rejects.toThrow(/search_cases.*description.*changed since you approved it/);
    expect(log()).not.toContain('upstream ran search_cases');
  });

  it('checks a tool on the second page of a modern server, keeping the protocol fields', async ({ task }) => {
    story.init(task, { tags: ['wrap', 'security'], covers: ['src/wrap.ts'] });

    story.given('a server that lists update_case on page two and wants _meta on every request');
    const output = new PassThrough();
    const input = new PassThrough();
    const answers: string[] = [];
    output.on('data', (chunk: Buffer) => answers.push(...chunk.toString('utf8').split('\n').filter(Boolean)));
    const exited = wrap(
      {
        command: process.execPath,
        args: [RAW, 'paged'],
        allow: ['search_cases', 'update_case'],
        pinned: new Map([
          ['search_cases', { name: 'search_cases' }],
          ['update_case', { name: 'update_case' }],
        ]),
      },
      { input, output, log: () => {} },
    );

    story.when('the client calls update_case straight away');
    const meta = { 'io.modelcontextprotocol/protocolVersion': '2026-07-28' };
    input.write(
      `${JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'update_case', arguments: {}, _meta: meta } })}\n`,
    );

    story.then('wrap reads both pages, finds it unchanged, and the call runs');
    await vi.waitFor(() => expect(answers.join('\n')).toContain('update_case done'));
    input.end();
    await exited;
  });

  it('answers a call whose recorded schema cannot be checked, and keeps running', async ({ task }) => {
    story.init(task, { tags: ['wrap', 'security'], covers: ['src/wrap.ts', 'src/screen.ts'] });
    const output = new PassThrough();
    const input = new PassThrough();
    const answers: string[] = [];
    output.on('data', (chunk: Buffer) => answers.push(...chunk.toString('utf8').split('\n').filter(Boolean)));
    const definition = {
      name: 'fetch_report',
      inputSchema: { $ref: 'http://169.254.169.254/latest/meta-data/schema.json' },
    };
    const exited = wrap(
      {
        command: process.execPath,
        args: [RAW, 'ref'],
        allow: ['fetch_report'],
        pinned: new Map([['fetch_report', definition]]),
      },
      { input, output, log: () => {} },
    );

    story.when('the client calls the tool, then pings');
    input.write(
      `${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'fetch_report', arguments: {} } })}\n`,
    );

    story.then('the call is refused with a reason, and wrap is still there to answer');
    await vi.waitFor(() => expect(answers.join('\n')).toContain('the recorded schema could not be checked'));
    input.end();
    await exited;
  });

  it('refuses a request whose id it could not match to the answer', async ({ task }) => {
    story.init(task, { tags: ['wrap', 'security'], covers: ['src/wrap.ts'] });
    const output = new PassThrough();
    const input = new PassThrough();
    let answered = '';
    let log = '';
    output.on('data', (chunk: Buffer) => (answered += chunk.toString('utf8')));
    const exited = wrap(
      { command: process.execPath, args: [UPSTREAM], deny: ['delete_case'] },
      { input, output, log: (line) => (log += `${line}\n`) },
    );

    story.when('a listing and a call carry an id past 2^53');
    input.write('{"jsonrpc":"2.0","id":9007199254740993,"method":"tools/list","params":{}}\n');
    input.write(
      '{"jsonrpc":"2.0","id":9007199254740995,"method":"tools/call","params":{"name":"search_cases","arguments":{}}}\n',
    );

    story.then('both are refused, with the id echoed exactly, and neither reaches the server');
    await vi.waitFor(() => expect(answered).toContain('"id":9007199254740995'));
    expect(answered).toContain('"id":9007199254740993,"error"');
    expect(answered).toContain('cannot track an id it cannot hold exactly');
    expect(answered).not.toContain('delete_case');
    expect(log).not.toContain('upstream ran');
    input.end();
    await exited;
  });

  it('exits non-zero, saying why, when the upstream cannot start', async ({ task }) => {
    story.init(task, { tags: ['wrap', 'dx'], covers: ['src/wrap.ts'] });

    story.given('a wrap whose upstream command does not exist');
    let log = '';
    const exited = wrap(
      { command: 'mcp-authz-no-such-server', args: [] },
      { input: new PassThrough(), output: new PassThrough(), log: (line) => (log += line) },
    );

    story.then('it exits 1 rather than hanging, and names the command');
    await expect(exited).resolves.toBe(1);
    expect(log).toContain('mcp-authz-no-such-server');
  });

  it('exits once the client goes away, with the upstream exit code', async ({ task }) => {
    story.init(task, { tags: ['wrap'], covers: ['src/wrap.ts'] });

    story.given('a connected client');
    const { client, exited } = await connect({});
    running.pop();

    story.when('the client closes its end');
    await client.close();

    story.then('the upstream exits cleanly and wrap reports its code');
    await expect(exited).resolves.toBe(0);
  });
});

const RAW = fileURLToPath(new URL('./__fixtures__/raw-upstream.mjs', import.meta.url));

/** `wrap` over a bare-JSON-lines upstream, for orderings the SDK will not produce. */
function raw(
  mode: string,
  options: { deny?: string[]; signal?: AbortSignal; graceMs?: number; output?: Writable } = {},
) {
  const input = new PassThrough();
  const output = options.output ?? new PassThrough();
  const received: Record<string, unknown>[] = [];
  if (output instanceof PassThrough) {
    let buffered = '';
    output.setEncoding('utf8');
    output.on('data', (chunk: string) => {
      buffered += chunk;
      let newline;
      while ((newline = buffered.indexOf('\n')) !== -1) {
        received.push(JSON.parse(buffered.slice(0, newline)));
        buffered = buffered.slice(newline + 1);
      }
    });
  }
  let log = '';
  const exited = wrap(
    { command: process.execPath, args: [RAW, mode], deny: options.deny, graceMs: options.graceMs },
    { input, output, log: (line) => (log += `${line}\n`), signal: options.signal },
  );
  return {
    input,
    exited,
    log: () => log,
    send: (message: object) => input.write(`${JSON.stringify({ jsonrpc: '2.0', ...message })}\n`),
    received: async (count: number) => {
      await expect.poll(() => received.length, { timeout: 15_000 }).toBeGreaterThanOrEqual(count);
      return received;
    },
  };
}

describe('wrap, at the edges of the protocol', () => {
  it('reads a message the way the server does: one line per newline, whatever the text holds', async ({
    task,
  }) => {
    story.init(task, { tags: ['wrap', 'security'], covers: ['src/wrap.ts'] });

    story.given('a wrapped server with delete_case denied');
    const upstream = raw('plain', { deny: ['delete_case'] });

    story.when('a call carries U+2028 in an argument, and the listing carries it in descriptions');
    const call = `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"search_cases","arguments":{"q":"a\u2028b"}}}`;
    upstream.input.write(`${call}\n`);
    upstream.send({ id: 6, method: 'tools/list' });

    story.then('the call reaches the server whole, and the listing still comes back filtered');
    // The server logged one line; the log itself, read with node:readline,
    // shows it broken at U+2028.
    await expect.poll(() => upstream.log()).toContain(`upstream got ${call.replace('\u2028', '\n')}`);
    const replies = await upstream.received(1);
    expect(replies.find((reply) => reply.id === 6)).toMatchObject({
      result: { tools: [{ name: 'search_cases' }] },
    });
    upstream.input.end();
    await upstream.exited;
  });

  it('refuses a batch rather than forwarding calls it did not check', async ({ task }) => {
    story.init(task, { tags: ['wrap', 'security'], covers: ['src/wrap.ts'] });

    story.given('a wrapped server with delete_case denied');
    const upstream = raw('plain', { deny: ['delete_case'] });

    story.when('a client sends the denied call inside a JSON-RPC batch');
    upstream.input.write(
      `${JSON.stringify([{ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'delete_case' } }])}\n`,
    );

    story.then('wrap refuses the batch, and nothing reaches the server');
    const [reply] = await upstream.received(1);
    expect(reply).toMatchObject({ id: null, error: { code: -32600 } });
    expect(upstream.log()).not.toContain('upstream got');
    upstream.input.end();
    await upstream.exited;
  });

  it('refuses a line it cannot parse rather than forwarding it unchecked', async ({ task }) => {
    story.init(task, { tags: ['wrap', 'security'], covers: ['src/wrap.ts'] });

    story.given('a wrapped server with delete_case denied');
    const upstream = raw('plain', { deny: ['delete_case'] });

    story.when('a client sends a line that is not valid JSON');
    upstream.input.write('{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_case"}\n');

    story.then('wrap answers with a parse error, and nothing reaches the server');
    const [reply] = await upstream.received(1);
    expect(reply).toMatchObject({ id: null, error: { code: -32700 } });
    expect(upstream.log()).not.toContain('upstream got');
    upstream.input.end();
    await upstream.exited;
  });

  it('refuses a message with a duplicate key, so the two sides cannot read different calls', async ({
    task,
  }) => {
    story.init(task, { tags: ['wrap', 'security'], covers: ['src/wrap.ts'] });

    story.given('a wrapped server with delete_case denied');
    const upstream = raw('plain', { deny: ['delete_case'] });

    story.when('a client names two tools in one call, one of them spelled with an escape');
    upstream.input.write(
      '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"delete_case","na\\u006de":"search_cases"}}\n',
    );

    story.then('wrap answers that request with an error, and nothing reaches the server');
    const [reply] = await upstream.received(1);
    expect(reply).toMatchObject({ id: 3, error: { code: -32600 } });
    expect(upstream.log()).not.toContain('upstream got');
    upstream.input.end();
    await upstream.exited;
  });

  it('forwards an allowed call byte for byte, so large numbers keep every digit', async ({ task }) => {
    story.init(task, { tags: ['wrap'], covers: ['src/wrap.ts'] });

    story.given('a wrapped server');
    const upstream = raw('plain', { deny: ['delete_case'] });

    story.when('a client calls a visible tool with an id larger than a double can hold exactly');
    const line =
      '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"search_cases","arguments":{"record_id":9007199254740993}}}';
    upstream.input.write(`${line}\n`);

    story.then('the server receives exactly what was sent');
    await expect.poll(() => upstream.log()).toContain(`upstream got ${line}`);
    upstream.input.end();
    await upstream.exited;
  });

  it('filters a listing even when the server reuses its id for a request of its own', async ({ task }) => {
    story.init(task, { tags: ['wrap', 'security'], covers: ['src/wrap.ts'] });

    story.given('a server that sends roots/list with the same id as the pending tools/list');
    const upstream = raw('collide', { deny: ['delete_case'] });

    story.when('the client lists tools');
    upstream.send({ id: 1, method: 'tools/list' });
    const [request, response] = await upstream.received(2);

    story.then("the server's request passes through, and the listing is still filtered");
    expect(request).toMatchObject({ id: 1, method: 'roots/list' });
    expect(response).toMatchObject({ id: 1, result: { tools: [{ name: 'search_cases' }] } });
    upstream.input.end();
    await upstream.exited;
  });

  it('stops a server that ignores the end of its input, rather than hanging', async ({ task }) => {
    story.init(task, { tags: ['wrap'], covers: ['src/wrap.ts'] });

    story.given('a server that ignores both EOF and SIGTERM');
    const upstream = raw('stubborn', { graceMs: 50 });

    story.when('the client disconnects');
    upstream.input.end();

    story.then('wrap escalates to SIGKILL and exits');
    await expect(upstream.exited).resolves.toBe(1);
  });

  it('stops the server when wrap itself is told to stop', async ({ task }) => {
    story.init(task, { tags: ['wrap'], covers: ['src/wrap.ts'] });

    story.given('a running server, and a client that has not disconnected');
    const stop = new AbortController();
    const upstream = raw('stubborn', { signal: stop.signal, graceMs: 50 });

    story.when('wrap receives a signal');
    stop.abort();

    story.then('the server does not outlive it');
    await expect(upstream.exited).resolves.toBe(1);
  });

  it('stops the real server, not just the launcher in front of it', async ({ task }) => {
    story.init(task, { tags: ['wrap', 'security'], covers: ['src/wrap.ts'] });

    story.given('a launcher, like npx, that started a server which ignores SIGTERM');
    const stop = new AbortController();
    const upstream = raw('launcher', { signal: stop.signal, graceMs: 50 });
    await expect.poll(() => /server pid (\d+)/.exec(upstream.log()), { timeout: 15_000 }).toBeTruthy();
    const pid = Number(/server pid (\d+)/.exec(upstream.log())![1]);

    story.when('wrap is told to stop');
    stop.abort();
    await upstream.exited;

    story.then('by the time wrap exits, the server is gone too');
    expect(() => process.kill(pid, 0)).toThrow();
  });

  it('finishes stopping the server when the client has already closed its end', async ({ task }) => {
    story.init(task, { tags: ['wrap'], covers: ['src/wrap.ts'] });

    story.given('a client whose end of the pipe is closed, as on disconnect');
    const closed = new Writable({
      write: (_chunk, _encoding, done) => done(Object.assign(new Error('write EPIPE'), { code: 'EPIPE' })),
    });
    const upstream = raw('farewell', { output: closed, graceMs: 50 });
    await expect.poll(() => upstream.log()).toBe('');

    story.when('the client disconnects and the server says one last thing');
    upstream.input.end();

    story.then('wrap skips the write and still stops the server');
    await expect(upstream.exited).resolves.toBe(1);
  });

  it('reaps the server when its launcher exits before the client disconnects', async ({ task }) => {
    story.init(task, { tags: ['wrap', 'security'], covers: ['src/wrap.ts', 'src/windows-job.ts'] });
    story.given('a launcher that starts a persistent server and immediately exits 23');
    const upstream = raw('launcher-exit', { graceMs: 50 });
    let pid: number | undefined;
    try {
      await expect.poll(() => /server pid (\d+)/.exec(upstream.log()), { timeout: 15_000 }).toBeTruthy();
      pid = Number(/server pid (\d+)/.exec(upstream.log())![1]);
      story.when('wrap observes the launcher exit with client input still open');
      await expect(upstream.exited).resolves.toBe(23);
      story.then('the descendant is gone and the launcher exit code is preserved');
      await expect
        .poll(() => {
          try {
            process.kill(pid!, 0);
            return false;
          } catch {
            return true;
          }
        })
        .toBe(true);
    } finally {
      upstream.input.end();
      if (pid !== undefined) {
        try {
          process.kill(pid, 'SIGKILL');
        } catch {
          /* Already reaped. */
        }
      }
      await upstream.exited;
    }
  });

  it('drops messages that arrive while it is shutting down', async ({ task }) => {
    story.init(task, { tags: ['wrap'], covers: ['src/wrap.ts'] });

    story.given('a wrap that has started to stop');
    const stop = new AbortController();
    const upstream = raw('stubborn', { signal: stop.signal, graceMs: 50 });
    stop.abort();

    story.when('the client sends one more request');
    upstream.send({ id: 9, method: 'tools/list' });

    story.then('wrap still finishes stopping the server');
    await expect(upstream.exited).resolves.toBe(1);
  });
});
