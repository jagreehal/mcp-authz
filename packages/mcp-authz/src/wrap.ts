import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { setTimeout as sleep } from 'node:timers/promises';
import type { Readable, Writable } from 'node:stream';
import { windowsJobCommand } from './windows-job';

/**
 * Sit in front of a stdio MCP server and show the model fewer of its tools.
 *
 * Over stdio, MCP is one JSON-RPC message per line, so this needs no SDK. It
 * filters `tools/list` results, answers calls to hidden tools itself, and
 * forwards every other message as written, whichever protocol version the two
 * ends negotiate.
 *
 * It trims what one session can reach. The credential the upstream holds keeps
 * its full reach for anything else that uses it.
 */

export type WrapOptions = {
  command: string;
  args: readonly string[];
  allow?: readonly string[];
  deny?: readonly string[];
  /** Where the server runs. Defaults to this process's working directory. */
  cwd?: string;
  /** How long each shutdown step waits before the next, harder one. */
  graceMs?: number;
};

export type WrapIo = {
  input: Readable;
  output: Writable;
  log: (line: string) => void;
  /** Aborted when this process is told to stop, so the server is too. */
  signal?: AbortSignal;
};

type Message = {
  id?: string | number;
  method?: string;
  params?: { name?: unknown };
  result?: { tools?: { name: string }[]; nextCursor?: string };
};

/** Resolves with the upstream's exit code. */
export function wrap(options: WrapOptions, io: WrapIo): Promise<number> {
  const visible = (name: string) =>
    options.allow ? options.allow.includes(name) : !options.deny?.includes(name);

  // Unix uses a process group; Windows uses a supervisor owning a Job Object.
  // Both keep descendants reachable after their launcher exits.
  const windows = process.platform === 'win32';
  const upstream = windows ? windowsJobCommand(options.command, options.args) : undefined;
  const child = spawn(upstream?.command ?? options.command, [...(upstream?.args ?? options.args)], {
    stdio: ['pipe', 'pipe', 'pipe'],
    detached: !windows,
    windowsHide: true,
    ...(options.cwd ? { cwd: options.cwd } : {}),
  });
  // The server can exit with a message in flight; the write then fails with
  // EPIPE, and the exit handler below takes it from there.
  child.stdin.on('error', () => {});
  // Ids of the client's `tools/list` requests, so their answers can be filtered.
  const listing = new Set<string | number>();

  // Said once, on the first full listing: the line you read in your client's
  // server log to see the filter took, and which names in it matched nothing.
  const seen = new Set<string>();
  let reported = false;
  const report = () => {
    if (reported) return;
    reported = true;
    const hidden = [...seen].filter((name) => !visible(name)).sort();
    io.log(
      `mcp-authz wrap: ${seen.size - hidden.length}/${seen.size} tools exposed` +
        (hidden.length > 0 ? `, hidden: ${hidden.join(', ')}` : ''),
    );
    for (const name of options.allow ?? options.deny ?? []) {
      if (!seen.has(name)) io.log(`mcp-authz wrap: no tool named ${name}`);
    }
  };

  // A line is forwarded byte for byte, so a large number in an argument keeps
  // every digit, once wrap has read it exactly as the server will: one message,
  // valid JSON, no repeated key. Parsers resolve a repeated key differently, so
  // wrap answers those itself, along with batches, which MCP dropped in
  // 2025-06-18.
  onLines(io.input, (line) => {
    if (stopping || line.trim() === '') return;
    let value: unknown;
    // Answer with the request's own id when there is one, so the client can
    // match the error to its request instead of waiting on it.
    const refuse = (code: number, reason: string) => {
      const id = (value as Message | undefined)?.id;
      const replyTo = typeof id === 'string' || typeof id === 'number' ? id : null;
      send(JSON.stringify({ jsonrpc: '2.0', id: replyTo, error: { code, message: reason } }));
    };
    try {
      value = JSON.parse(line);
    } catch {
      refuse(-32700, 'Parse error: mcp-authz wrap forwards only messages it can read');
      return;
    }
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      refuse(-32600, 'Invalid request: mcp-authz wrap forwards single JSON-RPC messages, not batches');
      return;
    }
    if (hasDuplicateKey(line)) {
      refuse(-32600, 'Invalid request: mcp-authz wrap refuses a message that repeats a key');
      return;
    }
    const message = value as Message;
    if (message.method === 'tools/list' && message.id !== undefined) listing.add(message.id);
    // Answered here, so the upstream never sees it. -32602 is the code the spec
    // gives a server for a tool it does not know.
    const name = message.method === 'tools/call' ? message.params?.name : undefined;
    if (message.method === 'tools/call' && (typeof name !== 'string' || !visible(name))) {
      const error = {
        code: -32602,
        message:
          typeof name === 'string'
            ? `Tool "${name}" is blocked by mcp-authz wrap`
            : 'tools/call needs a tool name',
      };
      send(JSON.stringify({ jsonrpc: '2.0', id: message.id ?? null, error }));
      return;
    }
    child.stdin.write(`${line}\n`);
  });

  // A disconnecting client closes its end first, so the server's last message
  // can meet a closed pipe. wrap stops writing and finishes the shutdown.
  io.output.on('error', () => void stop());
  const send = (line: string) => {
    if (io.output.writable) io.output.write(`${line}\n`);
  };

  const treeAlive = (): boolean => {
    if (child.pid === undefined) return false;
    if (windows) return child.exitCode === null && child.signalCode === null;
    try {
      process.kill(-child.pid, 0);
      return true;
    } catch {
      return false;
    }
  };
  const signalTree = (signal: NodeJS.Signals) => {
    if (child.pid === undefined) return;
    if (windows) {
      // Terminating the supervisor closes the last job handle, which kills
      // its entire tree. It also does this itself when the launcher exits.
      child.kill('SIGKILL');
      return;
    }
    try {
      process.kill(-child.pid, signal);
    } catch {
      // Gone between the check and the signal.
    }
  };
  const goneWithin = async (ms: number) => {
    for (const deadline = Date.now() + ms; Date.now() < deadline; await sleep(25)) {
      if (!treeAlive()) return true;
    }
    return !treeAlive();
  };

  // The spec's stdio shutdown: close the server's input, then SIGTERM, then
  // SIGKILL, each after a grace period, to the whole group. Escalation follows
  // the group rather than the child, because a launcher that exits on SIGTERM
  // can leave behind the server that ignored it.
  const grace = options.graceMs ?? 2000;
  let stopping: Promise<void> | undefined;
  const stop = () =>
    (stopping ??= (async () => {
      child.stdin.end();
      for (const signal of ['SIGTERM', 'SIGKILL'] as const) {
        if (await goneWithin(grace)) return;
        signalTree(signal);
      }
      await goneWithin(grace);
    })());
  io.input.on('end', stop);
  if (io.signal?.aborted) void stop();
  else io.signal?.addEventListener('abort', stop, { once: true });

  onLines(child.stdout, (line) => {
    const message = parse(line);
    // Only a response settles a request: the server numbers its own requests,
    // and one of those can carry the id of a listing still in flight.
    const response = message?.method === undefined && message?.id !== undefined;
    if (response && listing.delete(message.id!) && message.result?.tools) {
      for (const tool of message.result.tools) seen.add(tool.name);
      if (!message.result.nextCursor) report();
      message.result.tools = message.result.tools.filter((tool) => visible(tool.name));
      line = JSON.stringify(message);
    }
    send(line);
  });

  createInterface({ input: child.stderr }).on('line', io.log);

  const exited = new Promise<number>((resolve) => {
    child.on('exit', (code) => resolve(code ?? 1));
    // A command that never starts emits 'error' and no 'exit'.
    child.on('error', (error) => {
      io.log(
        `mcp-authz wrap: could not start ${options.command}: ${error.message}. ` +
          'Install it, or give its full path in your config.',
      );
      resolve(1);
    });
  });
  // Stopping after any exit also reaps whatever the server left in its group.
  return exited.then(async (code) => {
    await stop();
    // The launcher deletes the spec once read; this covers a launcher that never ran.
    upstream?.cleanup();
    return code;
  });
}

/**
 * Call `onLine` for each newline-terminated line, framed as the MCP SDKs frame
 * stdio: split on `\n` alone, with a trailing `\r` dropped. node:readline also
 * splits on `\r`, U+2028 and U+2029, which JSON allows unescaped inside a
 * string, so it would read one message as two where the server reads one.
 */
function onLines(stream: Readable, onLine: (line: string) => void): void {
  let buffered = '';
  stream.setEncoding('utf8');
  stream.on('data', (chunk: string) => {
    buffered += chunk;
    let newline;
    while ((newline = buffered.indexOf('\n')) !== -1) {
      onLine(buffered.slice(0, newline).replace(/\r$/, ''));
      buffered = buffered.slice(newline + 1);
    }
  });
  stream.on('end', () => {
    if (buffered !== '') onLine(buffered.replace(/\r$/, ''));
    buffered = '';
  });
}

/**
 * Whether any object repeats a key, compared after unescaping, so `"name"` and
 * `"na\u006de"` are the same key. Only called on text JSON.parse accepted,
 * which is what lets it skip validating anything else.
 */
function hasDuplicateKey(text: string): boolean {
  const scopes: (Set<string> | undefined)[] = [];
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (char === '{') scopes.push(new Set());
    else if (char === '[') scopes.push(undefined);
    else if (char === '}' || char === ']') scopes.pop();
    else if (char === '"') {
      let end = i + 1;
      while (text[end] !== '"') end += text[end] === '\\' ? 2 : 1;
      let next = end + 1;
      while (text[next] === ' ' || text[next] === '\t' || text[next] === '\r' || text[next] === '\n') next++;
      const scope = scopes.at(-1);
      // In an object, a string followed by a colon is a key.
      if (scope && text[next] === ':') {
        const key = JSON.parse(text.slice(i, end + 1)) as string;
        if (scope.has(key)) return true;
        scope.add(key);
      }
      i = end;
    }
  }
  return false;
}

function parse(line: string): Message | undefined {
  try {
    const value: unknown = JSON.parse(line);
    return typeof value === 'object' && value !== null ? (value as Message) : undefined;
  } catch {
    return undefined;
  }
}
