import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { setTimeout as sleep } from 'node:timers/promises';
import type { Readable, Writable } from 'node:stream';
import { changedFields, definitionOf, INSTRUCTIONS, type Definition } from './definitions';
import { checkArguments, screenResult, withNotice } from './screen';
import { hasDuplicateKey, holdsInexactNumber, parseChecked } from './strict-json';
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
 *
 * Given the definitions you approved, it also hides any tool whose definition
 * has changed since: a server that rewrites a description to steer the model,
 * or adds an argument to exfiltrate through, loses the tool until you review
 * the change. A name alone is not consent to whatever the server later puts
 * behind it. A call is held until wrap has seen the tool's live definition,
 * since a client may call without listing first, and the server's own
 * instructions are held to the record the same way.
 */

export type WrapOptions = {
  command: string;
  args: readonly string[];
  allow?: readonly string[];
  deny?: readonly string[];
  /**
   * Each tool's definition when it was approved. A listed tool that differs is
   * hidden; with `allow`, so is one that was never recorded.
   */
  pinned?: ReadonlyMap<string, Definition>;
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
  params?: { name?: unknown; arguments?: unknown; _meta?: Record<string, unknown> };
  result?: {
    tools?: ({ name: string } & Record<string, unknown>)[];
    content?: unknown;
    structuredContent?: unknown;
    nextCursor?: string;
    instructions?: unknown;
  };
  error?: unknown;
};

/**
 * Roughly what a tool's definition costs in the model's context: its JSON, at
 * four characters a token. A guide for choosing what to hide, not a bill.
 */
export function estimateTokens(tool: object): number {
  return Math.ceil(JSON.stringify(tool).length / 4);
}

export function formatTokens(tokens: number): string {
  return tokens < 1000 ? `~${tokens}` : `~${(tokens / 1000).toFixed(1)}k`;
}

/** Resolves with the upstream's exit code. */
export function wrap(options: WrapOptions, io: WrapIo): Promise<number> {
  const listed = (name: string) =>
    options.allow ? options.allow.includes(name) : !options.deny?.includes(name);
  // Why a tool you listed is hidden anyway: its definition is not the one you
  // approved. Updated on every listing, so a change mid-session is caught too.
  const changed = new Map<string, string>();
  const drift = (tool: { name: string } & Record<string, unknown>): string | undefined => {
    if (!options.pinned) return undefined;
    const approved = options.pinned.get(tool.name);
    if (!approved) return options.allow ? 'it was not offered when you approved this list' : undefined;
    const fields = changedFields(approved, definitionOf(tool));
    return fields.length > 0 ? `its ${fields.join(', ')} changed since you approved it` : undefined;
  };
  const visible = (name: string) => listed(name) && !changed.has(name);
  // Tools whose live definition matched the record since the server last said
  // its list changed. Only these are called without checking first.
  const verified = new Set<string>();
  const check = (tool: { name: string } & Record<string, unknown>) => {
    const reason = drift(tool);
    if (reason === undefined) {
      changed.delete(tool.name);
      verified.add(tool.name);
      return;
    }
    verified.delete(tool.name);
    if (listed(tool.name) && changed.get(tool.name) !== reason) {
      changed.set(tool.name, reason);
      io.log(
        `mcp-authz wrap: hid ${tool.name}: ${reason}. ` +
          'Review it with mcp-authz tools --check <config>, then --refresh to approve.',
      );
    }
  };

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
  // Ids of the client's `tools/list` requests, so their answers can be filtered,
  // and of its `initialize` or `server/discover`, whose instructions are checked.
  const listing = new Set<string | number>();
  const discovering = new Set<string | number>();

  // Calls waiting on wrap's own listing, which it sends when a call names a tool
  // it has not yet seen. Its pages are answered here and never reach the client.
  const held: { line: string; message: Message }[] = [];
  let verifying: string | undefined;
  let verifications = 0;
  // Kept for every page: a 2026-07-28 server wants the protocol fields on each
  // request, the second page as much as the first.
  let verifyMeta: Record<string, unknown> | undefined;
  const requestList = (meta: Record<string, unknown> | undefined, cursor?: string) => {
    verifyMeta = meta;
    verifying = `mcp-authz-wrap/verify/${++verifications}`;
    const params = { ...(cursor ? { cursor } : {}), ...(meta ? { _meta: meta } : {}) };
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: verifying, method: 'tools/list', params })}\n`);
  };
  // Ids of calls in flight, so their answers can be screened.
  const calls = new Map<string | number, string>();
  const forward = (line: string, message: Message) => {
    const name = message.params!.name as string;
    const approved = options.pinned?.get(name);
    const wrong = approved && checkArguments(name, approved, message.params!.arguments);
    if (wrong) {
      const error = { code: -32602, message: `Invalid params: ${wrong}` };
      send(JSON.stringify({ jsonrpc: '2.0', id: message.id ?? null, error }));
      return;
    }
    if (message.id !== undefined) calls.set(message.id, name);
    child.stdin.write(`${line}\n`);
  };
  const release = (failure?: string) => {
    verifying = undefined;
    for (const { line, message } of held.splice(0)) {
      const name = message.params!.name as string;
      if (!failure && visible(name) && verified.has(name)) {
        forward(line, message);
        continue;
      }
      const reason =
        failure ?? changed.get(name) ?? 'the server did not list it, so its definition could not be checked';
      const error = { code: -32602, message: `Tool "${name}" is blocked by mcp-authz wrap: ${reason}` };
      send(JSON.stringify({ jsonrpc: '2.0', id: message.id ?? null, error }));
    }
  };

  // Said once, on the first full listing: the line you read in your client's
  // server log to see the filter took, what it saved, and which names in it
  // matched nothing.
  const seen = new Map<string, number>();
  let reported = false;
  const report = () => {
    if (reported) return;
    reported = true;
    const hidden = [...seen.keys()].filter((name) => !visible(name)).sort();
    const total = [...seen.values()].reduce((sum, tokens) => sum + tokens, 0);
    const shown = total - hidden.reduce((sum, name) => sum + seen.get(name)!, 0);
    io.log(
      `mcp-authz wrap: ${seen.size - hidden.length}/${seen.size} tools exposed ` +
        `(${formatTokens(shown)} of ${formatTokens(total)} tokens)` +
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
      // An id past what JavaScript holds exactly is echoed as the text it came as.
      const replyTo = typeof id === 'string' || typeof id === 'number' || holdsInexactNumber(id) ? id : null;
      send(JSON.stringify({ jsonrpc: '2.0', id: replyTo, error: { code, message: reason } }));
    };
    try {
      // Exact, so an argument past 2^53 is checked as the server will read it.
      value = parseChecked(line);
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
    // wrap matches each answer to its request by id, to filter a listing or
    // screen a result. An id it cannot hold exactly would never match the
    // answer's, which would then pass unfiltered, so such a request is refused.
    if (message.method !== undefined && holdsInexactNumber(message.id)) {
      refuse(-32600, 'Invalid request: mcp-authz wrap cannot track an id it cannot hold exactly');
      return;
    }
    if (message.method === 'tools/list' && message.id !== undefined) listing.add(message.id);
    if (
      (message.method === 'initialize' || message.method === 'server/discover') &&
      message.id !== undefined
    ) {
      discovering.add(message.id);
    }
    // Answered here, so the upstream never sees it. -32602 is the code the spec
    // gives a server for a tool it does not know.
    const name = message.method === 'tools/call' ? message.params?.name : undefined;
    if (message.method === 'tools/call' && (typeof name !== 'string' || !visible(name))) {
      const error = {
        code: -32602,
        message:
          typeof name !== 'string'
            ? 'tools/call needs a tool name'
            : changed.has(name)
              ? `Tool "${name}" is blocked by mcp-authz wrap: ${changed.get(name)}`
              : `Tool "${name}" is blocked by mcp-authz wrap`,
      };
      send(JSON.stringify({ jsonrpc: '2.0', id: message.id ?? null, error }));
      return;
    }
    if (message.method === 'tools/call' && options.pinned && !verified.has(name as string)) {
      held.push({ line, message });
      // The protocol fields this session's requests carry, so wrap's listing is
      // one the server accepts. A progress token belongs to the call alone.
      const meta = Object.fromEntries(
        Object.entries(message.params?._meta ?? {}).filter(([key]) =>
          key.startsWith('io.modelcontextprotocol/'),
        ),
      );
      if (verifying === undefined) requestList(Object.keys(meta).length > 0 ? meta : undefined);
      return;
    }
    if (message.method === 'tools/call') forward(line, message);
    else child.stdin.write(`${line}\n`);
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
    if (response && message.id === verifying) {
      if (!message.result?.tools) return release('the server would not list its tools to check it');
      for (const tool of message.result.tools) check(tool);
      if (message.result.nextCursor) requestList(verifyMeta, message.result.nextCursor);
      else release();
      return;
    }
    // A changed list may hold changed definitions, so every tool is checked
    // again before its next call.
    if (message?.method === 'notifications/tools/list_changed') verified.clear();
    if (response && listing.delete(message.id!) && message.result?.tools) {
      for (const tool of message.result.tools) {
        seen.set(tool.name, estimateTokens(tool));
        check(tool);
      }
      if (!message.result.nextCursor) report();
      message.result.tools = message.result.tools.filter((tool) => visible(tool.name));
      line = JSON.stringify(message);
    }
    // Instructions reach the model like a description does, so with a record
    // they are held to it: changed, or never recorded, they are removed.
    if (response && discovering.delete(message.id!) && options.pinned && message.result) {
      const live = message.result.instructions;
      const approved = options.pinned.get(INSTRUCTIONS)?.instructions;
      if (live !== undefined && live !== approved) {
        delete message.result.instructions;
        line = JSON.stringify(message);
        io.log(
          "mcp-authz wrap: removed the server's instructions: they changed since you approved them. " +
            'Review with mcp-authz tools --check <config>, then --refresh to approve.',
        );
      }
    }
    const tool = response ? calls.get(message.id!) : undefined;
    if (message && tool !== undefined && calls.delete(message.id!) && message.result) {
      // Checked as written: a number the plain parse rounded would pass a
      // bound the server's own number breaks.
      const checked = (parseChecked(line) as { result: Record<string, unknown> }).result;
      const screened = screenResult(tool, options.pinned?.get(tool) ?? {}, checked);
      // A passing answer goes on as the line that arrived, every digit intact.
      if (screened.verdict !== 'pass') {
        line = JSON.stringify(
          screened.verdict === 'withhold'
            ? { ...message, result: screened.result }
            : withNotice(line, screened.notice),
        );
        io.log(`mcp-authz wrap: ${screened.warning}`);
      }
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

function parse(line: string): Message | undefined {
  try {
    const value: unknown = JSON.parse(line);
    return typeof value === 'object' && value !== null ? (value as Message) : undefined;
  } catch {
    return undefined;
  }
}
