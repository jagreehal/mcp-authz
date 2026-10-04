// A stdio server written as bare JSON lines, for behaviour the SDK will not
// produce on cue. `node raw-upstream.mjs <mode>`:
//
//   collide   before answering tools/list, sends its own request reusing that id
//             (legal: each side numbers its own requests)
//   stubborn  ignores both the end of stdin and SIGTERM
//   farewell  on the end of stdin, sends one last notification and keeps
//             running, ignoring SIGTERM
//   launcher  starts a stubborn server and waits on it, the way npx does, and
//             reports the server's pid on stderr
//   launcher-exit  as launcher, then exits itself, leaving the server running
//   ref       lists a tool whose inputSchema is a remote $ref
//   paged     a 2026-07-28 server that lists its tools over two pages and wants
//             protocol _meta on every request
import process from 'node:process';
import { setInterval } from 'node:timers';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const mode = process.argv[2];
const send = (message) => process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', ...message })}\n`);

if (mode === 'farewell') {
  process.stdin.on('end', () => send({ method: 'notifications/message', params: { data: 'bye' } }));
}

if (mode === 'stubborn' || mode === 'farewell') {
  process.on('SIGTERM', () => {});
  setInterval(() => {}, 1000);
}

if (mode === 'launcher' || mode === 'launcher-exit') {
  const server = spawn(process.execPath, [fileURLToPath(import.meta.url), 'stubborn'], { stdio: 'inherit' });
  process.stderr.write(`server pid ${server.pid}\n`, () => {
    if (mode === 'launcher-exit') process.exit(23);
  });
} else
  // Lines end at \n alone, as in the MCP SDKs; U+2028 inside a string stays put.
  onLines(process.stdin, (line) => {
    // Every line that arrives, verbatim, so a test can see what got through.
    process.stderr.write(`upstream got ${line}\n`);
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      return;
    }
    const { id, method } = message;
    if (mode === 'ref') {
      // A tool whose schema points at a URL: a validator that followed it would
      // fetch from the network, and one that cannot must still answer.
      const tool = {
        name: 'fetch_report',
        inputSchema: { $ref: 'http://169.254.169.254/latest/meta-data/schema.json' },
      };
      if (method === 'tools/list') send({ id, result: { tools: [tool] } });
      if (method === 'tools/call') send({ id, result: { content: [{ type: 'text', text: 'ran' }] } });
      return;
    }
    if (mode === 'paged') {
      // A 2026-07-28 server: every request carries its protocol version, the
      // second page of a listing as much as the first.
      if (!message.params?._meta?.['io.modelcontextprotocol/protocolVersion']) {
        send({ id, error: { code: -32602, message: 'missing protocol _meta' } });
      } else if (method === 'tools/list') {
        const tool = message.params.cursor ? 'update_case' : 'search_cases';
        send({
          id,
          result: { tools: [{ name: tool }], ...(message.params.cursor ? {} : { nextCursor: 'two' }) },
        });
      } else if (method === 'tools/call') {
        send({ id, result: { content: [{ type: 'text', text: `${message.params.name} done` }] } });
      }
      return;
    }
    if (method === 'tools/list') {
      if (mode === 'collide') send({ id, method: 'roots/list' });
      // A description may carry U+2028, which JSON.stringify leaves unescaped.
      send({
        id,
        result: {
          tools: [
            { name: 'search_cases', description: 'Find cases\u2028by text' },
            { name: 'delete_case', description: 'Remove a case\u2028for good' },
          ],
        },
      });
    }
  });

function onLines(stream, onLine) {
  let buffered = '';
  stream.setEncoding('utf8');
  stream.on('data', (chunk) => {
    buffered += chunk;
    let newline;
    while ((newline = buffered.indexOf('\n')) !== -1) {
      onLine(buffered.slice(0, newline));
      buffered = buffered.slice(newline + 1);
    }
  });
}
