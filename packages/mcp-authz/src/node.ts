import { createServer, type Server } from 'node:http';
import { toNodeHandler } from '@modelcontextprotocol/node';

export type ListenMcpOptions = {
  port: number;
  /** Log label. Defaults to `mcp-authz`. */
  name?: string;
  /** Extra lines logged after the listen banner. */
  info?: Record<string, string | undefined>;
};

/**
 * Bind a `createMcpFetch` handler to every interface. Safe because the
 * bearer gate is the security boundary, not the bind address.
 */
export async function listenMcp(
  fetch: (request: Request) => Promise<Response>,
  options: ListenMcpOptions,
): Promise<Server> {
  const { port, name = 'mcp-authz', info = {} } = options;

  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`PORT must be an integer between 1 and 65535; received ${port}.`);
  }

  const nodeHandler = toNodeHandler({ fetch });
  const server = createServer((request, response) => {
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Referrer-Policy', 'no-referrer');
    Promise.resolve(nodeHandler(request, response)).catch((error: unknown) => {
      console.error(`[${name}]`, error);
      if (!response.headersSent) response.writeHead(500);
      response.end('Internal Server Error');
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, () => {
      server.off('error', reject);
      resolve();
    });
  });

  console.log(`${name} on :${port}`);
  for (const [key, value] of Object.entries(info)) {
    if (value) console.log(`  ${key.padEnd(10)} ${value}`);
  }

  let stopping = false;
  function shutdown(signal: NodeJS.Signals): void {
    if (stopping) return;
    stopping = true;
    console.error(`[${name}] ${signal}; draining connections`);
    server.close((error) => {
      if (error) console.error(`[${name}] shutdown failed`, error);
      process.exitCode = error ? 1 : 0;
    });
    setTimeout(() => server.closeAllConnections(), 10_000).unref();
  }

  process.once('SIGINT', () => shutdown('SIGINT'));
  process.once('SIGTERM', () => shutdown('SIGTERM'));

  return server;
}
