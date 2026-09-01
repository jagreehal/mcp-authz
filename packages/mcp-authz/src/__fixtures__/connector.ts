import { McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';

/**
 * What a connector module looks like from the CLI's side: it already holds the
 * configuration, so it can hand back a built server with no arguments. Built
 * ungated on purpose — a gated server answers per principal.
 */
export default function buildServer(): McpServer {
  const server = new McpServer(
    { name: 'fixture-connector', version: '1.0.0' },
    { capabilities: { tools: {}, prompts: {} } },
  );
  server.registerTool(
    'get_case',
    { description: 'Read one case', inputSchema: { id: z.string() } },
    async () => ({ content: [] }),
  );
  server.registerTool('update_case', { description: 'Change one case' }, async () => ({ content: [] }));
  server.registerPrompt('triage', { description: 'Walk a failure' }, () => ({ messages: [] }));
  return server;
}
