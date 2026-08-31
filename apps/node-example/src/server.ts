import { authz, type AuditEvent } from 'mcp-authz';
import { z } from 'zod';
import { policy } from './policy';

/**
 * Tools, prompts and resources carry the permission they need. Nothing filters
 * `tools/list`: what the caller cannot use is never registered, so it is not
 * there to be listed.
 */

const { tool, prompt, resource, server } = authz(policy);

const cases = new Map([['C1234', { id: 'C1234', title: 'Login rejects an expired password' }]]);

export const tools = [
  tool(
    'whoami',
    {
      permission: 'cases:read',
      description: 'Return the verified caller and what they may do',
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    async (_args, { principal }) => ({
      content: [
        {
          type: 'text' as const,
          text: JSON.stringify(
            { sub: principal.sub, email: principal.email, roles: principal.roles },
            null,
            2,
          ),
        },
      ],
    }),
  ),

  tool(
    'get_case',
    {
      permission: 'cases:read',
      description: 'Fetch a test case',
      inputSchema: z.object({ id: z.string().describe('Case ID, e.g. C1234') }),
      annotations: { readOnlyHint: true },
      audit: ({ id }) => `case:${id}`,
    },
    async ({ id }) => ({
      content: [{ type: 'text' as const, text: JSON.stringify(cases.get(id) ?? null, null, 2) }],
    }),
  ),

  tool(
    'update_case',
    {
      permission: 'cases:write',
      description: 'Rename a test case',
      inputSchema: z.object({ id: z.string(), title: z.string() }),
      audit: ({ id }) => `case:${id}`,
    },
    // No permission check in here. An editor got this tool registered; a reader
    // never saw it. The handler only does the work.
    async ({ id, title }) => {
      cases.set(id, { id, title });
      return { content: [{ type: 'text' as const, text: `Updated ${id}` }] };
    },
  ),

  // A prompt is a tool call somebody else composed. This one talks the caller
  // through a rename, so it costs the same permission the rename costs.
  prompt(
    'triage_case',
    {
      permission: 'cases:write',
      description: 'Walk through renaming a case so it says what actually failed',
      argsSchema: z.object({ id: z.string() }),
      audit: ({ id }) => `case:${id}`,
    },
    async ({ id }) => ({
      messages: [
        {
          role: 'user' as const,
          content: {
            type: 'text' as const,
            text: `Rewrite the title of case ${id} to name the failing behaviour.`,
          },
        },
      ],
    }),
  ),

  // The door people forget. Read-only to MCP, and still the whole case list.
  resource(
    'cases',
    {
      permission: 'cases:read',
      uri: 'cases://all',
      description: 'Every case this caller may read',
      mimeType: 'application/json',
    },
    async (uri) => ({
      contents: [{ uri: uri.href, text: JSON.stringify([...cases.values()], null, 2) }],
    }),
  ),
];

/**
 * The record the downstream API cannot write. TestRail sees one service
 * account; this says which person was behind the call, and which case.
 */
function logDecision(event: AuditEvent): void {
  console.log(JSON.stringify(event));
}

export const buildExampleServer = server(tools, {
  name: 'mcp-authz-node-example',
  version: '0.1.0',
  onAudit: logDecision,
});
