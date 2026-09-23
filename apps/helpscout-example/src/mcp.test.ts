import { describe, expect, it } from 'vitest';
import { mcpFromEnv } from './mcp';

const env = {
  MCP_PUBLIC_URL: 'http://127.0.0.1:8400/mcp',
  MCP_BEARER: 'test-key',
  HELPSCOUT_DOCS_API_KEY: 'docs',
  HELPSCOUT_APP_ID: 'app',
  HELPSCOUT_APP_SECRET: 'secret',
};

const META = {
  'io.modelcontextprotocol/protocolVersion': '2026-07-28',
  'io.modelcontextprotocol/clientInfo': { name: 'test', version: '0' },
  'io.modelcontextprotocol/clientCapabilities': {},
};

async function list(fetch: ReturnType<typeof mcpFromEnv>, bearer?: string) {
  return fetch(
    new Request(env.MCP_PUBLIC_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        'MCP-Protocol-Version': '2026-07-28',
        'Mcp-Method': 'tools/list',
        ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}),
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: { _meta: META } }),
    }),
  );
}

describe('helpscout example', () => {
  it('refuses a missing or wrong bearer, lists every tool for the right one', async () => {
    const fetch = mcpFromEnv(env);

    expect((await list(fetch)).status).toBe(401);
    expect((await list(fetch, 'wrong')).status).toBe(401);

    const listed = await list(fetch, 'test-key');
    expect(listed.status).toBe(200);
    expect(await names(listed)).toEqual([
      'get_article',
      'get_conversation',
      'get_customer',
      'list_collections',
      'list_inboxes',
      'search_articles',
      'search_conversations',
    ]);
  });

  it('lists only Docs tools when the Mailbox credential is absent', async () => {
    const docsOnly = { ...env, HELPSCOUT_APP_ID: undefined, HELPSCOUT_APP_SECRET: undefined };
    expect(await names(await list(mcpFromEnv(docsOnly), 'test-key'))).toEqual([
      'get_article',
      'list_collections',
      'search_articles',
    ]);
  });
});

async function names(response: Response) {
  return [...(await response.text()).matchAll(/"name":"([a-z_]+)"/g)].map((m) => m[1]).sort();
}
