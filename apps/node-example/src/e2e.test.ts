import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { devAuthEnv, mintToken, withDevAuth } from './dev-auth';
import { mcpFromEnv } from './mcp';

/**
 * The demo, asserted. Everything `pnpm dev` shows a person in the MCP Inspector
 * is checked here against the same code path, so the README cannot quietly stop
 * being true.
 */

const PORT = 8200;
const env = devAuthEnv(PORT);
const server = withDevAuth(mcpFromEnv(env), PORT);

let restoreFetch: (() => void) | undefined;

beforeAll(() => {
  // The connector fetches its own JWKS over HTTP. In `pnpm dev` that is a live
  // localhost route; here it is the same route, called directly.
  const real = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input instanceof Request ? input.url : input);
    if (url.startsWith(`http://localhost:${PORT}/`)) return server(new Request(url, init));
    return real(input as never, init);
  }) as typeof fetch;
  restoreFetch = () => {
    globalThis.fetch = real;
  };
});

afterEach(() => {
  vi.restoreAllMocks();
});

afterAll(() => {
  restoreFetch?.();
});

const META = {
  'io.modelcontextprotocol/protocolVersion': '2026-07-28',
  'io.modelcontextprotocol/clientInfo': { name: 'mcp-authz-test', version: '1.0.0' },
  'io.modelcontextprotocol/clientCapabilities': {},
};

const rpc = async (
  token: string,
  body: { method?: string; params?: Record<string, unknown> },
  headers: Record<string, string> = {},
  modern = true,
) => {
  const params = modern ? { ...(body.params ?? {}), _meta: META } : body.params;
  const name =
    typeof params?.name === 'string' ? params.name : typeof params?.uri === 'string' ? params.uri : undefined;
  const response = await server(
    new Request(env.MCP_PUBLIC_URL!, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        Authorization: `Bearer ${token}`,
        ...(modern
          ? {
              'MCP-Protocol-Version': '2026-07-28',
              ...(body.method ? { 'Mcp-Method': body.method } : {}),
              ...(name ? { 'Mcp-Name': name } : {}),
            }
          : {}),
        ...headers,
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, ...body, ...(params ? { params } : {}) }),
    }),
  );
  const text = await response.text();
  // Streamable HTTP may answer as SSE; the payload is the same either way.
  const json = text.includes('data: ') ? text.slice(text.indexOf('data: ') + 6).split('\n')[0]! : text;
  return { status: response.status, headers: response.headers, body: json ? JSON.parse(json) : undefined };
};

const toolNames = async (token: string): Promise<string[]> => {
  const { body } = await rpc(token, { method: 'tools/list', params: {} }, { 'Mcp-Method': 'tools/list' });
  return (body?.result?.tools ?? []).map((tool: { name: string }) => tool.name).sort();
};

describe('The demo, end to end', () => {
  it('shows a reader and an editor different tools', async () => {
    const reader = await mintToken({ email: 'dana@acme.com', port: PORT });
    const editor = await mintToken({ email: 'alice@acme.com', port: PORT });

    // Dana matches only the domain rule, so she never sees the write tool —
    // it is not registered for her request, not hidden after the fact.
    expect(await toolNames(reader)).toEqual(['get_case', 'whoami']);
    expect(await toolNames(editor)).toEqual(['get_case', 'update_case', 'whoami']);
  });

  it('promotes someone by an IdP group claim, with no policy edit', async () => {
    const lead = await mintToken({
      email: 'priya@acme.com',
      port: PORT,
      claims: { 'https://acme.com/groups': ['qa-leads'] },
    });
    expect(await toolNames(lead)).toContain('update_case');
  });

  it('refuses an outsider with an actionable 403 rather than a 500', async () => {
    const outsider = await mintToken({ email: 'sam@other.com', port: PORT });
    const { status, body } = await rpc(outsider, { method: 'tools/list', params: {} });

    expect(status).toBe(403);
    expect(body.error).toBe('forbidden');
    expect(body.reason).toBe('policy_denied');
    expect(body.error_description).toContain('sam@other.com');
  });

  it('refuses a token minted for a different resource', async () => {
    const reader = await mintToken({ email: 'dana@acme.com', port: PORT });
    const elsewhere = reader.slice(0, -4) + 'AAAA';
    const { status } = await rpc(elsewhere, { method: 'tools/list', params: {} });
    expect(status).toBe(401);
  });

  it('challenges for a scope the token lacks instead of failing the tool', async () => {
    const editor = await mintToken({ email: 'alice@acme.com', port: PORT, scope: 'mcp' });
    expect(await toolNames(editor)).toContain('update_case');
    const response = await server(
      new Request(env.MCP_PUBLIC_URL!, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
          Authorization: `Bearer ${editor}`,
          'MCP-Protocol-Version': '2026-07-28',
          'Mcp-Method': 'tools/call',
          'Mcp-Name': 'update_case',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { _meta: META, name: 'update_case', arguments: {} },
        }),
      }),
    );

    // The other axis: a scope gap is something the client can re-authorise for,
    // which a tool returning isError could never tell it.
    expect(response.status).toBe(403);
    expect(response.headers.get('WWW-Authenticate')).toMatch(/insufficient_scope/);
    expect(response.headers.get('WWW-Authenticate')).toMatch(/scope="mcp write"/);
  });

  it('refuses policy before suggesting a futile scope upgrade', async () => {
    const reader = await mintToken({ email: 'dana@acme.com', port: PORT, scope: 'mcp' });
    const response = await rpc(reader, {
      method: 'tools/call',
      params: { name: 'update_case', arguments: { id: 'C1234', title: 'Must not run' } },
    });

    expect(response.status).toBe(403);
    expect(response.body).toMatchObject({ error: 'forbidden', reason: 'policy_denied' });
    expect(response.headers.has('WWW-Authenticate')).toBe(false);
  });

  it.each([
    ['missing', {}],
    ['dishonest', { 'Mcp-Method': 'tools/call', 'Mcp-Name': 'get_case' }],
  ])('never lets %s routing headers downgrade a write scope', async (_label, headers) => {
    const editor = await mintToken({ email: 'alice@acme.com', port: PORT, scope: 'mcp' });
    const { status, body } = await rpc(
      editor,
      {
        method: 'tools/call',
        params: { name: 'update_case', arguments: { id: 'C1234', title: 'Must not run' } },
      },
      headers,
      false,
    );

    expect(status).toBe(400);
    expect(body.error.code).toBe(-32020);
  });

  it('decodes a Base64 Mcp-Name before choosing the scope', async () => {
    const editor = await mintToken({ email: 'alice@acme.com', port: PORT, scope: 'mcp' });
    const { status } = await rpc(
      editor,
      {
        method: 'tools/call',
        params: { name: 'update_case', arguments: { id: 'C1234', title: 'Must not run' } },
      },
      { 'Mcp-Method': 'tools/call', 'Mcp-Name': '=?base64?dXBkYXRlX2Nhc2U=?=' },
    );

    expect(status).toBe(403);
  });

  it('audits the person and the case, not just the tool name', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const editor = await mintToken({ email: 'alice@acme.com', port: PORT });

    await rpc(
      editor,
      { method: 'tools/call', params: { name: 'update_case', arguments: { id: 'C1234', title: 'Renamed' } } },
      { 'Mcp-Method': 'tools/call', 'Mcp-Name': 'update_case' },
    );

    const events = log.mock.calls.map(([line]) => JSON.parse(String(line)));
    expect(events).toContainEqual(
      expect.objectContaining({
        email: 'alice@acme.com',
        kind: 'tool',
        name: 'update_case',
        permission: 'cases:write',
        resource: 'case:C1234',
        decision: 'allow',
        phase: 'success',
      }),
    );
  });

  it('gates prompts and resources, not tools alone', async () => {
    const reader = await mintToken({ email: 'dana@acme.com', port: PORT });
    const editor = await mintToken({ email: 'alice@acme.com', port: PORT });

    const promptNames = async (token: string) => {
      const { body } = await rpc(token, { method: 'prompts/list', params: {} });
      return (body?.result?.prompts ?? []).map((prompt: { name: string }) => prompt.name);
    };
    const resourceUris = async (token: string) => {
      const { body } = await rpc(token, { method: 'resources/list', params: {} });
      return (body?.result?.resources ?? []).map((entry: { uri: string }) => entry.uri);
    };

    // triage_case composes the rename, so it costs what the rename costs.
    expect(await promptNames(reader)).toEqual([]);
    expect(await promptNames(editor)).toEqual(['triage_case']);

    // Both may read, so both see the resource. It is gated, not ungoverned.
    expect(await resourceUris(reader)).toEqual(['cases://all']);
    expect(await resourceUris(editor)).toEqual(['cases://all']);

    // The list is a convenience, not the boundary. Dana asking for the prompt
    // by name, without listing anything, still cannot reach it.
    const direct = await rpc(reader, {
      method: 'prompts/get',
      params: { name: 'triage_case', arguments: { id: 'C1234' } },
    });
    expect(direct.body.result).toBeUndefined();
    expect(direct.status).toBe(403);
    expect(direct.body).toMatchObject({ error: 'forbidden', reason: 'policy_denied' });
    expect(direct.headers.has('WWW-Authenticate')).toBe(false);
  });
});
