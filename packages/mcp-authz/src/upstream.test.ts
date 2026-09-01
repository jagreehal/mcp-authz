import { describe, expect, it } from 'vitest';
import { forwardToUpstream, isEventStream, isJsonResponse } from './upstream';

describe('upstream response helpers', () => {
  it('detects JSON and event-stream content types', () => {
    expect(isJsonResponse(new Response('', { headers: { 'Content-Type': 'application/json' } }))).toBe(true);
    expect(isEventStream(new Response('', { headers: { 'Content-Type': 'text/event-stream' } }))).toBe(true);
    expect(isJsonResponse(new Response('', { headers: { 'Content-Type': 'text/plain' } }))).toBe(false);
  });
});

describe('forwardToUpstream', () => {
  it('drops the hop-by-hop headers the Connection header names, not only the fixed list', async () => {
    let seen: Headers | undefined;
    await forwardToUpstream(
      new Request('https://proxy.example/mcp', {
        method: 'POST',
        headers: {
          Connection: 'X-Hop-Token, Keep-Alive',
          'X-Hop-Token': 'internal-only',
          'X-Keep': 'passes through',
        },
        body: '{}',
      }),
      {
        url: 'https://upstream.example/mcp',
        bearer: 'svc',
        fetch: (async (input: string | URL | Request) => {
          seen = (input as Request).headers;
          return new Response('{}');
        }) as typeof fetch,
      },
    );

    expect(seen?.get('x-hop-token')).toBeNull();
    expect(seen?.get('connection')).toBeNull();
    expect(seen?.get('x-keep')).toBe('passes through');
    expect(seen?.get('authorization')).toBe('Bearer svc');
  });
});
