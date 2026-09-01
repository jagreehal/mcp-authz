export type UpstreamConfig = {
  /** Base MCP endpoint the proxy forwards to. */
  url: string | URL;
  bearer: string | (() => string | Promise<string>);
  fetch?: typeof fetch;
};

/**
 * Headers that must not survive a hop.
 *
 * `authorization` and `cookie` are the caller's credentials for *this* proxy;
 * forwarding either would hand a third-party upstream a token it was never the
 * audience for. The rest are hop-by-hop per RFC 9110 §7.6.1 — they describe the
 * connection that just ended, not the one about to be opened — plus `host`,
 * which the new URL decides.
 */
const DROPPED_ON_FORWARD = new Set([
  'authorization',
  'cookie',
  'host',
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

export async function forwardToUpstream(request: Request, config: UpstreamConfig): Promise<Response> {
  const fetchFn = config.fetch ?? fetch;
  const bearer = typeof config.bearer === 'function' ? await config.bearer() : config.bearer;
  const target = new URL(config.url);

  const dropped = new Set(DROPPED_ON_FORWARD);
  // RFC 9110 §7.6.1: `Connection` names further fields that belong to this hop
  // only. They are named at run time, so a fixed list cannot know them, and
  // forwarding one sends the previous hop's private state to the next.
  for (const named of request.headers.get('connection')?.split(',') ?? []) {
    const field = named.trim().toLowerCase();
    if (field) dropped.add(field);
  }

  const headers = new Headers();
  for (const [name, value] of request.headers) {
    if (!dropped.has(name.toLowerCase())) headers.set(name, value);
  }
  headers.set('authorization', `Bearer ${bearer}`);

  const upstreamRequest = new Request(target, {
    method: request.method,
    headers,
    body: request.body,
    // Streaming bodies need half-duplex on Node 18+ fetch.
    duplex: 'half',
  } as RequestInit);

  return fetchFn(upstreamRequest);
}

/**
 * The upstream's headers minus the framing that described a body we replaced.
 *
 * A filtered listing is shorter than what arrived, and `fetch` has already
 * decoded any `content-encoding`, so copying either header across would
 * describe the old body: a client would read a truncated response, or try to
 * gunzip plain JSON.
 */
export function headersForRewrittenBody(response: Response): Headers {
  const headers = new Headers(response.headers);
  headers.delete('content-length');
  headers.delete('content-encoding');
  return headers;
}

export function isEventStream(response: Response): boolean {
  const type = response.headers.get('content-type') ?? '';
  return type.includes('text/event-stream');
}

export function isJsonResponse(response: Response): boolean {
  const type = response.headers.get('content-type') ?? '';
  return type.includes('application/json') || type.includes('+json');
}

/**
 * A response body as text, or `undefined` when it is over the cap.
 *
 * Reads chunk by chunk and stops at the limit rather than buffering first and
 * measuring after, because measuring after is how an upstream decides how much
 * memory this process spends. Consumes the body rather than cloning it, so
 * there is no second buffered branch left behind holding the same bytes.
 */
export async function readCappedBody(
  body: ReadableStream<Uint8Array> | null,
  maxBytes: number,
): Promise<string | undefined> {
  if (!body) return '';
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        void reader.cancel().catch(() => {});
        return undefined;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const joined = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    joined.set(chunk, at);
    at += chunk.byteLength;
  }
  return new TextDecoder().decode(joined);
}
