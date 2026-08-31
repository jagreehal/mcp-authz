import { classifyInboundRequest, type InboundClassificationOutcome } from '@modelcontextprotocol/server';
import { decodeMcpNameHeader } from './scopes';

export type TrustedMcpRoute = {
  kind: 'modern';
  body: unknown;
  outcome: Extract<InboundClassificationOutcome, { kind: 'modern' }>;
  method: string;
  name?: string;
};

export type UntrustedMcpRoute = {
  kind: 'legacy';
  body: unknown;
  outcome: Extract<InboundClassificationOutcome, { kind: 'legacy' }>;
};

export type RejectedMcpRoute = {
  kind: 'reject';
  httpStatus: number;
  code: number;
  message: string;
  data?: unknown;
  id: string | number | null;
};

export type ScopedRoute = TrustedMcpRoute | UntrustedMcpRoute | RejectedMcpRoute;

const NAME_SOURCE = {
  'tools/call': 'name',
  'prompts/get': 'name',
  'resources/read': 'uri',
} as const;

/**
 * Parse and validate every routing input before it can influence OAuth scopes.
 * This mirrors the SDK's standard-header rung, including Base64 sentinel
 * decoding, but runs before bearer authorization rather than during dispatch.
 */
export function classifyScopedRequest(request: Request, body: unknown): ScopedRoute {
  if (request.method.toUpperCase() !== 'POST') {
    return {
      kind: 'legacy',
      body: undefined,
      outcome: { kind: 'legacy', reason: 'http-method' },
    };
  }

  const outcome = classifyInboundRequest({
    httpMethod: request.method,
    ...header(request, 'mcp-protocol-version', 'protocolVersionHeader'),
    ...header(request, 'mcp-method', 'mcpMethodHeader'),
    ...header(request, 'mcp-name', 'mcpNameHeader'),
    body,
  });

  if (outcome.kind === 'reject') {
    return rejected(outcome.httpStatus, outcome.code, outcome.message, outcome.data, requestId(body));
  }
  if (outcome.kind === 'legacy') return { kind: 'legacy', body, outcome };

  const method = outcome.message.method;
  if (outcome.messageKind !== 'request') return { kind: 'modern', body, outcome, method };

  const methodHeader = request.headers.get('mcp-method');
  if (methodHeader === null) {
    return mismatch(
      '(missing)',
      `the body names method ${method} but the required Mcp-Method header is absent`,
      body,
    );
  }

  const source = Object.hasOwn(NAME_SOURCE, method)
    ? NAME_SOURCE[method as keyof typeof NAME_SOURCE]
    : undefined;
  if (source === undefined) return { kind: 'modern', body, outcome, method };

  const params = isRecord(outcome.message.params) ? outcome.message.params : undefined;
  const bodyName = typeof params?.[source] === 'string' ? params[source] : undefined;
  const rawName = request.headers.get('mcp-name');
  if (rawName === null) {
    if (bodyName === undefined) return { kind: 'modern', body, outcome, method };
    return mismatch(
      '(missing)',
      `the body carries params.${source}="${bodyName}" but the required Mcp-Name header is absent`,
      body,
    );
  }

  const decodedName = decodeMcpNameHeader(rawName);
  if (decodedName === undefined) {
    return mismatch(rawName.trim(), 'the Mcp-Name header carries an invalid Base64 sentinel value', body);
  }
  if (bodyName !== undefined && decodedName !== bodyName) {
    return mismatch(
      rawName.trim(),
      `the body carries params.${source}="${bodyName}" but the Mcp-Name header names "${decodedName}"`,
      body,
    );
  }

  return {
    kind: 'modern',
    body,
    outcome,
    method,
    ...(bodyName === undefined ? {} : { name: bodyName }),
  };
}

function header(
  request: Request,
  name: string,
  property: 'protocolVersionHeader' | 'mcpMethodHeader' | 'mcpNameHeader',
): Partial<Record<typeof property, string>> {
  const value = request.headers.get(name);
  return value === null ? {} : { [property]: value };
}

function mismatch(headerValue: string, bodyDescription: string, body: unknown): RejectedMcpRoute {
  return rejected(
    400,
    -32_020,
    `Bad Request: the request headers and body disagree: ${bodyDescription}`,
    { mismatch: { header: headerValue, body: bodyDescription } },
    requestId(body),
  );
}

function rejected(
  httpStatus: number,
  code: number,
  message: string,
  data: unknown,
  id: string | number | null,
): RejectedMcpRoute {
  return { kind: 'reject', httpStatus, code, message, ...(data === undefined ? {} : { data }), id };
}

function requestId(body: unknown): string | number | null {
  if (!isRecord(body)) return null;
  const id = body.id;
  return typeof id === 'string' || typeof id === 'number' ? id : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
