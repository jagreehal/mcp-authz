/**
 * OpenTelemetry sinks for mcp-authz. Depends on `@opentelemetry/api` only, so it
 * runs on Node and Workers. You initialise the SDK yourself.
 */
import { context, propagation, trace, type Attributes, type Span } from '@opentelemetry/api';
import type { AuditSink } from './tools.js';
import type { AuthorizationDecisionSink } from './decision.js';

/** Autotel tail-sampling attributes that keep authz spans through sampling. */
const TAIL_KEEP = 'autotel.sampling.tail.keep';
const TAIL_EVALUATED = 'autotel.sampling.tail.evaluated';

export type OtelSinkOptions = {
  /** Keep the active span through autotel tail sampling. Default true. */
  forceKeep?: boolean;
  /**
   * Secret for HMAC-SHA-256 digests of `sub`, `email` and `approvedBy`. Without
   * it the sinks leave those identifiers off the span.
   */
  hashKey?: string;
  /**
   * Copy the handler's error message (first 500 characters) onto the span.
   * Default false: `security.outcome` still marks the failure.
   */
  captureErrors?: boolean;
};

type Hasher = (value: string) => Promise<string>;

function forceKeepSpan(span: Span): void {
  span.setAttribute(TAIL_EVALUATED, true);
  span.setAttribute(TAIL_KEEP, true);
  span.setAttribute('security.force_keep', true);
}

/**
 * Returns a keyed digest function: HMAC-SHA-256 over UTF-8, first 32 hex
 * characters. WebCrypto runs it on Node and Workers, and the Python package
 * produces the same digest for the same key.
 */
export function createIdentifierHasher(hashKey: string): Hasher {
  const encoder = new TextEncoder();
  const key = crypto.subtle.importKey(
    'raw',
    encoder.encode(hashKey),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return async (value) => {
    const signature = await crypto.subtle.sign('HMAC', await key, encoder.encode(value));
    return Array.from(new Uint8Array(signature), (byte) => byte.toString(16).padStart(2, '0'))
      .join('')
      .slice(0, 32);
  };
}

async function actorAttrs(
  event: { issuer: string; sub: string; email?: string; domain?: string; emitter?: string },
  hash: Hasher | undefined,
): Promise<Attributes> {
  const attrs: Attributes = { 'mcp_authz.issuer': event.issuer };
  if (hash) {
    const sub = await hash(event.sub);
    attrs['mcp_authz.sub.hash'] = sub;
    attrs['enduser.id'] = sub;
    if (event.email) attrs['mcp_authz.email.hash'] = await hash(event.email);
  }
  if (event.domain) attrs['mcp_authz.domain'] = event.domain;
  if (event.emitter) attrs['mcp_authz.emitter'] = event.emitter;
  return attrs;
}

/** Writes `mcp_authz.audit.v1` onto the active span, if there is one. */
export function createOtelAuditSink(options?: OtelSinkOptions): AuditSink {
  const hash = options?.hashKey ? createIdentifierHasher(options.hashKey) : undefined;
  return async (event) => {
    const span = trace.getActiveSpan();
    if (!span) return;

    const attrs: Attributes = {
      ...(await actorAttrs(event, hash)),
      'mcp_authz.event': event.type,
      'mcp_authz.audit.call_id': event.callId,
      'mcp_authz.audit.kind': event.kind,
      'mcp_authz.audit.name': event.name,
      'mcp_authz.audit.permission': event.permission,
      'mcp_authz.audit.phase': event.phase,
      'mcp_authz.audit.decision': event.decision,
      'security.event': `mcp_authz.audit.${event.phase}`,
      'security.category': 'authorization',
      'security.outcome':
        event.decision === 'deny' || event.phase === 'failure' || event.phase === 'refused'
          ? 'failure'
          : 'success',
    };
    if (event.resource) attrs['mcp_authz.audit.resource'] = event.resource;
    if (event.approvedBy && hash) attrs['mcp_authz.audit.approved_by.hash'] = await hash(event.approvedBy);
    if (event.durationMs !== undefined) attrs['mcp_authz.audit.duration_ms'] = event.durationMs;
    if (event.error && options?.captureErrors) attrs['mcp_authz.audit.error'] = event.error.slice(0, 500);

    span.setAttributes(attrs);
    if (options?.forceKeep !== false) forceKeepSpan(span);
  };
}

/** Writes `mcp_authz.decision.v1` onto the active span, if there is one. */
export function createOtelDecisionSink(options?: OtelSinkOptions): AuthorizationDecisionSink {
  const hash = options?.hashKey ? createIdentifierHasher(options.hashKey) : undefined;
  return async (event) => {
    const span = trace.getActiveSpan();
    if (!span) return;

    const attrs: Attributes = {
      ...(await actorAttrs(event, hash)),
      'mcp_authz.event': event.type,
      'mcp_authz.decision': event.decision,
      'mcp_authz.roles': event.roles.join(','),
      'mcp_authz.permissions': event.permissions.join(','),
      'security.event': 'mcp_authz.access.decision',
      'security.category': 'authorization',
      'security.outcome': event.decision === 'allow' ? 'success' : 'failure',
      'security.severity': event.decision === 'allow' ? 'info' : 'warning',
    };
    if (event.reason) attrs['mcp_authz.decision.reason'] = event.reason;

    span.setAttributes(attrs);
    if (options?.forceKeep !== false) forceKeepSpan(span);
  };
}

/** Both sinks for `onAudit` (server) and `onDecision` (fetch/proxy). */
export function createOtelAuthzSinks(options?: OtelSinkOptions): {
  onAudit: AuditSink;
  onDecision: AuthorizationDecisionSink;
} {
  return {
    onAudit: createOtelAuditSink(options),
    onDecision: createOtelDecisionSink(options),
  };
}

/** A `fetch` that injects W3C trace context. Pass it as `upstream.fetch` to `createMcpProxy`. */
export function createTracedFetch(baseFetch: typeof fetch = fetch): typeof fetch {
  return (input: Request | string | URL, init?: RequestInit): Promise<Response> => {
    const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
    propagation.inject(context.active(), headers, {
      set(carrier, key, value) {
        carrier.set(key, value);
      },
    });
    return baseFetch(input, { ...init, headers });
  };
}
