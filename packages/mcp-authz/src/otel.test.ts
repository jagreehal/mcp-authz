import { trace, type Span } from '@opentelemetry/api';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createIdentifierHasher, createOtelAuditSink, createOtelDecisionSink } from './otel.js';
import type { AuditEvent } from './tools.js';
import type { AuthorizationDecisionEvent } from './decision.js';

function mockSpan() {
  const attributes: Record<string, unknown> = {};
  const span = {
    setAttribute(key: string, value: unknown) {
      attributes[key] = value;
      return span as Span;
    },
    setAttributes(attrs: Record<string, unknown>) {
      Object.assign(attributes, attrs);
      return span as Span;
    },
    isRecording: () => true,
  } as unknown as Span;
  return { span, attributes };
}

describe('mcp-authz/otel', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('createIdentifierHasher matches the digest the Python package produces', async () => {
    const hash = createIdentifierHasher('test-key');
    expect(await hash('alice@acme.com')).toBe('6161c1d257155902ecdc1d474288baa8');
    expect(await createIdentifierHasher('other-key')('alice@acme.com')).not.toBe(
      '6161c1d257155902ecdc1d474288baa8',
    );
  });

  it('leaves identifiers off the span without a hashKey', async () => {
    const { span, attributes } = mockSpan();
    vi.spyOn(trace, 'getActiveSpan').mockReturnValue(span);

    await createOtelDecisionSink()({
      type: 'mcp_authz.decision.v1',
      issuer: 'https://auth.example',
      sub: 'user-2',
      email: 'alice@acme.com',
      decision: 'allow',
      roles: [],
      permissions: [],
      at: new Date().toISOString(),
    });

    expect(attributes['mcp_authz.decision']).toBe('allow');
    expect(attributes).not.toHaveProperty('mcp_authz.sub.hash');
    expect(attributes).not.toHaveProperty('mcp_authz.email.hash');
    expect(attributes).not.toHaveProperty('enduser.id');
  });

  it('createOtelAuditSink writes mcp_authz.audit attributes and force-keep', async () => {
    const { span, attributes } = mockSpan();
    vi.spyOn(trace, 'getActiveSpan').mockReturnValue(span);

    const event: AuditEvent = {
      type: 'mcp_authz.audit.v1',
      callId: 'c1',
      issuer: 'https://auth.example',
      sub: 'user-1',
      email: 'alice@acme.com',
      kind: 'tool',
      name: 'get_case',
      permission: 'cases:read',
      decision: 'allow',
      phase: 'success',
      at: new Date().toISOString(),
      resource: 'case:C1234',
    };

    await createOtelAuditSink({ hashKey: 'test-key' })(event);

    expect(attributes['mcp_authz.audit.phase']).toBe('success');
    expect(attributes['mcp_authz.audit.name']).toBe('get_case');
    expect(attributes['mcp_authz.audit.resource']).toBe('case:C1234');
    expect(attributes['mcp_authz.email.hash']).toBe('6161c1d257155902ecdc1d474288baa8');
    expect(attributes['autotel.sampling.tail.keep']).toBe(true);
    expect(attributes['security.category']).toBe('authorization');
  });

  it('createOtelDecisionSink records deny with reason', async () => {
    const { span, attributes } = mockSpan();
    vi.spyOn(trace, 'getActiveSpan').mockReturnValue(span);

    const event: AuthorizationDecisionEvent = {
      type: 'mcp_authz.decision.v1',
      issuer: 'https://auth.example',
      sub: 'user-2',
      decision: 'deny',
      roles: [],
      permissions: [],
      reason: 'policy_denied',
      at: new Date().toISOString(),
    };

    await createOtelDecisionSink()(event);

    expect(attributes['mcp_authz.decision']).toBe('deny');
    expect(attributes['mcp_authz.decision.reason']).toBe('policy_denied');
    expect(attributes['security.outcome']).toBe('failure');
  });

  it('is a no-op without an active span', async () => {
    vi.spyOn(trace, 'getActiveSpan').mockReturnValue(undefined);
    await expect(
      createOtelAuditSink({ hashKey: 'test-key' })({
        type: 'mcp_authz.audit.v1',
        callId: 'c2',
        issuer: 'https://auth.example',
        sub: 'user-1',
        kind: 'tool',
        name: 'get_case',
        permission: 'cases:read',
        decision: 'allow',
        phase: 'attempt',
        at: new Date().toISOString(),
      }),
    ).resolves.toBeUndefined();
  });

  it('keeps error text off the span unless captureErrors is set', async () => {
    const event: AuditEvent = {
      type: 'mcp_authz.audit.v1',
      callId: 'c3',
      issuer: 'https://auth.example',
      sub: 'user-1',
      kind: 'tool',
      name: 'get_case',
      permission: 'cases:read',
      decision: 'allow',
      phase: 'failure',
      at: new Date().toISOString(),
      error: 'row for alice@acme.com not found',
    };
    const quiet = mockSpan();
    vi.spyOn(trace, 'getActiveSpan').mockReturnValue(quiet.span);
    await createOtelAuditSink()(event);
    expect(quiet.attributes).not.toHaveProperty('mcp_authz.audit.error');
    expect(quiet.attributes['security.outcome']).toBe('failure');

    const verbose = mockSpan();
    vi.spyOn(trace, 'getActiveSpan').mockReturnValue(verbose.span);
    await createOtelAuditSink({ captureErrors: true })(event);
    expect(verbose.attributes['mcp_authz.audit.error']).toBe('row for alice@acme.com not found');
  });
});
