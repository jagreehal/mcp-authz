import { AccessDeniedError } from './identity';
import type { Principal } from './policy';

/**
 * The access decision and how it is reported, with nothing protocol-shaped
 * attached.
 *
 * Its own module for the bundle rather than for tidiness: this rides in every
 * enforcement path, while the rest of the ladder is MCP route classification
 * and scope step-up. Left there, an OpenAPI deployment shipped the MCP wire
 * format it never calls.
 */

export type AuthorizationDecisionEvent = {
  /** See `AuditEvent['type']`: same contract, its own shape and version. */
  type: 'mcp_authz.decision.v1';
  issuer: string;
  sub: string;
  email?: string;
  /** See `AuditEvent['domain']`: the nearest thing to an organisation. */
  domain?: string;
  /** Which deployment emitted this, when you named it. */
  emitter?: string;
  decision: 'allow' | 'deny';
  roles: readonly string[];
  permissions: readonly string[];
  reason?: string;
  at: string;
};

export type AuthorizationDecisionSink = (event: AuthorizationDecisionEvent) => unknown | Promise<unknown>;

export function policyDenied(error: AccessDeniedError): Response {
  return Response.json(
    { error: 'forbidden', reason: 'policy_denied', error_description: error.message },
    { status: 403 },
  );
}

export async function emitDecision<P extends string>(
  sink: AuthorizationDecisionSink | undefined,
  principal: Principal<P> | undefined,
  decision: 'allow' | 'deny',
  reason?: string,
  emitter?: string,
): Promise<void> {
  if (!principal) return;
  await sink?.({
    type: 'mcp_authz.decision.v1',
    issuer: principal.issuer,
    sub: principal.sub,
    email: principal.email,
    domain: principal.domain,
    ...(emitter ? { emitter } : {}),
    decision,
    roles: principal.roles,
    permissions: principal.permissions,
    ...(reason ? { reason } : {}),
    at: new Date().toISOString(),
  });
}

export function principalLabel(principal: Pick<Principal, 'issuer' | 'sub' | 'email'>): string {
  return principal.email ?? `${principal.issuer}#${principal.sub}`;
}
