/**
 * The rungs both enforcement locations share: classify a request, price the
 * capability it names, then step up its scope.
 *
 * **Every rung here has to say which side's assumptions it encodes.** The two
 * callers are not symmetric, and where they differ is where the security bugs
 * live. `createMcpFetch` has the SDK downstream of it, so it can be lenient
 * with a request it cannot classify and let the SDK refuse it a second way.
 * `createMcpProxy` has nothing downstream that re-checks anything, and forwards
 * on a service credential that outranks the caller, so the same leniency hands
 * an upstream a call nobody priced. That difference is `strictClassification`,
 * and it was a header-smuggling hole before it was an option.
 *
 * The same shape has surfaced twice more: a resource is named by label in a
 * permission map and by URI on the wire, and a listing filter that cannot read
 * a response has to withhold it rather than pass it on. A shared rung that
 * silently picks one caller's default is the bug, not the sharing.
 */
import {
  bearerAuthChallengeResponse,
  isJsonContentType,
  OAuthError,
  OAuthErrorCode,
  type AuthInfo,
} from '@modelcontextprotocol/server';
import { AccessDeniedError } from './identity';
import type { Principal } from './policy';
import { emitDecision, policyDenied, principalLabel, type AuthorizationDecisionSink } from './decision';
import { classifyScopedRequest, routeFromBody, type TrustedMcpRoute } from './routing';
import { scopesForCapability, type CapabilityScopeMap } from './scopes';
import { readCappedBody } from './upstream';

export type ScopedPreflight = {
  body: unknown;
  route: TrustedMcpRoute;
  /**
   * Whether the 2026 routing headers were present and agreed with the body.
   *
   * False means the route was read from the body alone. That is enough to price
   * a capability, because the body is what the server will act on, but not
   * enough to choose a scope: a scope decision has to be defensible against a
   * caller who chose the headers, so it demands the cross-checked form.
   */
  headersValidated: boolean;
};

export type ScopedGateResult = { ok: true; preflight?: ScopedPreflight } | { ok: false; response: Response };

/** Bare name for a tool, `prompt:`/`resource:` prefixed for the rest — same as `gate()`. */
export function capabilityLabel(kind: 'tool' | 'prompt' | 'resource', name: string): string {
  return kind === 'tool' ? name : `${kind}:${name}`;
}

export function permissionForRoute(
  resolver: ((kind: 'tool' | 'prompt' | 'resource', name: string) => string | undefined) | undefined,
  permissions: ReadonlyMap<string, string> | undefined,
  route: TrustedMcpRoute,
): string | undefined {
  if (!route.name || (!resolver && !permissions)) return undefined;
  const kind =
    route.method === 'tools/call'
      ? 'tool'
      : route.method === 'prompts/get'
        ? 'prompt'
        : route.method === 'resources/read'
          ? 'resource'
          : undefined;
  return kind ? (resolver?.(kind, route.name) ?? permissions?.get(`${kind}:${route.name}`)) : undefined;
}

/**
 * A resource is named by URI on the wire and by label in a permission map, so
 * the two cannot be looked up in the same table. Each entry knows the URIs its
 * label covers, whether that is one address or a template's worth.
 */
export type ResourceIndex = readonly {
  label: string;
  permission: string;
  matches: (uri: string) => boolean;
}[];

/**
 * Resolve a permission from a flat map whose tool keys are bare names.
 *
 * `tools/call` and `prompts/get` carry the capability's name, which is what the
 * map is keyed by. `resources/read` carries a URI instead — `cases://case/C1`,
 * never `case` — so it is answered from the resource index rather than by
 * looking up a name the request never sent.
 */
export function permissionForFlatMap(
  permissions: ReadonlyMap<string, string>,
  route: TrustedMcpRoute,
  resources: ResourceIndex = [],
  can: (permission: string) => boolean = () => true,
): string | undefined {
  if (!route.name) return undefined;
  if (route.method === 'tools/call') {
    return permissions.get(route.name) ?? permissions.get(`tool:${route.name}`);
  }
  if (route.method === 'prompts/get') return permissions.get(`prompt:${route.name}`);
  if (route.method !== 'resources/read') return undefined;

  // Patterns can overlap, and which registration an upstream routes a URI to is
  // its business, not something to guess from the order of a permission map. So
  // every pattern that covers this URI has to be satisfied: report the first
  // one the caller fails, and only then the first one at all.
  const matches = resources.filter((entry) => entry.matches(route.name!));
  if (matches.length === 0) return undefined;
  return (matches.find((entry) => !can(entry.permission)) ?? matches[0])?.permission;
}

export async function runScopedGate<P extends string>(options: {
  request: Request;
  auth: AuthInfo;
  /** Absent in resolver mode, where the resolver decides access for itself. */
  principal: Principal<P> | undefined;
  maxRequestBytes: number;
  requiredScopes: string[];
  scoped: boolean;
  routed: boolean;
  /**
   * Whether a request this cannot classify is refused here.
   *
   * `createMcpFetch` passes `false`: the SDK sits downstream and stays the
   * authority on a malformed or legacy request, which it would otherwise refuse
   * a second way, with a different error. A proxy passes `true`, because
   * nothing downstream is trusted to check anything — a request whose routing
   * inputs cannot be validated cannot be authorized either, and forwarding it
   * on a service credential would hand the upstream a call this never priced.
   */
  strictClassification?: boolean;
  scopeMap?: CapabilityScopeMap;
  /**
   * The capability scopes a route demands, when a plain key lookup cannot find
   * them.
   *
   * A `resources/read` carries one concrete URI; a scope map is keyed by the
   * resource as registered, which may be a template or a label. Comparing the
   * two as strings is a step-up that silently never fires, so the caller that
   * knows the registrations resolves it — and where several registrations cover
   * one URI, it returns what all of them ask for.
   */
  resolveCapabilityScopes?: (route: TrustedMcpRoute) => string[] | undefined;
  scopesForRequest?: (request: Request, route: TrustedMcpRoute) => string[];
  resolvePermission: (route: TrustedMcpRoute) => string | undefined;
  onDecision?: AuthorizationDecisionSink;
  /** Names this deployment on the decisions this rung emits. */
  emitter?: string;
  resourceMetadataUrl: string;
}): Promise<ScopedGateResult> {
  const {
    request,
    auth,
    principal,
    maxRequestBytes,
    requiredScopes,
    scoped,
    routed,
    strictClassification = false,
    scopeMap,
    resolveCapabilityScopes,
    scopesForRequest,
    resolvePermission,
    onDecision,
    emitter,
    resourceMetadataUrl,
  } = options;

  // One classification serves both remaining checks, because both are about a
  // named capability. Its routing inputs go through the 2026 body-header
  // validation ladder, so a dishonest `Mcp-Name` or `Mcp-Method` can neither
  // talk its way into a cheaper scope nor into another capability's permission.
  //
  // Only a POST carries a body to check the headers against. Anything else is
  // held to the baseline rather than to what its unvalidated headers claim.
  const classified =
    (scoped || routed) && request.method.toUpperCase() === 'POST'
      ? await preflightScopedRequest(request, maxRequestBytes)
      : undefined;
  if (classified instanceof Response && (scoped || strictClassification)) {
    return { ok: false, response: classified };
  }
  const preflight = classified instanceof Response ? undefined : classified;

  // A scope is chosen from the capability's name, so it may only be chosen from
  // a name the headers and the body agree on. Pricing a permission has no such
  // requirement: it reads the body, which is what the server will act on.
  if (scoped && preflight && !preflight.headersValidated) {
    return {
      ok: false,
      response: protocolError(
        400,
        -32_020,
        'Per-capability scopes require a 2026-07-28 request with matching MCP routing headers.',
        undefined,
        requestId(preflight.body),
      ),
    };
  }

  // No principal means resolver mode, where the caller resolves its own context
  // and `authz()` enforces at registration instead. There is nothing to ask
  // here, so this rung is skipped rather than crashed through.
  const routePermission = preflight ? resolvePermission(preflight.route) : undefined;
  if (routePermission && principal && !principal.can(routePermission as P)) {
    await emitDecision(onDecision, principal, 'deny', 'policy_denied', emitter);
    return {
      ok: false,
      response: policyDenied(
        AccessDeniedError.notPermitted(principalLabel(principal), `the permission '${routePermission}'`),
      ),
    };
  }

  // Permission before scope, so an unpermitted caller is never prompted through
  // a step-up for an action the policy will refuse anyway.
  const scopes =
    preflight && scoped
      ? scopeMap
        ? [
            ...new Set([
              ...requiredScopes,
              ...(resolveCapabilityScopes?.(preflight.route) ??
                scopesForCapability(
                  preflight.route.method,
                  preflight.route.name,
                  scopeMap,
                  requiredScopes[0] ?? 'mcp',
                )),
            ]),
          ]
        : scopesForRequest!(request, preflight.route)
      : requiredScopes;

  const missingScopes = scopes.filter((scope) => !auth.scopes.includes(scope));
  if (missingScopes.length > 0) {
    return {
      ok: false,
      response: bearerAuthChallengeResponse(
        new OAuthError(OAuthErrorCode.InsufficientScope, 'Insufficient scope'),
        { requiredScopes: scopes, resourceMetadataUrl },
      ),
    };
  }

  return { ok: true, ...(preflight ? { preflight } : {}) };
}

export async function preflightScopedRequest(
  request: Request,
  maxBytes: number,
): Promise<ScopedPreflight | Response> {
  // The capability is named in the body, not trustworthily in a header, so
  // deciding either its scope or its permission means reading it. The bearer
  // gate has already run by the time this does, so the cap bounds an
  // authenticated caller rather than anyone who can reach the port.
  if (!isJsonContentType(request.headers.get('content-type'))) {
    return protocolError(415, -32_000, 'Per-capability scopes require an application/json body.');
  }

  const raw = await readCapped(request, maxBytes);
  if (raw === undefined) {
    return protocolError(413, -32_000, `Request body exceeds the ${maxBytes} byte limit.`);
  }

  let body: unknown;
  try {
    body = JSON.parse(raw);
  } catch {
    return protocolError(400, -32_700, 'Parse error: the request body is not valid JSON');
  }

  const route = classifyScopedRequest(request, body);
  // A rejection means the headers and the body disagree. That is never a
  // request to reason about further — one of the two is lying about what it
  // does, and neither answer can be trusted over the other.
  if (route.kind === 'reject') {
    return protocolError(route.httpStatus, route.code, route.message, route.data, route.id);
  }
  if (route.kind !== 'modern') {
    const derived = routeFromBody(body);
    return derived === undefined
      ? protocolError(
          400,
          -32_600,
          'Invalid Request: no JSON-RPC method to route on.',
          undefined,
          requestId(body),
        )
      : { body, route: derived, headersValidated: false };
  }
  return { body, route, headersValidated: true };
}

function requestId(body: unknown): string | number | null {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return null;
  const id = (body as { id?: unknown }).id;
  return typeof id === 'string' || typeof id === 'number' ? id : null;
}

function protocolError(
  status: number,
  code: number,
  message: string,
  data?: unknown,
  id: string | number | null = null,
): Response {
  return Response.json(
    { jsonrpc: '2.0', error: { code, message, ...(data === undefined ? {} : { data }) }, id },
    { status },
  );
}

/**
 * The request body as text, or `undefined` when it is over the cap.
 *
 * A declared `Content-Length` over the limit is refused without reading
 * anything; the stream itself is then held to the same limit, because the
 * header is the caller's claim rather than a measurement.
 */
async function readCapped(request: Request, maxBytes: number): Promise<string | undefined> {
  const declared = Number(request.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) return undefined;
  return readCappedBody(request.clone().body, maxBytes);
}

export {
  emitDecision,
  policyDenied,
  principalLabel,
  type AuthorizationDecisionEvent,
  type AuthorizationDecisionSink,
} from './decision';
