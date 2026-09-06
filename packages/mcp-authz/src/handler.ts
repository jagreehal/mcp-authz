import {
  createMcpHandler,
  getOAuthProtectedResourceMetadataUrl,
  oauthMetadataResponse,
  requireBearerAuth,
  type AuthInfo,
  type McpServer,
  type OAuthMetadata,
  type OAuthTokenVerifier,
} from '@modelcontextprotocol/server';
import { AccessDeniedError, type Identity } from './identity';
import {
  emitDecision,
  permissionForRoute,
  policyDenied,
  principalLabel,
  runScopedGate,
  type AuthorizationDecisionSink,
} from './ladder';
import { reconcile, type Policy, type Principal } from './policy';
import { type TrustedMcpRoute } from './routing';
import { scopesForCapability, type CapabilityScopeMap, type ToolScopeMap } from './scopes';
import { verifierFor, type VerifierOptions } from './verifier';

/** Where the resolved per-request context rides from the gate to the factory. */
const CONTEXT_KEY = 'mcp-authz.context';
const OAUTH_SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

export type { AuthorizationDecisionEvent, AuthorizationDecisionSink } from './ladder';

/**
 * An MCP Streamable HTTP resource server (2026-07-28) with
 * each person's own Google login in front of a per-request server factory.
 *
 * Three parties, and it matters which does what:
 *
 *   Claude          runs the OAuth flow and presents a bearer token
 *   your AS         registers Claude (CIMD preferred; DCR deprecated), logs
 *                   the human in with Google, and mints a token bound to
 *                   THIS server's URL
 *   this file       verifies that token, maps the identity to context, and
 *                   builds a server for that request
 *
 * We are a resource server and nothing more.
 */

export type McpFetchOptions<TContext, P extends string = string> = {
  /** This server's public URL, e.g. `https://mcp.acme.com/mcp`. */
  resourceServerUrl: URL;
  /** RFC 8414 metadata for the authorization server in front of us. */
  oauthMetadata: OAuthMetadata;
  /**
   * Token verification. The SDK verifies no tokens of its own, so this is the
   * security boundary, but every field has a sound default.
   *
   * `issuer` and `resource` come from `oauthMetadata.issuer` and
   * `resourceServerUrl`, which is what they have to be: a verifier trusting a
   * different issuer, or checking the audience against a URL this server does
   * not answer on, refuses every valid token and says only "invalid token".
   * `jwksUri` comes from `oauthMetadata.jwks_uri` when discovery supplied it,
   * so this whole block is optional.
   */
  verifier?: Partial<VerifierOptions>;
  /**
   * Bring any SDK-compatible verifier, including RFC 7662 introspection for
   * opaque tokens. Mutually exclusive with the built-in `verifier` options.
   */
  tokenVerifier?: OAuthTokenVerifier;
  /** Map a custom verifier's AuthInfo into the identity consumed by policy. */
  identityFromAuth?: (auth: AuthInfo) => Identity;
  /**
   * Baseline scopes every request must carry. Keep it to one small scope
   * (`mcp` by default); use `scopesForRequest` for per-tool step-up.
   */
  requiredScopes?: string[];
  /** All scopes advertised in protected-resource metadata. */
  supportedScopes?: string[];
  /** Declarative per-tool step-up. Mutually exclusive with `scopesForRequest`. */
  toolScopes?: ToolScopeMap;
  /** Tools, prompts and resource URIs mapped to scope requirements. */
  capabilityScopes?: CapabilityScopeMap;
  /**
   * Map a request to the scopes it needs. The second argument is the trusted,
   * body-validated and Base64-decoded MCP route; use it instead of reading raw
   * `Mcp-Method` / `Mcp-Name` values yourself. Returning more than the token
   * holds produces HTTP 403 with actionable `insufficient_scope` step-up.
   *
   * Omit to demand only `requiredScopes` on every call.
   */
  scopesForRequest?: (request: Request, route: TrustedMcpRoute) => string[];
  /**
   * Who may connect and what they may do. Supply this and the per-request
   * context is the `Principal`; a caller matching no rule is refused.
   *
   * Paired with a `toolServer`, the tools' permissions are reconciled against
   * the policy at startup, so a tool no role can reach fails the boot rather
   * than sitting there looking live.
   */
  policy?: Policy<P>;
  /**
   * Async alternative to `policy`, for roles and permissions stored in an IdP,
   * database or policy service. Return a principal with `createPrincipal`.
   */
  authorize?: (identity: Identity) => Promise<Principal<P>> | Principal<P>;
  /** Awaited access-decision sink. A rejection fails closed. */
  onDecision?: AuthorizationDecisionSink;
  /**
   * Names this deployment on every event it emits.
   *
   * Set the same value here and in `server(...)`, or a dashboard reading both
   * cannot tell that a refusal and a call came from the same place.
   */
  emitter?: string;
  /**
   * After auth: map the verified identity to backend context, or throw
   * `AccessDeniedError` for an actionable 403. Omit to use `policy` alone.
   *
   * Supply both when the context needs more than the principal — a tenant, a
   * connection, a downstream credential. The policy still runs first and still
   * refuses anyone it grants nothing, so this enriches the context rather than
   * taking over the decision, and the boot-time reconciliation stays honest.
   */
  resolve?: (identity: Identity, principal: Principal<P> | undefined) => Promise<TContext> | TContext;
  /** Per-request MCP server factory. `toolServer` builds one from a tool set. */
  createServer: ((context: TContext) => McpServer) & {
    /** Tool name to required permission, when the factory knows its own tools. */
    permissions?: ReadonlyMap<string, string>;
    /** Protocol route to permission, used to distinguish policy denial from scope step-up. */
    routePermissions?: ReadonlyMap<string, string>;
    routeNameFor?: (kind: 'tool' | 'prompt' | 'resource', name: string) => string | undefined;
    /** Resolve exact and templated protocol routes to their declared permission. */
    permissionForRoute?: (kind: 'tool' | 'prompt' | 'resource', name: string) => string | undefined;
  };
  /**
   * The same map, when your own factory wraps a `toolServer` and hides it —
   * which a richer `TContext` than the principal forces you to do. Pass
   * `toolServer(...).permissions` here and the boot-time check still runs.
   */
  permissions?: ReadonlyMap<string, string>;
  /** Key under `authInfo.extra` for the resolved context. */
  contextExtraKey?: string;
  /** Health check path. Defaults to `/health`. */
  healthPath?: string;
  /** Reject 2025-era requests by default; opt in only when legacy clients are required. */
  legacy?: 'reject' | 'stateless';
  /**
   * Cap on the body read that names the capability. Defaults to 1 MiB; over it
   * is a 413. The read happens after the bearer gate, so the cap bounds an
   * authenticated caller rather than anyone who can reach the port.
   */
  maxRequestBytes?: number;
};

/**
 * With a `policy`, the principal reaching `resolve` is never undefined: the
 * policy ran first and already refused anyone it grants nothing. Saying so here
 * saves every caller the same non-null assertion.
 */
export function createMcpFetch<TContext = Principal<string>, P extends string = string>(
  options: Omit<McpFetchOptions<TContext, P>, 'policy' | 'authorize' | 'resolve'> & {
    policy: Policy<P>;
    authorize?: never;
    resolve?: (identity: Identity, principal: Principal<P>) => Promise<TContext> | TContext;
  },
): (request: Request) => Promise<Response>;
export function createMcpFetch<TContext = Principal<string>, P extends string = string>(
  options: Omit<McpFetchOptions<TContext, P>, 'policy' | 'authorize' | 'resolve'> & {
    policy?: never;
    authorize: (identity: Identity) => Promise<Principal<P>> | Principal<P>;
    resolve?: (identity: Identity, principal: Principal<P>) => Promise<TContext> | TContext;
  },
): (request: Request) => Promise<Response>;
export function createMcpFetch<TContext = Principal<string>, P extends string = string>(
  options: Omit<McpFetchOptions<TContext, P>, 'policy' | 'authorize' | 'resolve'> & {
    policy?: never;
    authorize?: never;
    resolve: (identity: Identity, principal: undefined) => Promise<TContext> | TContext;
  },
): (request: Request) => Promise<Response>;
export function createMcpFetch<TContext = Principal<string>, P extends string = string>(
  // `never` is what makes both overloads assignable here: it accepts a `resolve`
  // written either way. The one cast this costs is below.
  options: Omit<McpFetchOptions<TContext, P>, 'resolve'> & {
    resolve?: (identity: Identity, principal: never) => Promise<TContext> | TContext;
  },
) {
  const {
    resourceServerUrl,
    oauthMetadata,
    requiredScopes = ['mcp'],
    supportedScopes,
    toolScopes,
    capabilityScopes,
    policy,
    createServer,
    emitter,
    contextExtraKey = CONTEXT_KEY,
    healthPath = '/health',
    legacy = 'reject',
    maxRequestBytes = 1_048_576,
  } = options;

  if (toolScopes && capabilityScopes) {
    throw new Error('Pass either `toolScopes` or `capabilityScopes`, not both.');
  }
  const invalidRequiredScope = requiredScopes.find((scope) => !OAUTH_SCOPE_TOKEN.test(scope));
  if (invalidRequiredScope !== undefined) {
    throw new Error(`requiredScopes has an invalid scope: '${invalidRequiredScope}'.`);
  }
  const invalidSupportedScope = supportedScopes?.find((scope) => !OAUTH_SCOPE_TOKEN.test(scope));
  if (invalidSupportedScope !== undefined) {
    throw new Error(`supportedScopes has an invalid scope: '${invalidSupportedScope}'.`);
  }
  const scopeMap = capabilityScopes ?? toolScopes;
  if (scopeMap && options.scopesForRequest) {
    throw new Error('Pass a declarative scope map or `scopesForRequest`, not both.');
  }
  if (scopeMap && requiredScopes.length === 0) {
    throw new Error('A declarative scope map needs at least one baseline scope.');
  }
  for (const [key, scopes] of Object.entries(scopeMap ?? {})) {
    if (Array.isArray(scopes) && scopes.length === 0) {
      throw new Error(`Scope map key '${key}' needs at least one scope.`);
    }
    if ((typeof scopes === 'string' ? [scopes] : scopes).some((scope) => !OAUTH_SCOPE_TOKEN.test(scope))) {
      throw new Error(`Scope map key '${key}' has an invalid scope.`);
    }
  }
  const scopeRoutes = Object.keys(scopeMap ?? {}).map((key) => ({ key, route: routeFromScopeKey(key) }));
  const named = new Set<string>();
  for (const { route } of scopeRoutes) {
    const canonical = `${route.kind}:${route.name}`;
    if (named.has(canonical)) {
      throw new Error(`Scope map names ${route.kind} '${route.name}' more than once.`);
    }
    named.add(canonical);
  }
  if (scopeMap && (createServer.permissionForRoute || createServer.routePermissions)) {
    for (const { key, route } of scopeRoutes) {
      const canonical = `${route.kind}:${route.name}`;
      const permission =
        createServer.permissionForRoute?.(route.kind, route.name) ??
        createServer.routePermissions?.get(canonical);
      if (permission === undefined) {
        throw new Error(`Scope map key '${key}' names no registered capability.`);
      }
    }
  }
  const scopesForRequest = options.scopesForRequest;
  const advertisedScopes = [
    ...new Set([
      ...requiredScopes,
      ...(supportedScopes ?? []),
      ...Object.values(scopeMap ?? {}).flatMap((scope) => (typeof scope === 'string' ? [scope] : [...scope])),
    ]),
  ];

  if (policy && options.authorize) {
    throw new Error('Pass either `policy` or `authorize`, not both.');
  }
  if (!policy && !options.authorize && !options.resolve) {
    throw new Error('createMcpFetch needs a `policy`, `authorize`, or `resolve`.');
  }

  // Drift between the policy and the tools, caught before the first request
  // rather than by whoever eventually notices the gap. Runs whenever both are
  // present: needing a richer context is no reason to lose the check.
  const required = options.permissions ?? createServer.permissions;
  const granted = new Set([...(policy?.roles.values() ?? [])].flat());
  if (policy && required) {
    const { error, warning } = reconcile(policy.roles, required);
    if (warning) console.warn(warning);
    if (error) throw new Error(error);
  }

  const enrich = options.resolve;
  const authorize = async (identity: Identity): Promise<Principal<P> | undefined> => {
    if (!policy && !options.authorize) return undefined;
    const principal = policy ? policy(identity) : await options.authorize!(identity);
    if (!isPrincipal(principal)) {
      throw new Error(
        'The authorizer returned an invalid principal. Use `createPrincipal` to construct one.',
      );
    }
    if (principal.permissions.length === 0) {
      await emitDecision(options.onDecision, principal, 'deny', 'not_permitted', emitter);
      throw AccessDeniedError.notPermitted(principalLabel(principal));
    }
    return principal;
  };

  const enrichIdentity = async (
    identity: Identity,
    principal: Principal<P> | undefined,
  ): Promise<TContext> => {
    if (!policy && !options.authorize) return enrich!(identity, undefined as never);
    try {
      const context = enrich ? await enrich(identity, principal as never) : (principal as TContext);
      await emitDecision(options.onDecision, principal!, 'allow', undefined, emitter);
      return context;
    } catch (error) {
      if (error instanceof AccessDeniedError) {
        await emitDecision(options.onDecision, principal!, 'deny', error.reason, emitter);
      }
      throw error;
    }
  };

  const { tokenVerifier, mapIdentity } = verifierFor({
    oauthMetadata,
    resourceServerUrl,
    ...(options.verifier ? { verifier: options.verifier } : {}),
    ...(options.tokenVerifier ? { tokenVerifier: options.tokenVerifier } : {}),
    ...(options.identityFromAuth ? { identityFromAuth: options.identityFromAuth } : {}),
  });

  const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(resourceServerUrl);
  const metadataOptions = { oauthMetadata, resourceServerUrl, scopesSupported: advertisedScopes };

  const mcp = createMcpHandler(
    (ctx) => {
      const context = ctx.authInfo?.extra?.[contextExtraKey] as TContext | undefined;
      if (context === undefined) {
        throw new Error('Request reached the MCP factory with no resolved context.');
      }
      return createServer(context);
    },
    { legacy },
  );

  return async function mcpFetch(request: Request): Promise<Response> {
    const metadata = oauthMetadataResponse(request, metadataOptions);
    if (metadata) return metadata;

    const { pathname } = new URL(request.url);
    if (pathname === healthPath) {
      // Counts, not names. This answers the operator's question — did my policy
      // load, and does it match the tools — without handing an unauthenticated
      // scanner a map of the server.
      return Response.json({
        ok: true,
        resource: resourceServerUrl.href,
        authorization: policy
          ? { mode: 'policy', roles: policy.roles.size, permissions: granted.size }
          : { mode: options.authorize ? 'authorizer' : 'resolver' },
        capabilities: required?.size ?? 'not declared',
      });
    }
    if (pathname !== resourceServerUrl.pathname) {
      // The first-run mistake: a connector pointed at the host, or at a path
      // that does not match the URL tokens are bound to. A bare 404 sends
      // people looking at their client.
      return new Response(
        `No MCP endpoint at ${pathname}. This server answers on ${resourceServerUrl.pathname}, ` +
          `which is also the audience its tokens must carry.\n`,
        { status: 404, headers: { 'Content-Type': 'text/plain' } },
      );
    }

    // Authenticate at the baseline first. Nothing below reads the body until a
    // valid token has proved somebody is entitled to make this process work,
    // and the per-capability scope is checked after the gate anyway.
    const gate = requireBearerAuth({
      verifier: tokenVerifier,
      requiredScopes,
      resourceMetadataUrl,
    });

    const auth: AuthInfo | Response = await gate(request);
    if (auth instanceof Response) return auth;

    let identity: Identity;
    let principal: Principal<P> | undefined;
    try {
      identity = mapIdentity(auth);
      principal = await authorize(identity);
    } catch (error) {
      if (error instanceof AccessDeniedError) {
        return policyDenied(error);
      }
      throw error;
    }

    const scoped = Boolean(scopeMap || scopesForRequest);
    const routed = Boolean(createServer.permissionForRoute ?? createServer.routePermissions);
    const gateResult = await runScopedGate({
      request,
      auth,
      principal,
      maxRequestBytes,
      requiredScopes,
      scoped,
      routed,
      scopeMap,
      resolveCapabilityScopes: (route) => {
        if (route.method !== 'resources/read' || !route.name || !scopeMap) return undefined;
        const registered = createServer.routeNameFor?.('resource', route.name);
        return registered === undefined
          ? undefined
          : scopesForCapability(route.method, registered, scopeMap, requiredScopes[0] ?? 'mcp');
      },
      scopesForRequest,
      resolvePermission: (route) =>
        permissionForRoute(createServer.permissionForRoute, createServer.routePermissions, route),
      onDecision: options.onDecision,
      ...(emitter ? { emitter } : {}),
      resourceMetadataUrl,
    });
    if (!gateResult.ok) return gateResult.response;
    const preflight = gateResult.preflight;

    let context: TContext;
    try {
      context = await enrichIdentity(identity, principal);
    } catch (error) {
      if (error instanceof AccessDeniedError) return policyDenied(error);
      throw error;
    }

    const answer = await mcp.fetch(request, {
      authInfo: { ...auth, extra: { ...auth.extra, [contextExtraKey]: context } },
      ...(preflight ? { parsedBody: preflight.body } : {}),
    });
    return legacy === 'reject' ? explainLegacyRefusal(answer) : answer;
  };
}

/**
 * Say what to do about the refusal every new deployment meets first.
 *
 * `legacy: 'reject'` is strict on purpose, but no MCP client shipping today can
 * satisfy it: they all still open with the `initialize` handshake that 2026-07-28
 * removed. So the first connection anybody makes fails with a bare protocol
 * error that does not mention that a setting exists, let alone which one. The
 * refusal stands; it just stops being a riddle.
 */
async function explainLegacyRefusal(response: Response): Promise<Response> {
  if (response.ok) return response;
  const body = await response.clone().text();
  if (!body.includes('Unsupported protocol version')) return response;

  let payload: { error?: { message?: string } };
  try {
    payload = JSON.parse(body) as { error?: { message?: string } };
  } catch {
    return response;
  }
  if (typeof payload.error?.message !== 'string') return response;

  payload.error.message +=
    ". No MCP client currently ships without the initialize handshake, so this refuses every client available today. Set legacy: 'stateless' to serve them.";
  return Response.json(payload, { status: response.status, headers: response.headers });
}

function routeFromScopeKey(key: string): { kind: 'tool' | 'prompt' | 'resource'; name: string } {
  for (const kind of ['tool', 'prompt', 'resource'] as const) {
    const prefix = `${kind}:`;
    if (key.startsWith(prefix)) return { kind, name: key.slice(prefix.length) };
  }
  return { kind: 'tool', name: key };
}

function isPrincipal(value: unknown): value is Principal<string> {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Partial<Principal<string>>;
  return (
    typeof candidate.issuer === 'string' &&
    typeof candidate.sub === 'string' &&
    // Optional, and genuinely absent for an opaque token whose introspection
    // response carries no email. Demanding one here refused every such caller
    // with a 500 that named the authorizer rather than the missing claim.
    (candidate.email === undefined || typeof candidate.email === 'string') &&
    Array.isArray(candidate.roles) &&
    candidate.roles.every((role) => typeof role === 'string') &&
    Array.isArray(candidate.permissions) &&
    candidate.permissions.every((permission) => typeof permission === 'string') &&
    typeof candidate.can === 'function'
  );
}
