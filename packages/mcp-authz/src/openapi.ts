import {
  getOAuthProtectedResourceMetadataUrl,
  oauthMetadataResponse,
  requireBearerAuth,
  type AuthInfo,
  type OAuthMetadata,
  type OAuthTokenVerifier,
} from '@modelcontextprotocol/server';
import { AccessDeniedError, type Identity } from './identity';
import { emitDecision, policyDenied, principalLabel, type AuthorizationDecisionSink } from './decision';
import { type PermissionMapRecord } from './permissions-module';
import { reconcile, type Policy, type Principal } from './policy';
import type { AuditErrorSink, AuditEvent, AuditSink } from './tools';
import { verifierFor, type VerifierOptions } from './verifier';

/**
 * The same bet as the MCP side, on the other catalogue an agent reads.
 *
 * `gate()` earns its keep because a tool that is never registered is a tool the
 * model never sees, so it never tries. An HTTP API has one thing shaped like
 * that list: its OpenAPI document. Filtering the served document per caller is
 * the same move — a smaller prompt, and no confident calls into a 403.
 *
 * For a hand-written client it changes nothing, because that client was coded
 * against the spec months ago. Hiding an operation is not the boundary; the
 * check on the request is, and it runs here whether or not the caller ever read
 * the document.
 */

/**
 * As much of an OpenAPI document as this needs to know about. Everything else
 * rides along untouched, so a document with `components`, `webhooks` or a
 * vendor extension comes back out the way it went in.
 */
export type OpenApiDocument = {
  paths?: Record<string, Record<string, unknown> | undefined>;
  [key: string]: unknown;
};

/** The methods OpenAPI defines on a path item. Anything else there is not an operation. */
const METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'] as const;

export type OpenApiOperation = {
  /** The document's own `operationId`, which is what the permission map is keyed by. */
  operationId: string;
  /** Lowercased HTTP method. */
  method: string;
  /** The templated path, e.g. `/cases/{id}`. */
  path: string;
};

export type OperationRecord = PermissionMapRecord & {
  /** Every operation the document describes, in document order. */
  operations: OpenApiOperation[];
};

/**
 * What the document says this API can do, read off the document.
 *
 * The mirror of `recordCapabilities`, and it needs no running server: an
 * OpenAPI file is the catalogue, already sitting in your repository. Feed the
 * result to `toPermissionsModule` for a map priced `TODO:unassigned`, which no
 * role grants and the boot refuses until somebody decides what each operation
 * costs.
 */
export function recordOperations(spec: OpenApiDocument): OperationRecord {
  const operations: OpenApiOperation[] = [];
  const seen = new Map<string, string>();

  for (const [path, item] of Object.entries(spec.paths ?? {})) {
    if (!item || typeof item !== 'object') continue;
    for (const method of METHODS) {
      const operation = (item as Record<string, unknown>)[method];
      if (!operation || typeof operation !== 'object') continue;
      const operationId = (operation as { operationId?: unknown }).operationId;
      if (typeof operationId !== 'string' || operationId.length === 0) {
        // Refused rather than named `get /cases/{id}` for you. A generated
        // fallback is a second naming scheme that only some operations use, and
        // it changes under a path rename — so the map silently stops matching
        // the route it was written for. Every generator emits an operationId.
        throw new Error(
          `${method.toUpperCase()} ${path} has no operationId, and the permission map is keyed by it. ` +
            'Give the operation an operationId in the document.',
        );
      }
      const duplicate = seen.get(operationId);
      if (duplicate) {
        throw new Error(
          `operationId '${operationId}' is used by both ${duplicate} and ${method.toUpperCase()} ${path}. ` +
            'One id would price two routes, so the map could not say which.',
        );
      }
      seen.set(operationId, `${method.toUpperCase()} ${path}`);
      operations.push({ operationId, method, path });
    }
  }

  return { names: [...seen.keys()].sort(), operations };
}

/**
 * The document as this caller should see it: their operations, and nothing else.
 *
 * A path item left with no operations is dropped, so the reader is not offered
 * a route with no verbs. `components` is deliberately left whole — pruning it
 * means walking the `$ref` graph, and a schema nobody references costs a few
 * hundred tokens where a wrongly-pruned one breaks the document.
 */
export function filterSpec<P extends string>(
  spec: OpenApiDocument,
  principal: Principal<P>,
  permissions: Readonly<Record<string, string>>,
): OpenApiDocument {
  const paths: Record<string, Record<string, unknown>> = {};

  for (const [path, item] of Object.entries(spec.paths ?? {})) {
    if (!item || typeof item !== 'object') continue;
    const kept: Record<string, unknown> = {};
    let any = false;
    for (const [key, value] of Object.entries(item)) {
      const method = METHODS.find((candidate) => candidate === key);
      if (!method) {
        // `parameters`, `summary`, `$ref`, extensions: path-level things that
        // describe whatever operations survive.
        kept[key] = value;
        continue;
      }
      const operationId = (value as { operationId?: unknown })?.operationId;
      const permission = typeof operationId === 'string' ? permissions[operationId] : undefined;
      if (permission !== undefined && principal.can(permission as P)) {
        kept[key] = value;
        any = true;
      }
    }
    if (any) paths[path] = kept;
  }

  return { ...spec, paths };
}

export type OpenApiFetchOptions<P extends string = string> = {
  /** The document describing this API. Also the catalogue served to callers. */
  spec: OpenApiDocument;
  /** `operationId` to the permission it costs. Every operation needs an entry. */
  permissions: Readonly<Record<string, string>>;
  /** This API's public base URL, e.g. `https://api.acme.com`. Tokens must carry it. */
  resourceServerUrl: URL;
  /** RFC 8414 metadata for the authorization server in front of us. */
  oauthMetadata: OAuthMetadata;
  /** Token verification. Defaults come from `oauthMetadata` and `resourceServerUrl`. */
  verifier?: Partial<VerifierOptions>;
  /** Bring any SDK-compatible verifier. Mutually exclusive with `verifier`. */
  tokenVerifier?: OAuthTokenVerifier;
  /** Map a custom verifier's AuthInfo into the identity consumed by policy. */
  identityFromAuth?: (auth: AuthInfo) => Identity;
  /** Baseline scopes every request must carry. */
  requiredScopes?: string[];
  /** All scopes advertised in protected-resource metadata. */
  supportedScopes?: string[];
  /** Who may call and what they may do. */
  policy?: Policy<P>;
  /** Async alternative to `policy`, for roles held elsewhere. */
  authorize?: (identity: Identity) => Promise<Principal<P>> | Principal<P>;
  /** Awaited access-decision sink. Sees the refusals, including probes. */
  onDecision?: AuthorizationDecisionSink;
  /** Awaited audit sink. `attempt` then `success` or `failure`, per call. */
  onAudit?: AuditSink;
  /** Where a failed terminal audit write goes. */
  onAuditError?: AuditErrorSink;
  /** Where the filtered document is served. Defaults to `/openapi.json`. */
  specPath?: string;
  /**
   * Names this deployment on every event it emits.
   *
   * Set the same value in every entry point of one deployment: a dashboard
   * reading several of them cannot otherwise tell which server refused a call.
   */
  emitter?: string;
  /** Your API. Reached only for a request this caller is permitted to make. */
  upstream: (request: Request, principal: Principal<P>) => Promise<Response> | Response;
};

/**
 * An OAuth 2.1 resource server in front of an API you already have.
 *
 * Anything the document does not describe is refused. That is the same rule as
 * the MCP side — a capability nobody priced is reachable by everyone or by
 * nobody, with no error to read — and it means routes you deliberately leave
 * out of the spec (a health check, static files) belong outside this wrapper
 * rather than behind it.
 */
export function createOpenApiFetch<P extends string = string>(
  options: OpenApiFetchOptions<P>,
): (request: Request) => Promise<Response> {
  const {
    spec,
    permissions,
    resourceServerUrl,
    oauthMetadata,
    requiredScopes = ['api'],
    supportedScopes,
    policy,
    specPath = '/openapi.json',
    emitter,
    upstream,
  } = options;

  if (policy && options.authorize) {
    throw new Error('Pass either `policy` or `authorize`, not both.');
  }
  if (!policy && !options.authorize) {
    throw new Error('createOpenApiFetch needs a `policy` or an `authorize`.');
  }

  const record = recordOperations(spec);
  const priced = new Map<string, string>();
  for (const name of record.names) {
    const permission = permissions[name];
    if (permission === undefined) {
      // The boot, not the first call. An operation with no price is either
      // reachable by everyone or by nobody, and both are found late.
      throw new Error(
        `The permission map puts no price on '${name}'. Every operation in the document needs an entry; ` +
          'recordOperations() and toPermissionsModule() generate the starting map.',
      );
    }
    priced.set(name, permission);
  }
  for (const name of Object.keys(permissions)) {
    if (!priced.has(name)) {
      throw new Error(
        `The permission map prices '${name}', which the document describes no operation for. ` +
          'A renamed operationId leaves an entry behind that stops gating anything.',
      );
    }
  }
  if (policy) {
    const { error, warning } = reconcile(policy.roles, priced);
    if (warning) console.warn(warning);
    if (error) throw new Error(error);
  }

  // Concrete segments beat templated ones, so `/cases/search` is not swallowed
  // by `/cases/{id}`, whichever order the document happens to list them in.
  const routes = record.operations
    .map((operation) => ({ ...operation, match: matcher(operation.path) }))
    .sort((a, b) => templateCount(a.path) - templateCount(b.path) || b.path.length - a.path.length);

  const { tokenVerifier, mapIdentity } = verifierFor({
    oauthMetadata,
    resourceServerUrl,
    ...(options.verifier ? { verifier: options.verifier } : {}),
    ...(options.tokenVerifier ? { tokenVerifier: options.tokenVerifier } : {}),
    ...(options.identityFromAuth ? { identityFromAuth: options.identityFromAuth } : {}),
  });

  const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(resourceServerUrl);
  const advertisedScopes = [...new Set([...requiredScopes, ...(supportedScopes ?? [])])];
  const metadataOptions = { oauthMetadata, resourceServerUrl, scopesSupported: advertisedScopes };
  const basePath = resourceServerUrl.pathname.replace(/\/$/, '');

  return async function openApiFetch(request: Request): Promise<Response> {
    const metadata = oauthMetadataResponse(request, metadataOptions);
    if (metadata) return metadata;

    const { pathname } = new URL(request.url);
    if (!pathname.startsWith(basePath)) {
      return new Response(
        `No API at ${pathname}. This server answers under ${basePath || '/'}, ` +
          `which is also the audience its tokens must carry.\n`,
        { status: 404, headers: { 'Content-Type': 'text/plain' } },
      );
    }
    const route = pathname.slice(basePath.length) || '/';

    const gate = requireBearerAuth({ verifier: tokenVerifier, requiredScopes, resourceMetadataUrl });
    const auth: AuthInfo | Response = await gate(request);
    if (auth instanceof Response) return auth;

    let identity: Identity;
    let principal: Principal<P>;
    try {
      identity = mapIdentity(auth);
      principal = policy ? policy(identity) : await options.authorize!(identity);
      if (principal.permissions.length === 0) {
        await emitDecision(options.onDecision, principal, 'deny', 'not_permitted', emitter);
        throw AccessDeniedError.notPermitted(principalLabel(principal));
      }
    } catch (error) {
      if (error instanceof AccessDeniedError) return policyDenied(error);
      throw error;
    }

    // The catalogue, cut to this caller. Authenticated on purpose: it is a
    // different document per person, and an anonymous one would have to be the
    // whole thing.
    if (route === specPath) {
      await emitDecision(options.onDecision, principal, 'allow', undefined, emitter);
      return Response.json(filterSpec(spec, principal, permissions));
    }

    const method = request.method.toLowerCase();
    const matched = routes.find((candidate) => candidate.method === method && candidate.match.test(route));
    if (!matched) {
      await emitDecision(options.onDecision, principal, 'deny', 'no_such_operation', emitter);
      return Response.json(
        {
          error: 'not_found',
          error_description:
            `${request.method} ${route} is not in the document this server gates, so it is refused. ` +
            'Describe it in the OpenAPI document, or serve it outside this wrapper.',
        },
        { status: 404 },
      );
    }

    const permission = priced.get(matched.operationId)!;
    if (!principal.can(permission as P)) {
      await emitDecision(options.onDecision, principal, 'deny', 'not_permitted', emitter);
      return policyDenied(
        AccessDeniedError.notPermitted(principalLabel(principal), `the permission '${permission}'`),
      );
    }
    await emitDecision(options.onDecision, principal, 'allow', undefined, emitter);

    const base = {
      type: 'mcp_authz.audit.v1',
      // One id for both events of this call. See `AuditEvent['callId']`.
      callId: crypto.randomUUID(),
      issuer: principal.issuer,
      sub: principal.sub,
      ...(principal.email ? { email: principal.email } : {}),
      ...(principal.domain ? { domain: principal.domain } : {}),
      ...(emitter ? { emitter } : {}),
      kind: 'operation',
      name: matched.operationId,
      permission,
      // The concrete path, which is what the call actually touched. The query
      // string is left out: it carries values a log store should not be the
      // first place to hold.
      resource: route,
    } as const satisfies Omit<AuditEvent, 'decision' | 'phase' | 'at'>;

    const { onAudit, onAuditError } = options;
    if (!onAudit) return upstream(request, principal);

    const started = performance.now();
    try {
      await onAudit({ ...base, decision: 'allow', phase: 'attempt', at: new Date().toISOString() });
    } catch {
      // Fail closed, exactly as the MCP side does: an action nobody could
      // record is an action that should not happen.
      return Response.json(
        {
          error: 'unavailable',
          error_description: 'The audit log refused the write, so the call did not run.',
        },
        { status: 503 },
      );
    }

    let response: Response;
    try {
      response = await upstream(request, principal);
    } catch (error) {
      await deliver(onAudit, onAuditError, {
        ...base,
        decision: 'allow',
        phase: 'failure',
        at: new Date().toISOString(),
        durationMs: performance.now() - started,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }

    // What an auditor is asking is whether the action happened, and over HTTP
    // that is the status rather than whether a promise rejected.
    await deliver(onAudit, onAuditError, {
      ...base,
      decision: 'allow',
      phase: response.ok ? 'success' : 'failure',
      at: new Date().toISOString(),
      durationMs: performance.now() - started,
      ...(response.ok ? {} : { error: `HTTP ${response.status}` }),
    });
    return response;
  };
}

async function deliver(
  sink: AuditSink,
  onError: AuditErrorSink | undefined,
  event: AuditEvent,
): Promise<void> {
  try {
    await sink(event);
  } catch (error) {
    try {
      await onError?.({ error, event });
    } catch {
      // The call already happened. An observer cannot change that.
    }
  }
}

function templateCount(path: string): number {
  return (path.match(/\{/g) ?? []).length;
}

/**
 * A path template as a matcher.
 *
 * `{id}` matches one segment and never a `/`, so `/cases/{id}` does not answer
 * for `/cases/C1/notes` — which would hand a caller a route nobody priced.
 */
function matcher(template: string): RegExp {
  const pattern = template
    .split('/')
    .map((segment) =>
      /^\{[^{}]+\}$/.test(segment) ? '[^/]+' : segment.replaceAll(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`),
    )
    .join('/');
  return new RegExp(`^${pattern}$`);
}
