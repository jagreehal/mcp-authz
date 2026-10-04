import {
  getOAuthProtectedResourceMetadataUrl,
  oauthMetadataResponse,
  requireBearerAuth,
  UriTemplate,
  type AuthInfo,
  type OAuthMetadata,
  type OAuthTokenVerifier,
} from '@modelcontextprotocol/server';
import { err, isUnexpectedError, ok, run, type AsyncResult } from 'awaitly';
import { AccessDeniedError, type Identity } from './identity';
import {
  emitDecision,
  permissionForFlatMap,
  policyDenied,
  principalLabel,
  runScopedGate,
  type AuthorizationDecisionSink,
  type ResourceIndex,
} from './ladder';
import { filterListingResult, isInvocationMethod, isListingMethod, retainListed } from './catalogue';
import { missingDefinitions, type Definition } from './definitions';
import { holdToRecord, type UpstreamRecord } from './upstream-record';
import { checkArguments, screenResult, withNotice } from './screen';
import { parseChecked } from './strict-json';
import { scopesForCapability, type CapabilityScopeMap } from './scopes';
import { reconcile, type Policy, type Principal } from './policy';
import type { TrustedMcpRoute } from './routing';
import {
  forwardToUpstream,
  headersForRewrittenBody,
  isEventStream,
  isJsonResponse,
  readCappedBody,
  type UpstreamConfig,
} from './upstream';
import { identityFromAuth, jwksVerifier, type VerifierOptions } from './verifier';

const OAUTH_SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

export type McpProxyOptions<P extends string = string> = {
  /** This proxy's public URL, e.g. `https://mcp.acme.com/mcp`. */
  resourceServerUrl: URL;
  /** RFC 8414 metadata for the authorization server in front of the proxy. */
  oauthMetadata: OAuthMetadata;
  verifier?: Partial<VerifierOptions>;
  tokenVerifier?: OAuthTokenVerifier;
  identityFromAuth?: (auth: AuthInfo) => Identity;
  /** URL-only upstream reached with a service credential. */
  upstream: UpstreamConfig;
  /** Flat permission map — same labels as `gate()` and `recordCapabilities`. */
  permissions: Readonly<Record<string, P>> | ReadonlyMap<string, P>;
  /**
   * What each priced capability said to the model when it was recorded: the
   * `DEFINITIONS` that `mcp-authz record` writes beside `PERMISSIONS`.
   *
   * A permission prices a name, and the upstream decides what stands behind
   * it. Without this, an upstream could keep an approved tool's name and
   * rewrite its description to steer the model, or add an argument to carry
   * data out, and every caller would be served the new one. With it, a
   * capability whose definition has changed is left out of listings and its
   * invocations are refused until someone re-records and approves the change.
   */
  definitions: Readonly<Record<string, Definition>>;
  /**
   * `resource:<label>` to the URI or URI template it answers on.
   *
   * A listing names a resource; a read names a URI. Only the upstream knows
   * which is which, so the map that prices resources has to carry both.
   * `recordCapabilities` emits this alongside the permission map.
   */
  resourceUris?: Readonly<Record<string, string>>;
  policy: Policy<P>;
  requiredScopes?: string[];
  supportedScopes?: string[];
  capabilityScopes?: CapabilityScopeMap;
  onDecision?: AuthorizationDecisionSink;
  /** Names this deployment on every event it emits. See `McpFetchOptions`. */
  emitter?: string;
  healthPath?: string;
  maxRequestBytes?: number;
};

export function createMcpProxy<P extends string = string>(
  options: McpProxyOptions<P>,
): (request: Request) => Promise<Response> {
  const {
    resourceServerUrl,
    oauthMetadata,
    upstream,
    policy,
    permissions: permissionsInput,
    definitions: definitionsInput,
    requiredScopes = ['mcp'],
    supportedScopes,
    capabilityScopes,
    resourceUris,
    emitter,
    healthPath = '/health',
    maxRequestBytes = 1_048_576,
  } = options;

  if (options.tokenVerifier && options.verifier) {
    throw new Error('Pass either `tokenVerifier` or built-in `verifier` options, not both.');
  }

  const permissions = toPermissionMap(permissionsInput);
  validatePermissions(permissions);
  validateScopes(capabilityScopes, permissions);
  const resources = buildResourceIndex(permissions, resourceUris);
  const definitions = new Map(Object.entries(definitionsInput));
  const unrecorded = missingDefinitions(permissions.keys(), definitions);
  if (unrecorded.length > 0) {
    throw new Error(
      `These priced capabilities have no recorded definition, so a change to one would go unnoticed:\n` +
        `${unrecorded.map((label) => `  ${label}`).join('\n')}\n\n` +
        'Pass `definitions` from the module `mcp-authz record` writes, re-recording if it predates them.',
    );
  }
  const record = holdToRecord(definitions, upstream);

  const invalidRequiredScope = requiredScopes.find((scope) => !OAUTH_SCOPE_TOKEN.test(scope));
  if (invalidRequiredScope !== undefined) {
    throw new Error(`requiredScopes has an invalid scope: '${invalidRequiredScope}'.`);
  }
  const invalidSupportedScope = supportedScopes?.find((scope) => !OAUTH_SCOPE_TOKEN.test(scope));
  if (invalidSupportedScope !== undefined) {
    throw new Error(`supportedScopes has an invalid scope: '${invalidSupportedScope}'.`);
  }
  if (capabilityScopes && requiredScopes.length === 0) {
    throw new Error('A declarative scope map needs at least one baseline scope.');
  }
  for (const [key, scopes] of Object.entries(capabilityScopes ?? {})) {
    if (Array.isArray(scopes) && scopes.length === 0) {
      throw new Error(`Scope map key '${key}' needs at least one scope.`);
    }
    if ((typeof scopes === 'string' ? [scopes] : scopes).some((scope) => !OAUTH_SCOPE_TOKEN.test(scope))) {
      throw new Error(`Scope map key '${key}' has an invalid scope.`);
    }
  }

  const { error, warning } = reconcile(policy.roles, permissions);
  if (warning) console.warn(warning);
  if (error) throw new Error(error);

  const advertisedScopes = [
    ...new Set([
      ...requiredScopes,
      ...(supportedScopes ?? []),
      ...Object.values(capabilityScopes ?? {}).flatMap((scope) =>
        typeof scope === 'string' ? [scope] : [...scope],
      ),
    ]),
  ];

  let tokenVerifier: OAuthTokenVerifier;
  let mapIdentity: (auth: AuthInfo) => Identity;
  if (options.tokenVerifier) {
    tokenVerifier = options.tokenVerifier;
    mapIdentity = options.identityFromAuth ?? identityFromAuth;
  } else {
    const published = typeof oauthMetadata.jwks_uri === 'string' ? oauthMetadata.jwks_uri : undefined;
    const jwksUri = options.verifier?.jwksUri ?? published;
    if (!jwksUri) {
      throw new Error(
        'No JWKS to verify tokens against. Set `verifier.jwksUri`, use a custom ' +
          '`tokenVerifier`, or use `discoverOAuth(issuer)`, whose metadata carries `jwks_uri`.',
      );
    }
    const builtIn = jwksVerifier({
      ...options.verifier,
      jwksUri,
      issuer: options.verifier?.issuer ?? oauthMetadata.issuer,
      resource: options.verifier?.resource ?? resourceServerUrl,
    });
    tokenVerifier = builtIn;
    mapIdentity = options.identityFromAuth ?? builtIn.identityOf;
  }

  const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(resourceServerUrl);
  const metadataOptions = { oauthMetadata, resourceServerUrl, scopesSupported: advertisedScopes };
  const granted = new Set([...policy.roles.values()].flat());

  // The ladder, named. Each rung answers with what it produced or with the
  // refusal it decided on, and `run` stops at the first refusal — so the
  // order below is the whole authorization story, and a rung cannot be
  // skipped by forgetting to return its answer.
  const steps = {
    /** Baseline OAuth: a valid token for this resource, carrying the baseline scopes. */
    verify: async (request: Request): AsyncResult<AuthInfo, Response> => {
      const answer = await requireBearerAuth({
        verifier: tokenVerifier,
        requiredScopes,
        resourceMetadataUrl,
      })(request);
      return answer instanceof Response ? err(answer) : ok(answer);
    },

    /** Identity to principal. Nothing granted is a refusal, not an empty pass. */
    authorize: async (auth: AuthInfo): AsyncResult<Principal<P>, Response> => {
      let principal: Principal<P>;
      try {
        principal = policy(mapIdentity(auth));
      } catch (error) {
        if (error instanceof AccessDeniedError) return err(policyDenied(error));
        throw error;
      }
      if (principal.permissions.length === 0) {
        await emitDecision(options.onDecision, principal, 'deny', 'not_permitted', emitter);
        return err(policyDenied(AccessDeniedError.notPermitted(principalLabel(principal))));
      }
      await emitDecision(options.onDecision, principal, 'allow', undefined, emitter);
      return ok(principal);
    },

    /** Classify, price the named capability, then step up the scope if one is configured. */
    gate: async (
      request: Request,
      auth: AuthInfo,
      principal: Principal<P>,
    ): AsyncResult<TrustedMcpRoute, Response> => {
      const can = (permission: string): boolean => principal.can(permission as P);
      const result = await runScopedGate({
        request,
        auth,
        principal,
        maxRequestBytes,
        requiredScopes,
        scoped: Boolean(capabilityScopes),
        routed: true,
        // Nothing downstream re-checks anything, so a request this cannot
        // classify is refused here rather than forwarded on the service
        // credential and left to an upstream that may not look.
        strictClassification: true,
        scopeMap: capabilityScopes,
        // The map is keyed by label; a read carries a URI. Where several
        // patterns cover one URI, every one of their scopes is demanded, for
        // the same reason every one of their permissions is.
        //
        // A completion and a subscription reach a prompt or resources without
        // invoking them, so they are held to the scopes each reached capability
        // asks for, exactly as a direct request for it would be.
        resolveCapabilityScopes: (route) => {
          const reached = reach(route);
          if (!capabilityScopes || !Array.isArray(reached) || route.method === 'tools/call') return undefined;
          const baseline = requiredScopes[0] ?? 'mcp';
          const scopes = reached.flatMap((target) =>
            target.method === 'resources/read'
              ? coveringResources(resources, target.name!).flatMap((entry) =>
                  scopesForCapability(
                    target.method,
                    entry.label.slice('resource:'.length),
                    capabilityScopes,
                    baseline,
                  ),
                )
              : scopesForCapability(target.method, target.name, capabilityScopes, baseline),
          );
          return scopes.length > 0 ? [...new Set(scopes)] : undefined;
        },
        resolvePermission: (route) => permissionForFlatMap(permissions, route, resources, can),
        onDecision: options.onDecision,
        resourceMetadataUrl,
      });
      if (!result.ok) return err(result.response);
      // 2026-07-28 or nothing. A request without validated routing headers is
      // one whose capability only the body names, and this forwards on a
      // credential that outranks the caller; there is no older dialect to keep.
      if (!result.preflight?.headersValidated) {
        return err(
          jsonRpcError(
            400,
            -32_600,
            'This proxy speaks MCP 2026-07-28: send the Mcp-Method and Mcp-Name routing headers.',
            idOf(result.preflight?.route),
          ),
        );
      }
      return ok(result.preflight.route);
    },

    /** Refuse any method not on the list, and anything unpriced, unpermitted or changed. */
    price: async (principal: Principal<P>, route: TrustedMcpRoute): AsyncResult<undefined, Response> => {
      const denied = await authorizeMessage({
        principal,
        permissions,
        resources,
        record,
        definitions,
        route,
        onDecision: options.onDecision,
        ...(emitter ? { emitter } : {}),
      });
      return denied ? err(denied) : ok(undefined);
    },

    /** Swap the caller's credential for the service one and forward. */
    forward: async (request: Request): AsyncResult<Response, Response> =>
      ok(await forwardToUpstream(request, upstream)),

    /** Hide from a listing what the caller could not have called anyway. */
    filter: async (
      response: Response,
      route: TrustedMcpRoute,
      principal: Principal<P>,
    ): AsyncResult<Response, Response> => {
      const method = route.method;
      // The upstream's instructions reach the model as a description does, so
      // they are held to the record the same way.
      const transform: Transform | undefined = isListingMethod(method)
        ? (payload) => filterMessage(payload, method, principal, permissions, record)
        : method === 'server/discover'
          ? (payload) => holdInstructions(payload, record)
          : method === 'tools/call'
            ? (payload, raw) => screenAnswer(payload, raw, route.name!, definitions)
            : undefined;
      if (!transform) return ok(response);
      // A listing filtered for this caller is theirs alone, whatever the
      // upstream, serving one service account, said about sharing it.
      const personal = isListingMethod(method);
      // A tool's answer is held whole to be screened, and answers run larger
      // than catalogues: an export, a file. Bounded all the same.
      const cap = method === 'tools/call' ? Math.max(maxRequestBytes, ANSWER_BYTES) : maxRequestBytes;
      if (isEventStream(response)) {
        return ok(filterEventStream(response, method, transform, personal, cap, idOf(route)));
      }
      if (isJsonResponse(response)) {
        const filtered = await filterJson(response, transform, personal, cap);
        return filtered
          ? ok(filtered)
          : err(unfilterable(`${method} was over ${cap} bytes or not readable as JSON-RPC`, idOf(route)));
      }
      // A catalogue this cannot read is one it cannot hide anything from.
      // Passing it through would serve the full catalogue to everyone the day
      // an upstream changes its content type.
      return err(
        unfilterable(
          `${method} came back as '${response.headers.get('content-type') ?? 'no content type'}'`,
          idOf(route),
        ),
      );
    },
  };

  return async function mcpProxy(request: Request): Promise<Response> {
    const metadata = oauthMetadataResponse(request, metadataOptions);
    if (metadata) return metadata;

    const { pathname } = new URL(request.url);
    if (pathname === healthPath) {
      // Counts, not names, and never the upstream's address. This answers the
      // operator's question — did my policy load, and does it match the tools —
      // without handing an unauthenticated scanner a map of what sits behind.
      return Response.json({
        ok: true,
        mode: 'proxy',
        resource: resourceServerUrl.href,
        authorization: { mode: 'policy', roles: policy.roles.size, permissions: granted.size },
        capabilities: permissions.size,
      });
    }
    if (pathname !== resourceServerUrl.pathname) {
      return new Response(
        `No MCP endpoint at ${pathname}. This proxy answers on ${resourceServerUrl.pathname}, ` +
          `which is also the audience its tokens must carry.\n`,
        { status: 404, headers: { 'Content-Type': 'text/plain' } },
      );
    }

    // Every 2026-07-28 message is a POST; GET streams and DELETE sessions are gone.
    if (request.method.toUpperCase() !== 'POST') {
      return new Response('This proxy accepts MCP 2026-07-28 messages, which are all POSTs.\n', {
        status: 405,
        headers: { Allow: 'POST', 'Content-Type': 'text/plain' },
      });
    }

    const result = await run(steps, async (s) => {
      const auth = await s.verify(request);
      const principal = await s.authorize(auth);
      const route = await s.gate(request, auth, principal);
      await s.price(principal, route);
      const upstreamResponse = await s.forward(request);
      return s.filter(upstreamResponse, route, principal);
    });

    if (result.ok) return result.value;
    // A refusal is already the response it decided on. Anything else is a bug
    // in this process, and belongs to the host's error handling rather than
    // being flattened into a 500 that says nothing.
    if (isUnexpectedError(result.error)) throw result.error.cause;
    return result.error;
  };
}

/**
 * What may pass through, method by method. Nothing else does: a method missing
 * here is one nobody decided how to authorize, and forwarding it would run it on
 * the service credential, which outranks every caller.
 *
 * Listings are filtered on the way back, so asking for one needs no permission.
 * Invocations, and the two methods that reach a capability without invoking it,
 * are priced like a call: a completion runs the prompt's or resource's handler,
 * and a subscription reports updates to the resources it names.
 */
// The most a screened tool answer may hold.
const ANSWER_BYTES = 16 * 1024 * 1024;

const PASS_THROUGH = new Set([
  'server/discover',
  'ping',
  'tools/list',
  'prompts/list',
  'resources/list',
  'resources/templates/list',
  'notifications/cancelled',
  'notifications/progress',
]);

/**
 * A message rewritten on its way back, or `undefined` when it cannot be read.
 * Returning `payload` itself means unchanged, and the bytes that arrived are
 * passed on: re-serializing would round any integer past 2^53. `raw` is the
 * message as it arrived, for a rewrite that must keep every digit.
 */
type Transform = (payload: unknown, raw: string) => unknown;

async function authorizeMessage<P extends string>(options: {
  principal: Principal<P>;
  permissions: ReadonlyMap<string, string>;
  resources: ProxyResourceIndex;
  record: UpstreamRecord;
  definitions: ReadonlyMap<string, Definition>;
  route: TrustedMcpRoute;
  onDecision?: AuthorizationDecisionSink;
  emitter?: string;
}): Promise<Response | undefined> {
  const { route, principal, emitter, resources } = options;
  if (PASS_THROUGH.has(route.method)) return undefined;

  const refuse = async (because: string): Promise<Response> => {
    await emitDecision(options.onDecision, principal, 'deny', 'policy_denied', emitter);
    return policyDenied(AccessDeniedError.notPermitted(principalLabel(principal), because));
  };
  const can = (permission: string) => principal.can(permission as P);

  const reached = reach(route);
  if (reached === undefined) {
    return jsonRpcError(
      400,
      -32_601,
      `Method not found: this proxy does not forward ${route.method}.`,
      idOf(route),
    );
  }
  if (typeof reached === 'string') return refuse(reached);

  const labels: string[] = [];
  for (const target of reached) {
    if (target.method === 'resources/read') {
      // Every registration covering the URI has to be satisfied, since which
      // one the upstream serves it from is its business. A URI still holding a
      // template's braces names that template, as a completion does, and is
      // never read as literal characters some other pattern happens to match.
      const uri = target.name!;
      const covering = coveringResources(resources, uri);
      if (covering.length === 0) return refuse(`the capability '${uri}' is not priced in the permission map`);
      const denied = covering.find((entry) => !can(entry.permission));
      if (denied) return refuse(`the permission '${denied.permission}'`);
      labels.push(...covering.map((entry) => entry.label));
      continue;
    }
    const permission = permissionForFlatMap(options.permissions, target, resources, can);
    if (permission === undefined) {
      return refuse(`the capability '${target.name}' is not priced in the permission map`);
    }
    if (!can(permission)) return refuse(`the permission '${permission}'`);
    labels.push(
      ...(target.method === 'tools/call' ? [target.name!, `tool:${target.name}`] : [`prompt:${target.name}`]),
    );
  }
  // Priced and permitted, but the definition behind each name has to be the one
  // approved, checked now if it was not checked recently.
  const changed = await options.record.refuse(labels);
  if (changed) return refuse(changed);
  // The arguments a tool takes are part of what was approved.
  if (route.method === 'tools/call') {
    const definition = options.definitions.get(route.name!) ?? options.definitions.get(`tool:${route.name}`);
    const params = (route.body as { params?: { arguments?: unknown } }).params;
    const wrong = definition && checkArguments(route.name!, definition, params?.arguments);
    if (wrong) return jsonRpcError(400, -32_602, `Invalid params: ${wrong}`, idOf(route));
  }
  return undefined;
}

/**
 * Each capability a message reaches, as the request that would invoke it
 * directly: a string when the message is malformed, `undefined` for a method
 * this does not forward. Pricing and scopes both start here, so a completion
 * or a subscription is held to everything a direct request would be.
 */
function reach(route: TrustedMcpRoute): TrustedMcpRoute[] | string | undefined {
  const params = (route.body as { params?: Record<string, unknown> } | undefined)?.params ?? {};
  if (isInvocationMethod(route.method)) {
    // An invocation that names nothing cannot be priced, so it cannot be allowed.
    return route.name ? [route] : `a ${route.method} that names no capability`;
  }
  if (route.method === 'completion/complete') {
    const ref = params.ref as { type?: unknown; name?: unknown; uri?: unknown } | undefined;
    if (ref?.type === 'ref/prompt' && typeof ref.name === 'string') {
      return [{ ...route, method: 'prompts/get', name: ref.name }];
    }
    if (ref?.type === 'ref/resource' && typeof ref.uri === 'string') {
      return [{ ...route, method: 'resources/read', name: ref.uri }];
    }
    return 'a completion/complete whose ref names no prompt or resource';
  }
  if (route.method === 'subscriptions/listen') {
    const uris = (params.notifications as { resourceSubscriptions?: unknown } | undefined)
      ?.resourceSubscriptions;
    if (uris !== undefined && !(Array.isArray(uris) && uris.every((uri) => typeof uri === 'string'))) {
      return 'a subscriptions/listen whose resourceSubscriptions is not a list of URIs';
    }
    return ((uris ?? []) as string[]).map((uri) => ({ ...route, method: 'resources/read', name: uri }));
  }
  return undefined;
}

/**
 * Every priced resource covering a URI, since which one the upstream serves it
 * from is its business. A URI still holding a template's braces names that
 * template, as a completion does, and is never read as literal characters some
 * other pattern happens to match.
 */
function coveringResources(resources: ProxyResourceIndex, uri: string): ProxyResourceIndex {
  return resources.filter((entry) => (uri.includes('{') ? entry.pattern === uri : entry.matches(uri)));
}

/** A JSON-RPC error the client can match to its request. */
function jsonRpcError(status: number, code: number, message: string, id: string | number | null): Response {
  return Response.json({ jsonrpc: '2.0', id, error: { code, message } }, { status });
}

/** A `tools/call` answer, screened against the tool's approved definition. */
function screenAnswer(
  payload: unknown,
  raw: string,
  tool: string,
  definitions: ReadonlyMap<string, Definition>,
): unknown {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return undefined;
  const message = payload as Record<string, unknown>;
  if (!('result' in message)) return 'error' in message || 'method' in message ? message : undefined;
  if (typeof message.result !== 'object' || message.result === null) return undefined;
  const definition = definitions.get(tool) ?? definitions.get(`tool:${tool}`) ?? {};
  // Checked as written: a number the plain parse rounded would pass a bound
  // the upstream's own number breaks.
  const checked = (parseChecked(raw) as { result: Record<string, unknown> }).result;
  const screened = screenResult(tool, definition, checked);
  if (screened.verdict === 'pass') return payload;
  console.warn(`mcp-authz proxy: ${screened.warning}`);
  return screened.verdict === 'withhold'
    ? { ...message, result: screened.result }
    : withNotice(raw, screened.notice);
}

/** A `server/discover` answer with its instructions held to the record. */
function holdInstructions(payload: unknown, record: UpstreamRecord): unknown {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return undefined;
  const message = payload as Record<string, unknown>;
  if (!('result' in message)) return 'error' in message || 'method' in message ? message : undefined;
  if (typeof message.result !== 'object' || message.result === null) return undefined;
  const { instructions, ...result } = message.result as Record<string, unknown>;
  const kept = record.instructions(instructions);
  return { ...message, result: kept === undefined ? result : { ...result, instructions: kept } };
}

/** The resource index, with the URI or template each label was registered at. */
type ProxyResourceIndex = readonly (ResourceIndex[number] & { pattern: string })[];

/**
 * Match each priced `resource:` label to the URIs it covers.
 *
 * Exact URIs are tried before templates, so a resource registered at its own
 * address is never answered by a template that happens to span it.
 */
function buildResourceIndex(
  permissions: ReadonlyMap<string, string>,
  resourceUris: Readonly<Record<string, string>> | undefined,
): ProxyResourceIndex {
  const exact: { label: string; permission: string; pattern: string; matches: (uri: string) => boolean }[] =
    [];
  const templated: typeof exact = [];
  const unpriced: string[] = [];

  for (const [label, permission] of permissions) {
    if (!label.startsWith('resource:')) continue;
    const uri = resourceUris?.[label];
    if (uri === undefined) {
      unpriced.push(label);
      continue;
    }
    if (uri.includes('{')) {
      const template = new UriTemplate(uri);
      templated.push({
        label,
        permission,
        pattern: uri,
        matches: (target) => template.match(target) !== null,
      });
    } else {
      exact.push({ label, permission, pattern: uri, matches: (target) => target === uri });
    }
  }

  if (unpriced.length > 0) {
    throw new Error(
      `A proxy authorizes resources/read by URI, and these priced resources carry none:\n` +
        `${unpriced.map((label) => `  ${label}`).join('\n')}\n\n` +
        `Pass \`resourceUris\` mapping each label to its uri or uriTemplate. ` +
        `\`recordCapabilities\` writes one for you; see mcp-authz/testing.`,
    );
  }
  for (const label of Object.keys(resourceUris ?? {})) {
    if (!permissions.has(label)) {
      throw new Error(`resourceUris key '${label}' names no priced capability.`);
    }
  }

  return [...exact, ...templated];
}

/**
 * The filtered response, or `undefined` when the body was over the cap or not
 * readable as JSON-RPC.
 *
 * The body is read once, under the same byte cap the SSE path uses: a catalogue
 * has to be held whole to be filtered, so an upstream that sends an unbounded
 * one would otherwise choose how much memory this spends.
 */
async function filterJson(
  response: Response,
  transform: Transform,
  personal: boolean,
  maxBytes: number,
): Promise<Response | undefined> {
  const raw = await readCappedBody(response.body, maxBytes);
  if (raw === undefined) return undefined;

  let payload: unknown;
  try {
    payload = JSON.parse(raw);
  } catch {
    return undefined;
  }
  const filtered = transform(payload, raw);
  if (filtered === undefined) return undefined;
  const headers = rewrittenHeaders(response, personal);
  if (filtered === payload) return new Response(raw, { status: response.status, headers });
  return Response.json(filtered, { status: response.status, headers });
}

/**
 * One JSON-RPC message with its listing filtered, or `undefined` when this
 * cannot tell what the message carries.
 *
 * An error reply and a progress notification carry no catalogue and pass
 * through untouched. Anything unrecognisable does not, because the whole point
 * of reading the body is to know whether a capability is hiding in it.
 */
function filterMessage<P extends string>(
  payload: unknown,
  method: Parameters<typeof filterListingResult>[0],
  principal: Principal<P>,
  permissions: ReadonlyMap<string, string>,
  record: UpstreamRecord,
): unknown | undefined {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return undefined;
  const message = payload as Record<string, unknown>;
  if (!('result' in message)) return 'error' in message || 'method' in message ? message : undefined;
  const result = message.result;
  if (typeof result !== 'object' || result === null) return undefined;
  return {
    ...message,
    result: {
      ...filterListingResult(
        method,
        retainListed(method, result as Record<string, unknown>, record.matches),
        principal,
        permissions,
      ),
      // Filtered for this caller, so no shared cache may hand it to another.
      cacheScope: 'private',
    },
  };
}

/**
 * Filter a listing carried over SSE, event by event as it arrives.
 *
 * Streamed rather than buffered: the body is an upstream's to size, and reading
 * it to the end before answering would both hold a catalogue hostage to a slow
 * server and let that server decide how much memory this process spends.
 *
 * Framing is read properly rather than by prefix. `data:` needs no space after
 * it, and one payload may arrive across several `data:` lines that the client
 * rejoins — a filter that only understands `data: ` passes both straight
 * through, which is the whole catalogue, unfiltered.
 */
function filterEventStream(
  response: Response,
  method: string,
  transform: Transform,
  personal: boolean,
  maxEventBytes: number,
  id: string | number | null,
): Response {
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  let buffered = '';
  let started = false;
  /**
   * Where the search for a terminator has already looked, and how many bytes
   * the pending event holds.
   *
   * Both are carried rather than recomputed. Rescanning and re-encoding the
   * whole buffer on every chunk is quadratic in the number of chunks, and an
   * upstream chooses the chunk size: one 900 KB event delivered 64 bytes at a
   * time costs seconds of CPU that way, under the cap, on one connection.
   *
   * Bytes rather than `String.length`, which counts UTF-16 units — for anything
   * outside ASCII that reads a byte cap as up to three times larger.
   */
  let scanned = 0;
  let bufferedBytes = 0;
  // The longest terminator is CRLF twice, so a boundary can straddle a chunk
  // edge by at most three characters. The scan steps back that far and no more.
  const OVERLAP = 3;

  const filterEvent = (block: string): string => {
    // Any of CRLF, LF or a bare CR ends a line (WHATWG server-sent events).
    const lines = block.split(/\r\n|\n|\r/);
    const data: string[] = [];
    const rest: string[] = [];
    for (const line of lines) {
      if (line.startsWith(':')) continue;
      const separator = line.indexOf(':');
      const field = separator === -1 ? line : line.slice(0, separator);
      if (field !== 'data') {
        if (line.length > 0) rest.push(line);
        continue;
      }
      const value = separator === -1 ? '' : line.slice(separator + 1);
      data.push(value.startsWith(' ') ? value.slice(1) : value);
    }
    if (data.length === 0) return block;

    let payload: unknown;
    try {
      payload = JSON.parse(data.join('\n'));
    } catch {
      return `event: message\ndata: ${JSON.stringify(
        unfilterableBody(`${method} carried an unreadable event`, id),
      )}`;
    }
    const filtered = transform(payload, data.join('\n'));
    if (filtered === payload) return block;
    const body = filtered ?? unfilterableBody(`${method} carried an unrecognisable event`, id);
    return [...rest, `data: ${JSON.stringify(body)}`].join('\n');
  };

  const drain = (controller: TransformStreamDefaultController<Uint8Array>): boolean => {
    for (;;) {
      const from = Math.max(0, scanned - OVERLAP);
      const found = EVENT_END.exec(buffered.slice(from));
      const at = found ? from + found.index : -1;
      // A trailing lone CR may be the first half of a CRLF still in flight, so
      // it waits for the next chunk rather than being read as an event's end.
      const incomplete = !found || (buffered.endsWith('\r') && at + found[0].length === buffered.length);
      if (incomplete) {
        scanned = buffered.length;
        return bufferedBytes <= maxEventBytes;
      }
      const block = buffered.slice(0, at);
      // Measured before the event is filtered, not after it is emitted. Checking
      // only the unterminated case makes the cap a question of how the transport
      // happened to split the stream, which is the upstream's choice to make.
      const blockBytes = encoder.encode(block).length;
      if (blockBytes > maxEventBytes) return false;
      const consumed = encoder.encode(buffered.slice(0, at + found[0].length)).length;
      buffered = buffered.slice(at + found[0].length);
      bufferedBytes -= consumed;
      scanned = 0;
      controller.enqueue(encoder.encode(filterEvent(block) + found[0]));
    }
  };

  const stream = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      let text = decoder.decode(chunk, { stream: true });
      if (!started) {
        started = true;
        // A stream may open with a byte-order mark. Left in place it becomes
        // part of the first field name, so `data:` stops looking like `data:`
        // and the event is passed through unread.
        if (text.startsWith('\uFEFF')) text = text.slice(1);
      }
      buffered += text;
      bufferedBytes += encoder.encode(text).length;
      if (drain(controller)) return;
      // An event with no end is an event this would have to hold entirely to
      // read. Refusing bounds what a broken or hostile upstream can spend here.
      controller.enqueue(
        encoder.encode(
          `event: message\ndata: ${JSON.stringify(
            unfilterableBody(`${method} sent an event over ${maxEventBytes} bytes`, id),
          )}\n\n`,
        ),
      );
      buffered = '';
      bufferedBytes = 0;
      controller.terminate();
    },
    flush(controller) {
      buffered += decoder.decode();
      if (buffered.trim().length === 0) return;
      controller.enqueue(
        encoder.encode(
          bufferedBytes > maxEventBytes
            ? `event: message\ndata: ${JSON.stringify(
                unfilterableBody(`${method} sent an event over ${maxEventBytes} bytes`, id),
              )}\n\n`
            : filterEvent(buffered),
        ),
      );
    },
  });

  return new Response(response.body?.pipeThrough(stream) ?? null, {
    status: response.status,
    headers: rewrittenHeaders(response, personal),
  });
}

/**
 * Headers for a body this rewrote. A personal one may be cached by the caller
 * alone, and validators the upstream computed over its own body would vouch
 * for bytes this did not send.
 */
function rewrittenHeaders(response: Response, personal: boolean): Headers {
  const headers = headersForRewrittenBody(response);
  headers.delete('etag');
  headers.delete('last-modified');
  headers.delete('expires');
  if (personal) headers.set('cache-control', 'private, no-store');
  return headers;
}

/**
 * Two line terminators, which is what ends an event.
 *
 * Each may independently be CRLF, LF or a bare CR, so the nine combinations all
 * count — an upstream is under no obligation to be consistent between the two.
 * A lone CR only counts when no LF follows, or a single CRLF would decompose
 * into two terminators and every line would look like the end of an event.
 */
const LINE_END = String.raw`(?:\r\n|\r(?!\n)|\n)`;
const EVENT_END = new RegExp(LINE_END + LINE_END);

/**
 * A refusal the client can match to what it asked.
 *
 * An error carrying `id: null` answers no pending request, so a client is
 * entitled to ignore it — and then waits on a listing that will never arrive for
 * as long as the stream stays open. The id comes from the request body this
 * already validated.
 */
function unfilterableBody(because: string, id: string | number | null = null): Record<string, unknown> {
  return {
    jsonrpc: '2.0',
    id,
    error: { code: -32_010, message: `Bad Gateway: this catalogue could not be filtered — ${because}.` },
  };
}

/** The JSON-RPC id of the request a route came from, when it carried one. */
function idOf(route: TrustedMcpRoute | undefined): string | number | null {
  const body = route?.body;
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return null;
  const id = (body as { id?: unknown }).id;
  return typeof id === 'string' || typeof id === 'number' ? id : null;
}

/**
 * A catalogue withheld.
 *
 * Absence from a listing is not the security boundary — naming a hidden
 * capability is still refused — but a listing served unfiltered hands every
 * caller the map, so an unreadable one fails closed rather than through.
 */
function unfilterable(because: string, id: string | number | null = null): Response {
  return Response.json(unfilterableBody(because, id), { status: 502 });
}

function toPermissionMap<P extends string>(
  permissions: Readonly<Record<string, P>> | ReadonlyMap<string, P>,
): Map<string, string> {
  if (permissions instanceof Map) return new Map(permissions);
  return new Map(Object.entries(permissions));
}

function validatePermissions(permissions: ReadonlyMap<string, string>): void {
  for (const [label, permission] of permissions) {
    if (!label || typeof label !== 'string') {
      throw new Error('permissions keys must be non-empty strings.');
    }
    if (!permission || typeof permission !== 'string') {
      throw new Error(`permissions['${label}'] must be a non-empty string.`);
    }
  }
}

function validateScopes(
  capabilityScopes: CapabilityScopeMap | undefined,
  permissions: ReadonlyMap<string, string>,
): void {
  if (!capabilityScopes) return;
  // `update_case` and `tool:update_case` are the same capability written two
  // ways. Only one of them wins the lookup, so accepting both means the other's
  // scope is silently never asked for — and the one that loses is as likely to
  // be the stricter.
  const named = new Set<string>();
  for (const key of Object.keys(capabilityScopes)) {
    const route = routeFromScopeKey(key);
    const canonical = `${route.kind}:${route.name}`;
    if (named.has(canonical)) {
      throw new Error(`Scope map names ${route.kind} '${route.name}' more than once.`);
    }
    named.add(canonical);
    const label = route.kind === 'tool' ? route.name : canonical;
    const has = permissions.has(label) || (route.kind === 'tool' && permissions.has(`tool:${route.name}`));
    if (!has) {
      throw new Error(`Scope map key '${key}' names no registered capability.`);
    }
  }
}

function routeFromScopeKey(key: string): { kind: 'tool' | 'prompt' | 'resource'; name: string } {
  for (const kind of ['tool', 'prompt', 'resource'] as const) {
    const prefix = `${kind}:`;
    if (key.startsWith(prefix)) return { kind, name: key.slice(prefix.length) };
  }
  return { kind: 'tool', name: key };
}
