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
import { filterListingResult, isInvocationMethod, isListingMethod } from './catalogue';
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
    ): AsyncResult<TrustedMcpRoute | undefined, Response> => {
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
        resolveCapabilityScopes: (route) => {
          if (route.method !== 'resources/read' || !route.name || !capabilityScopes) return undefined;
          const labels = resources.filter((entry) => entry.matches(route.name!)).map((e) => e.label);
          if (labels.length === 0) return undefined;
          return [
            ...new Set(
              labels.flatMap((label) =>
                scopesForCapability(
                  route.method,
                  label.slice('resource:'.length),
                  capabilityScopes,
                  requiredScopes[0] ?? 'mcp',
                ),
              ),
            ),
          ];
        },
        resolvePermission: (route) => permissionForFlatMap(permissions, route, resources, can),
        onDecision: options.onDecision,
        resourceMetadataUrl,
      });
      return result.ok ? ok(result.preflight?.route) : err(result.response);
    },

    /** Refuse an invocation nobody priced, so a new upstream tool inherits nothing. */
    price: async (
      principal: Principal<P>,
      route: TrustedMcpRoute | undefined,
    ): AsyncResult<undefined, Response> => {
      const denied = await denyUnpricedInvocation({
        principal,
        permissions,
        resources,
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
      route: TrustedMcpRoute | undefined,
      principal: Principal<P>,
    ): AsyncResult<Response, Response> => {
      const method = route?.method;
      if (!isListingMethod(method)) return ok(response);
      if (isEventStream(response)) {
        return ok(
          filterEventStreamListing(response, method, principal, permissions, maxRequestBytes, idOf(route)),
        );
      }
      if (isJsonResponse(response)) {
        const filtered = await filterJsonListing(response, method, principal, permissions, maxRequestBytes);
        return filtered
          ? ok(filtered)
          : err(
              unfilterable(
                `${method} was over ${maxRequestBytes} bytes or not readable as JSON-RPC`,
                idOf(route),
              ),
            );
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
 * Refuse any invocation the permission map does not price.
 *
 * `runScopedGate` refuses a capability the caller may not reach. This refuses
 * one nobody priced at all, which in a proxy is the more common shape: the
 * upstream grew a tool since the map was recorded, and an unpriced tool must
 * fail closed rather than inherit the service credential.
 */
async function denyUnpricedInvocation<P extends string>(options: {
  principal: Principal<P>;
  permissions: ReadonlyMap<string, string>;
  resources: ResourceIndex;
  route?: TrustedMcpRoute;
  onDecision?: AuthorizationDecisionSink;
  emitter?: string;
}): Promise<Response | undefined> {
  const { route, principal, emitter } = options;
  if (!route || !isInvocationMethod(route.method)) return undefined;

  const refuse = async (because: string): Promise<Response> => {
    await emitDecision(options.onDecision, principal, 'deny', 'policy_denied', emitter);
    return policyDenied(AccessDeniedError.notPermitted(principalLabel(principal), because));
  };

  // An invocation that names nothing cannot be priced, so it cannot be allowed.
  if (!route.name) return refuse(`a ${route.method} that names no capability`);

  const permission = permissionForFlatMap(options.permissions, route, options.resources, (candidate) =>
    principal.can(candidate as P),
  );
  if (permission === undefined) {
    return refuse(`the capability '${route.name}' is not priced in the permission map`);
  }
  if (!principal.can(permission as P)) return refuse(`the permission '${permission}'`);
  return undefined;
}

/**
 * Match each priced `resource:` label to the URIs it covers.
 *
 * Exact URIs are tried before templates, so a resource registered at its own
 * address is never answered by a template that happens to span it.
 */
function buildResourceIndex(
  permissions: ReadonlyMap<string, string>,
  resourceUris: Readonly<Record<string, string>> | undefined,
): ResourceIndex {
  const exact: { label: string; permission: string; matches: (uri: string) => boolean }[] = [];
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
      templated.push({ label, permission, matches: (target) => template.match(target) !== null });
    } else {
      exact.push({ label, permission, matches: (target) => target === uri });
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
async function filterJsonListing<P extends string>(
  response: Response,
  method: Parameters<typeof filterListingResult>[0],
  principal: Principal<P>,
  permissions: ReadonlyMap<string, string>,
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
  const filtered = filterMessage(payload, method, principal, permissions);
  if (filtered === undefined) return undefined;
  return Response.json(filtered, { status: response.status, headers: headersForRewrittenBody(response) });
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
): unknown | undefined {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return undefined;
  const message = payload as Record<string, unknown>;
  if (!('result' in message)) return 'error' in message || 'method' in message ? message : undefined;
  const result = message.result;
  if (typeof result !== 'object' || result === null) return undefined;
  return {
    ...message,
    result: filterListingResult(method, result as Record<string, unknown>, principal, permissions),
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
function filterEventStreamListing<P extends string>(
  response: Response,
  method: Parameters<typeof filterListingResult>[0],
  principal: Principal<P>,
  permissions: ReadonlyMap<string, string>,
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
    const filtered = filterMessage(payload, method, principal, permissions);
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
    headers: headersForRewrittenBody(response),
  });
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
