import { McpServer, UriTemplate } from '@modelcontextprotocol/server';
import type {
  CallToolResult,
  GetPromptResult,
  Icon,
  Implementation,
  ReadResourceResult,
  ResourceMetadata,
  ResourceTemplate,
  StandardSchemaV1,
  StandardSchemaWithJSON,
  ToolAnnotations,
  ServerOptions as McpServerOptions,
} from '@modelcontextprotocol/server';
import type { PermissionCatalog, Policy, Principal } from './policy';

/**
 * Tools, prompts and resources that carry the permission they require.
 *
 * Declaring it here rather than in a separate rules file is the whole point: it
 * is checked against the policy by the compiler, reconciled against the policy
 * at boot, and it cannot drift when somebody renames the tool.
 *
 * MCP exposes three things a caller can reach, so gating only tools leaves two
 * doors open. All three register the same way: check the permission, skip the
 * registration when the caller lacks it, audit what they do reach.
 */

/** Which of the three a caller reached. */
export type Capability = 'tool' | 'prompt' | 'resource';

/** What actually happened, for the audit log the downstream API cannot write. */
export type AuditEvent = {
  issuer: string;
  sub: string;
  email?: string;
  kind: Capability;
  /** The registered name, e.g. `update_case`. */
  name: string;
  permission: string;
  /** Whatever the definition's own `audit` said the call touched, e.g. `case:C1234`. */
  resource?: string;
  decision: 'allow' | 'deny';
  phase: 'attempt' | 'success' | 'failure' | 'refused';
  /** Who approved it, when the capability asked for a second person. */
  approvedBy?: string;
  at: string;
  durationMs?: number;
  error?: string;
};

export type AuditSink = (event: AuditEvent) => unknown | Promise<unknown>;

export type AuditDeliveryFailure = {
  error: unknown;
  event: AuditEvent;
};

export type AuditErrorSink = (failure: AuditDeliveryFailure) => unknown | Promise<unknown>;

/**
 * What a human is being asked to approve, before it happens.
 *
 * Everything here was proved rather than claimed: the identity came off a
 * verified token and the permission was already checked, so the question left
 * for a person is only whether this particular call should happen.
 */
export type ApprovalRequest<A = unknown> = {
  issuer: string;
  sub: string;
  email?: string;
  kind: Capability;
  name: string;
  permission: string;
  /** The arguments the call would run with, so the message can name them. */
  arguments: A;
  /** Whatever the definition's own `audit` said the call touches. */
  resource?: string;
  at: string;
};

/**
 * Approving anonymously is not a second pair of eyes, so `by` is required on
 * the approving branch and the compiler will not let you omit it.
 */
export type ApprovalDecision =
  { approved: true; by: string; reason?: string } | { approved: false; by?: string; reason?: string };

export type ApprovalSink = (request: ApprovalRequest) => ApprovalDecision | Promise<ApprovalDecision>;

/** Thrown into the handler's place when a person said no, or said nothing in time. */
export class ApprovalRefusedError extends Error {
  readonly capability: string;
  readonly by?: string;

  constructor(capability: string, reason: string, by?: string) {
    super(`${capability} was not approved: ${reason}`);
    this.name = 'ApprovalRefusedError';
    this.capability = capability;
    this.by = by;
  }
}

type InferArgs<S> = S extends StandardSchemaV1<unknown, infer Output> ? Output : undefined;

/** Shared by all three: what it costs, and what the call touched. */
type Gated<P extends string, A> = {
  /** Required to reach it. Typed to the policy's permissions, so a typo is a build error. */
  permission: P;
  /**
   * Name the thing the call touched, for the audit event. The library cannot
   * know that `{ caseId: 'C1234' }` means a case; the application always does.
   */
  audit?: (args: A) => string | undefined;
  /**
   * Ask a person before this runs. `true` for every call, or a predicate when
   * only some arguments warrant it — a refund over a threshold, a delete that
   * names production.
   *
   * This is not the permission check repeated. The caller already holds the
   * permission; approval is for actions that want a second person anyway.
   */
  approval?: boolean | ((args: A) => boolean);
};

export type ToolConfig<P extends string, S> = Gated<P, InferArgs<S>> & {
  title?: string;
  description?: string;
  inputSchema?: S;
  outputSchema?: StandardSchemaWithJSON;
  annotations?: ToolAnnotations;
  icons?: Icon[];
};

export type PromptConfig<P extends string, S> = Gated<P, InferArgs<S>> & {
  title?: string;
  description?: string;
  argsSchema?: S;
  icons?: Icon[];
};

export type ResourceConfig<P extends string> = Gated<P, URL> &
  ResourceMetadata & {
    /** The URI clients read, or a template for a family of them. */
    uri: string | ResourceTemplate;
  };

/**
 * Erased once built, so a server registers every capability the same way
 * whatever it accepts.
 */
export type Definition<P extends string, C = Principal<P>> = {
  /**
   * Unique key for the boot-time check. Bare for a tool, prefixed otherwise, so
   * a prompt sharing a tool's name stays a separate entry rather than shadowing
   * it.
   */
  label: string;
  kind: Capability;
  /** Exact protocol name used to refuse an unpermitted direct invocation before scope step-up. */
  routeName?: string;
  routeMatches?: (name: string) => boolean;
  permission: P;
  /** Whether this definition can ask for a person, so boot can check a sink exists. */
  approval?: boolean;
  register: (server: McpServer, principal: Principal<P>, context: C, guards: Guards<unknown>) => void;
};

/** What every registration needs to record and, sometimes, to ask. */
export type Guards<A> = {
  onAudit?: AuditSink;
  onAuditError?: AuditErrorSink;
  onApproval?: ApprovalSink;
  approvalTimeoutMs: number;
  /** Present only when this capability declared one. */
  needsApproval?: (args: A) => boolean;
};

/**
 * Everything that wraps a permitted invocation, whatever kind it is, and
 * whether the capability was defined here or wrapped by `gate`.
 *
 * Recording and asking live together because they share one decision: what the
 * call touches. Splitting them would mean calling `audit(args)` twice and
 * hoping the two answers stayed the same.
 */
export function guarding<A>(
  kind: Capability,
  name: string,
  permission: string,
  audit: ((args: A) => string | undefined) | undefined,
  // Only who they are: `can` is contravariant in the permission union, and this
  // never asks it anything.
  principal: Pick<Principal, 'issuer' | 'sub' | 'email'>,
  guards: Guards<A>,
): <T>(args: A, run: () => T | Promise<T>) => Promise<T> {
  const { onAudit, onAuditError, onApproval, approvalTimeoutMs, needsApproval } = guards;

  return async (args, run) => {
    const asking = needsApproval?.(args) === true;
    if (!onAudit && !asking) return run();

    const started = performance.now();
    const resource = audit?.(args);
    const base = {
      issuer: principal.issuer,
      sub: principal.sub,
      email: principal.email,
      kind,
      name,
      permission,
      resource,
    };
    const now = () => new Date().toISOString();
    await onAudit?.({ ...base, decision: 'allow', phase: 'attempt', at: now() });

    let approvedBy: string | undefined;
    if (asking) {
      const decision = await decideWithin(
        () => onApproval!({ ...base, arguments: args, at: now() }),
        approvalTimeoutMs,
      );
      if (decision.approved && (typeof decision.by !== 'string' || decision.by.trim().length === 0)) {
        const reason = 'approval did not name who gave it';
        await deliverTerminalAudit(onAudit, onAuditError, {
          ...base,
          decision: 'deny',
          phase: 'refused',
          at: now(),
          durationMs: performance.now() - started,
          error: reason,
        });
        throw new ApprovalRefusedError(name, reason);
      }
      if (!decision.approved) {
        const reason = decision.reason ?? 'refused';
        await deliverTerminalAudit(onAudit, onAuditError, {
          ...base,
          decision: 'deny',
          phase: 'refused',
          approvedBy: decision.by,
          at: now(),
          durationMs: performance.now() - started,
          error: reason,
        });
        throw new ApprovalRefusedError(name, reason, decision.by);
      }
      approvedBy = decision.by;
    }

    try {
      const result = await run();
      await deliverTerminalAudit(onAudit, onAuditError, {
        ...base,
        decision: 'allow',
        phase: 'success',
        approvedBy,
        at: now(),
        durationMs: performance.now() - started,
      });
      return result;
    } catch (error) {
      await deliverTerminalAudit(onAudit, onAuditError, {
        ...base,
        decision: 'allow',
        phase: 'failure',
        approvedBy,
        at: now(),
        durationMs: performance.now() - started,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  };
}

async function deliverTerminalAudit(
  sink: AuditSink | undefined,
  onError: AuditErrorSink | undefined,
  event: AuditEvent,
): Promise<void> {
  try {
    await sink?.(event);
  } catch (error) {
    try {
      await onError?.({ error, event });
    } catch {
      // The handler returned or threw. An observer cannot change that result.
    }
  }
}

/**
 * Wait for a person, but not forever.
 *
 * The deadline is the whole reason this stays a library rather than a service:
 * the caller is still on the other end of an open request, so nothing has to
 * survive a restart — a process that dies mid-question takes the request with
 * it, and the action correctly did not happen.
 *
 * ponytail: blocking, in-memory, one process. Keep the deadline under the idle
 * timeout of whatever proxy sits in front, and reach for MCP progress
 * notifications (or a pending-ticket tool of your own) if you need longer.
 */
async function decideWithin(
  ask: () => ApprovalDecision | Promise<ApprovalDecision>,
  ms: number,
): Promise<ApprovalDecision> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expiry = new Promise<ApprovalDecision>((resolve) => {
    timer = setTimeout(() => resolve({ approved: false, reason: `no answer within ${ms}ms` }), ms);
  });
  try {
    return await Promise.race([Promise.resolve(ask()), expiry]);
  } catch (error) {
    // A sink that throws refuses, rather than letting the action through on the
    // strength of a Slack outage.
    return { approved: false, reason: error instanceof Error ? error.message : String(error) };
  } finally {
    clearTimeout(timer);
  }
}

function toolsFor<P extends string, C, H>(handlerContext: (context: C, principal: Principal<P>) => H) {
  return function tool<S extends StandardSchemaWithJSON | undefined = undefined>(
    name: string,
    config: ToolConfig<P, S>,
    handler: (args: InferArgs<S>, context: H) => CallToolResult | Promise<CallToolResult>,
  ): Definition<P, C> {
    const { permission, audit, approval, ...toolConfig } = config;

    return {
      label: name,
      kind: 'tool',
      routeName: name,
      permission,
      approval: Boolean(approval),
      register(server, principal, context, guards) {
        // Not registered rather than registered-and-refused: a tool you cannot
        // call should not appear in tools/list, and leaving it out is also the
        // only filtering code this needs.
        if (!principal.can(permission)) return;
        const record = guarding('tool', name, permission, audit, principal, {
          ...guards,
          needsApproval: approvalPredicate(approval),
        });

        server.registerTool(
          name,
          toolConfig as never,
          (async (args: InferArgs<S>) => {
            return record(args, () => handler(args, handlerContext(context, principal)));
          }) as never,
        );
      },
    };
  };
}

/**
 * Approval is decided per call, not per registration, because it turns on the
 * arguments — which is why it is the one check here that cannot be a decision
 * about whether to register something.
 */
export function approvalPredicate<A>(approval: boolean | ((args: A) => boolean) | undefined) {
  if (approval === undefined || approval === false) return undefined;
  return approval === true ? () => true : approval;
}

function promptsFor<P extends string, C, H>(handlerContext: (context: C, principal: Principal<P>) => H) {
  return function prompt<S extends StandardSchemaWithJSON | undefined = undefined>(
    name: string,
    config: PromptConfig<P, S>,
    handler: (args: InferArgs<S>, context: H) => GetPromptResult | Promise<GetPromptResult>,
  ): Definition<P, C> {
    const { permission, audit, approval, ...promptConfig } = config;

    return {
      label: `prompt:${name}`,
      kind: 'prompt',
      routeName: name,
      permission,
      approval: Boolean(approval),
      register(server, principal, context, guards) {
        if (!principal.can(permission)) return;
        const record = guarding('prompt', name, permission, audit, principal, {
          ...guards,
          needsApproval: approvalPredicate(approval),
        });

        server.registerPrompt(
          name,
          promptConfig as never,
          (async (args: InferArgs<S>) => {
            return record(args, () => handler(args, handlerContext(context, principal)));
          }) as never,
        );
      },
    };
  };
}

function resourcesFor<P extends string, C, H>(handlerContext: (context: C, principal: Principal<P>) => H) {
  return function resource(
    name: string,
    config: ResourceConfig<P>,
    handler: (uri: URL, context: H) => ReadResourceResult | Promise<ReadResourceResult>,
  ): Definition<P, C> {
    const { permission, audit, approval, uri, ...metadata } = config;
    const routeTemplate = typeof uri === 'string' ? new UriTemplate(uri) : uri.uriTemplate;

    return {
      label: `resource:${name}`,
      kind: 'resource',
      ...(typeof uri === 'string' ? { routeName: uri } : {}),
      routeMatches: (target) => routeTemplate.match(target) !== null,
      permission,
      approval: Boolean(approval),
      register(server, principal, context, guards) {
        if (!principal.can(permission)) return;
        const record = guarding('resource', name, permission, audit, principal, {
          ...guards,
          needsApproval: approvalPredicate(approval),
        });

        server.registerResource(
          name,
          uri as never,
          metadata as never,
          (async (target: URL) => {
            return record(target, () => handler(target, handlerContext(context, principal)));
          }) as never,
        );
      },
    };
  };
}

export type ServerOptions = Implementation & {
  /** Called on every permitted invocation. The one record tying a person to an action. */
  onAudit?: AuditSink;
  /** Receives a failed terminal audit write without changing the completed action's result. */
  onAuditError?: AuditErrorSink;
  /**
   * Ask a person. Awaited while the caller's request stays open, so this holds
   * a connection for as long as it takes to answer — required as soon as any
   * capability declares `approval`, and refused at boot when one does and this
   * is missing.
   */
  onApproval?: ApprovalSink;
  /**
   * How long to wait before treating silence as a refusal. Defaults to 45s,
   * which is under the 60s idle timeout most proxies ship with. Raise it only
   * as far as whatever sits in front of this server will actually hold.
   */
  approvalTimeoutMs?: number;
  /** Pass-through SDK options; declared gated capabilities are merged in. */
  mcp?: McpServerOptions;
};

/**
 * A per-request server factory over a fixed set of capabilities, plus the
 * label-to-permission map that `createMcpFetch` reconciles against the policy
 * at boot.
 */
type ServerFactory<C> = ((context: C) => McpServer) & {
  permissions: ReadonlyMap<string, string>;
  routePermissions: ReadonlyMap<string, string>;
  permissionForRoute: (kind: Capability, name: string) => string | undefined;
};

function buildServer<P extends string, C>(
  definitions: readonly Definition<P, C>[],
  options: ServerOptions,
  principalOf: (context: C) => Principal<P>,
): ServerFactory<C> {
  const permissions = new Map<string, string>();
  const routePermissions = new Map<string, string>();
  for (const definition of definitions) {
    if (permissions.has(definition.label)) {
      throw new Error(`'${definition.label}' is registered twice.`);
    }
    permissions.set(definition.label, definition.permission);
    if (definition.routeName !== undefined) {
      routePermissions.set(`${definition.kind}:${definition.routeName}`, definition.permission);
    }
  }

  // Asking nobody is not approving. A capability that wants a person and has no
  // way to reach one would otherwise refuse every call at run time, or worse,
  // depending on which way somebody defaulted it.
  const unaskable = definitions.filter((definition) => definition.approval).map((d) => d.label);
  if (unaskable.length > 0 && !options.onApproval) {
    throw new Error(
      `MCP approval is not configured\n\n` +
        `These capabilities ask for a person:\n${unaskable.map((label) => `  ${label}`).join('\n')}\n\n` +
        `Pass \`onApproval\` to server(), or drop \`approval\` from them.`,
    );
  }

  // Advertise what this server has, rather than all three every time. A client
  // seeing `prompts` and then an empty list has to ask to learn there is
  // nothing, and the answer never changes.
  const factory = (context: C): McpServer => {
    const principal = principalOf(context);
    const enabled = definitions.filter((definition) => principal.can(definition.permission));
    const declared = {
      ...(enabled.some((definition) => definition.kind === 'tool') ? { tools: {} } : {}),
      ...(enabled.some((definition) => definition.kind === 'prompt') ? { prompts: {} } : {}),
      ...(enabled.some((definition) => definition.kind === 'resource') ? { resources: {} } : {}),
    };
    const {
      onAudit,
      onAuditError,
      onApproval,
      approvalTimeoutMs = 45_000,
      mcp: mcpOptions = {},
      ...serverInfo
    } = options;
    const server = new McpServer(serverInfo, {
      ...mcpOptions,
      capabilities: { ...mcpOptions.capabilities, ...declared },
    });
    const guards = { onAudit, onAuditError, onApproval, approvalTimeoutMs };
    for (const definition of enabled) definition.register(server, principal, context, guards);
    return server;
  };

  return Object.assign(factory, {
    permissions: permissions as ReadonlyMap<string, string>,
    routePermissions: routePermissions as ReadonlyMap<string, string>,
    permissionForRoute: (kind: Capability, name: string) =>
      definitions.find(
        (definition) =>
          definition.kind === kind && (definition.routeMatches?.(name) ?? definition.routeName === name),
      )?.permission,
  });
}

/**
 * Everything bound to one policy: `permission` accepts only what that policy can
 * grant, in all four places, from one call.
 *
 * The policy is a type carrier here and is never invoked. Authorization happens
 * once per request when the principal is resolved, not once per definition.
 *
 * ```ts
 * const { tool, prompt, resource, server } = authz(policy);
 * ```
 */
function bindAuthz<P extends string, C, H>(
  _permissions: Policy<P> | PermissionCatalog<P>,
  principalOf: (context: C) => Principal<P>,
  handlerContext: (context: C, principal: Principal<P>) => H,
) {
  // Inferred rather than annotated: writing the return type out widens `P` back
  // to `string`, and a permission typo stops being a build error, which is the
  // one thing a library can do that a gateway cannot.
  return {
    tool: toolsFor<P, C, H>(handlerContext),
    prompt: promptsFor<P, C, H>(handlerContext),
    resource: resourcesFor<P, C, H>(handlerContext),
    server: (definitions: readonly Definition<P, C>[], options: ServerOptions) =>
      buildServer(definitions, options, principalOf),
  };
}

export function authz<P extends string>(
  policy: Policy<P> | PermissionCatalog<P>,
): ReturnType<typeof bindAuthz<P, Principal<P>, { principal: Principal<P> }>>;
export function authz<P extends string, C>(
  policy: Policy<P> | PermissionCatalog<P>,
  options: { principal: (context: C) => Principal<P> },
): ReturnType<typeof bindAuthz<P, C, C>>;
export function authz<P extends string, C>(
  policy: Policy<P> | PermissionCatalog<P>,
  options?: { principal: (context: C) => Principal<P> },
) {
  if (options) return bindAuthz(policy, options.principal, (context) => context);
  return bindAuthz(
    policy,
    (principal: Principal<P>) => principal,
    (_context, principal) => ({ principal }),
  );
}
