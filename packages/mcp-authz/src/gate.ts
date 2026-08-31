import type { McpServer } from '@modelcontextprotocol/server';
import type { Principal } from './policy';
import {
  approvalPredicate,
  guarding,
  type ApprovalSink,
  type AuditErrorSink,
  type AuditSink,
  type Capability,
} from './tools';

/**
 * Gate a server somebody else builds.
 *
 * `authz(policy)` is for tools you write. This is for the ones you already
 * have: an MCP server from another package, or one you are not ready to change,
 * whose tools were never declared with a permission.
 *
 * It cannot read a built server's tool list — the SDK keeps that private, and
 * no library can filter what it never saw. So this wraps the server *before*
 * registration and gates each call as it happens, which needs one hook from
 * whoever builds it:
 *
 * ```ts
 * // in their builder
 * const server = options.wrap ? options.wrap(new McpServer(info, opts)) : new McpServer(info, opts);
 *
 * // in your connector
 * buildServer(config, { wrap: (server) => gate(server, principal, PERMISSIONS) })
 * ```
 *
 * Unpermitted registrations are registered and immediately disabled rather than
 * skipped, so the caller still gets the handle its own code expects, and the
 * SDK does the list-filtering and the refusal.
 */

export type GateOptions = {
  /** Same event as `authz`, for tools this package did not define. */
  onAudit?: AuditSink;
  /** Receives a failed terminal audit write without changing the completed action's result. */
  onAuditError?: AuditErrorSink;
  /**
   * Name the thing a call touched, keyed by the same label as `permissions`.
   * Their tool, your domain knowledge.
   */
  audit?: Readonly<Record<string, (args: never) => string | undefined>>;
  /**
   * Ask a person before one of their tools runs, keyed by the same label. The
   * one thing worth adding to somebody else's destructive tool without touching
   * their code.
   */
  approval?: Readonly<Record<string, boolean | ((args: never) => boolean)>>;
  /** Awaited human decision. Required when `approval` names anything. */
  onApproval?: ApprovalSink;
  /** Silence is a refusal after this long. Defaults to 45s, as in `authz`. */
  approvalTimeoutMs?: number;
};

/** Bare name for a tool, `prompt:`/`resource:` prefixed for the rest. */
export type PermissionMap<P extends string> = Readonly<Record<string, P>> | ReadonlyMap<string, P>;

export function gate<P extends string>(
  server: McpServer,
  principal: Principal<P>,
  permissions: PermissionMap<P>,
  options: GateOptions = {},
): McpServer {
  const required = isMapLike<P>(permissions)
    ? new Map(permissions)
    : new Map(Object.entries(permissions as Record<string, P>));

  const wrap = (kind: Capability, register: (...args: never[]) => unknown) =>
    function gated(this: unknown, ...args: unknown[]) {
      const name = String(args[0]);
      const label = kind === 'tool' ? name : `${kind}:${name}`;
      const permission = required.get(label);

      if (permission === undefined) {
        // Deny by default, loudly. Dropping it silently is how a tool nobody
        // priced ends up reachable by everyone, or by nobody, with no error.
        throw new Error(
          `gate(): no permission declared for ${kind} '${name}'. ` +
            `Add '${label}' to the permission map, or stop registering it.`,
        );
      }

      const approval = options.approval?.[label] as boolean | ((args: unknown) => boolean) | undefined;
      if (approval && !options.onApproval) {
        throw new Error(`gate(): ${kind} '${name}' asks for approval, but no 'onApproval' was passed.`);
      }

      // The handler is the last argument for all three register methods.
      const last = args.length - 1;
      const handler = args[last];
      if ((options.onAudit || approval) && typeof handler === 'function') {
        // The same wrapper `authz` capabilities use, so a gated tool and a
        // defined one cannot emit subtly different events or ask differently.
        const record = guarding<unknown>(
          kind,
          name,
          permission,
          options.audit?.[label] as ((args: unknown) => string | undefined) | undefined,
          principal,
          {
            onAudit: options.onAudit,
            onAuditError: options.onAuditError,
            onApproval: options.onApproval,
            approvalTimeoutMs: options.approvalTimeoutMs ?? 45_000,
            needsApproval: approvalPredicate(approval),
          },
        );
        const inner = handler as (...called: unknown[]) => unknown;
        args[last] = async function guarded(this: unknown, ...called: unknown[]) {
          return record(called[0], () => inner.apply(this, called));
        };
      }

      const registered = register.apply(server, args as never[]) as { disable?: () => void };
      if (!principal.can(permission)) {
        if (typeof registered?.disable !== 'function') {
          throw new Error(`gate(): SDK registration for ${kind} '${name}' cannot be disabled safely.`);
        }
        registered.disable();
      }
      return registered;
    };

  const gatedMethods: Record<string, unknown> = {
    registerTool: wrap('tool', server.registerTool as never),
    registerPrompt: wrap('prompt', server.registerPrompt as never),
    registerResource: wrap('resource', server.registerResource as never),
  };

  return new Proxy(server, {
    get(target, property) {
      const gatedMethod = gatedMethods[property as string];
      if (gatedMethod) return gatedMethod;
      // Read off the target and bind to it: a class with private fields throws
      // if its methods run with the proxy as `this`.
      const value = target[property as keyof McpServer];
      return typeof value === 'function' ? (value as (...a: unknown[]) => unknown).bind(target) : value;
    },
  });
}

function isMapLike<P extends string>(value: PermissionMap<P>): value is ReadonlyMap<string, P> {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as ReadonlyMap<string, P>).get === 'function' &&
    Symbol.iterator in value
  );
}
