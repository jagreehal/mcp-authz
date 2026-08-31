import type { Identity } from './identity';

// The input to every policy, re-exported so `mcp-authz/policy` is usable
// without reaching back into the MCP half of the package.
export type { Identity } from './identity';

/**
 * Permissions are the authorization primitive. Roles are only a convenient name
 * for a set of them, which is why nothing downstream ever asks what role
 * somebody holds.
 *
 * Nothing in this file imports MCP: an identity in, a principal out. The same
 * policy gates any tool-calling surface, and MCP is one of them.
 */

export type Principal<P extends string = string> = {
  issuer: string;
  /** Stable subject from the token. Prefer it to email for anything durable. */
  sub: string;
  email?: string;
  domain?: string;
  roles: string[];
  permissions: string[];
  /** A method rather than an array check because it honours a `*` grant. */
  can: (permission: P) => boolean;
};

/** Everything a rule can match on. All present fields must match. */
export type Match = {
  issuer?: string;
  sub?: string;
  email?: string;
  domain?: string;
  /**
   * A claim name, or a dotted path into a nested one (`org.id`). A namespaced
   * name containing dots is matched literally first, so Auth0's
   * `https://acme.com/groups` works as written. A scalar claim must equal the
   * value; an array claim must contain it, which is how group lists match.
   */
  claim?: Record<string, string>;
};

export type Rule<R extends string = string> = {
  /** Omit to match every authenticated caller. */
  match?: Match;
  role?: R | readonly R[];
  /** Matched by a deny rule and the principal gets nothing, whatever else says. */
  deny?: boolean;
};

export type PolicySpec = {
  /**
   * Optional source-of-truth permission catalogue. Required for a policy whose
   * roles grant only `*`; otherwise TypeScript has no literal names to infer.
   */
  permissions?: readonly string[];
  roles: Record<string, readonly string[]>;
  rules: readonly Rule[];
};

/** One rule that matched, pointed back at the line an administrator edits. */
export type MatchedRule = {
  /** Index into the policy's own `rules` array. */
  index: number;
  match: Match;
  roles: string[];
  deny: boolean;
};

/**
 * Why a principal came out the way it did.
 *
 * The decision alone answers "may Alice do this". It cannot answer "why", and
 * that is the question asked when somebody is surprised. Deriving it a second
 * time somewhere else would be a second matcher to keep in step, so it lives
 * here beside the first one.
 */
export type Explanation<P extends string = string> = {
  principal: Principal<P>;
  /** Every matching rule, in policy order. Empty means no rule matched. */
  matched: MatchedRule[];
  /** The deny that emptied the grant, when one did. */
  deniedBy?: MatchedRule;
};

export type Policy<P extends string = string> = ((identity: Identity) => Principal<P>) & {
  /** Role name to the permissions it grants. Reconciled against the tools at boot. */
  readonly roles: ReadonlyMap<string, readonly string[]>;
  /** Concrete permission vocabulary carried for builders and diagnostics. */
  readonly permissions: readonly P[];
  /**
   * The same decision, plus the rules that produced it. Off the request path:
   * nothing in the gate calls this, so it costs a served request nothing.
   */
  readonly explain: (identity: Identity) => Explanation<P>;
};

export type PermissionCatalog<P extends string = string> = {
  readonly permissions: readonly P[];
};

/** The permissions a policy can grant, as a union of string literals. */
export type PermissionOf<T> = T extends Policy<infer P> ? P : never;

type RolesIn<T extends PolicySpec> = keyof T['roles'] & string;
type PermissionsIn<T extends PolicySpec> = T extends { readonly permissions: readonly string[] }
  ? T['permissions'][number]
  : Exclude<T['roles'][keyof T['roles']][number], '*'>;

/**
 * A policy from a plain object.
 *
 * Written inline as a literal, the permission names become a string-literal
 * union, so a tool requiring `cases:wrtie` fails to compile. Handed
 * `JSON.parse(process.env.MCP_POLICY)` or a parsed YAML file the same call
 * still validates its shape and still reconciles against the tools at boot —
 * it just cannot type-check names TypeScript never sees. Nothing here reads the
 * environment or the filesystem: how an application loads configuration is the
 * application's business.
 *
 * There is deliberately no `default` setting. Matching no rule means no
 * permissions, and that is not configurable — a default that can be widened
 * eventually is, and the failure is silent.
 */
export function definePolicy<const T extends PolicySpec>(
  spec: T & { rules: readonly Rule<RolesIn<T>>[] },
): Policy<PermissionsIn<T>> {
  if (!isRecord(spec)) throw new Error('Policy must be an object.');
  for (const key of Object.keys(spec)) {
    if (!['permissions', 'roles', 'rules'].includes(key))
      throw new Error(`Policy has unknown field '${key}'.`);
  }
  if (!isRecord(spec.roles)) throw new Error("Policy 'roles' must be an object.");
  if (!Array.isArray(spec.rules)) throw new Error("Policy 'rules' must be an array.");

  const catalogue =
    spec.permissions === undefined ? undefined : stringList(spec.permissions, "Policy 'permissions'");
  if (catalogue?.includes('*'))
    throw new Error("Policy 'permissions' must name concrete permissions, not '*'.");
  const known = catalogue ? new Set(catalogue) : undefined;

  const roles = new Map<string, readonly string[]>();
  for (const [role, permissions] of Object.entries(spec.roles ?? {})) {
    if (!role) throw new Error('Policy role names must not be empty.');
    const validated = stringList(permissions, `Policy role '${role}'`);
    if (validated.includes('*') && validated.length > 1) {
      throw new Error(`Policy role '${role}' grants '*' and must not list redundant permissions.`);
    }
    for (const permission of validated) {
      if (permission !== '*' && known && !known.has(permission)) {
        throw new Error(
          `Policy role '${role}' grants '${permission}', which is absent from the permission catalogue.`,
        );
      }
    }
    roles.set(role, validated);
  }

  // Validated once here rather than per request, so a malformed policy fails on
  // boot instead of quietly refusing one person on a Tuesday.
  const rules = (spec.rules ?? []).map((rule, index) => {
    const at = `Policy rule ${index}`;
    if (!isRecord(rule)) throw new Error(`${at} must be an object.`);
    for (const key of Object.keys(rule)) {
      if (!['match', 'role', 'deny'].includes(key)) throw new Error(`${at} has unknown field '${key}'.`);
    }
    if (rule.deny !== undefined && typeof rule.deny !== 'boolean') {
      throw new Error(`${at} 'deny' must be a boolean.`);
    }
    if (!rule.deny && rule.role === undefined) {
      throw new Error(`${at} grants nothing: it needs a 'role' or 'deny: true'.`);
    }
    const named = roleNames(rule.role, at);
    for (const role of named) {
      if (!roles.has(role)) throw new Error(`${at} names role '${role}', which is not defined.`);
    }
    return { index, match: validateMatch(rule.match, at), deny: rule.deny === true, roles: named };
  });

  // One evaluation, two callers. `explain` reading a second implementation is
  // how the answer starts disagreeing with the decision.
  const evaluate = (identity: Identity) => {
    const matched = rules.filter((rule) => matches(rule.match, identity));
    const deniedBy = matched.find((rule) => rule.deny);

    const held = deniedBy ? [] : [...new Set(matched.flatMap((rule) => rule.roles))];
    const permissions = deniedBy ? [] : [...new Set(held.flatMap((role) => [...(roles.get(role) ?? [])]))];
    return { matched, deniedBy, principal: createPrincipal(identity, held, permissions) };
  };

  const policy = (identity: Identity): Principal<PermissionsIn<T>> => evaluate(identity).principal;

  const explain = (identity: Identity): Explanation<PermissionsIn<T>> => {
    const { matched, deniedBy, principal } = evaluate(identity);
    return {
      principal,
      matched: matched.map(toMatchedRule),
      ...(deniedBy ? { deniedBy: toMatchedRule(deniedBy) } : {}),
    };
  };

  const concrete = catalogue ?? [
    ...new Set([...roles.values()].flat().filter((permission) => permission !== '*')),
  ];
  return Object.assign(policy, {
    roles: roles as ReadonlyMap<string, readonly string[]>,
    permissions: concrete as PermissionsIn<T>[],
    explain,
  });
}

function toMatchedRule(rule: { index: number; match: Match; deny: boolean; roles: string[] }): MatchedRule {
  return { index: rule.index, match: rule.match, roles: [...rule.roles], deny: rule.deny };
}

/** A typed permission vocabulary for async authorizers that do not use a static policy. */
export function definePermissions<const P extends readonly string[]>(
  permissions: P,
): PermissionCatalog<P[number]> {
  const catalogue = stringList(permissions, 'Permission catalogue');
  if (catalogue.includes('*')) {
    throw new Error("Permission catalogue must name concrete permissions, not '*'.");
  }
  return { permissions: catalogue as P[number][] };
}

/** Build a sound principal from an external entitlement decision. */
export function createPrincipal<P extends string>(
  identity: Identity,
  roles: readonly string[],
  permissions: readonly (P | '*')[],
): Principal<P> {
  if (!isRecord(identity) || typeof identity.sub !== 'string' || identity.sub.length === 0) {
    throw new Error('Principal identity needs a non-empty subject.');
  }
  if (typeof identity.issuer !== 'string' || identity.issuer.length === 0) {
    throw new Error('Principal identity needs a non-empty issuer.');
  }
  if (identity.email !== undefined && identity.email.length === 0) {
    throw new Error('Principal identity email must not be empty.');
  }
  const heldRoles = [...new Set(stringList(roles, 'Principal roles'))];
  const heldPermissions = [...new Set(stringList(permissions, 'Principal permissions') as (P | '*')[])];
  const wildcard = heldPermissions.includes('*');
  return {
    issuer: identity.issuer,
    sub: identity.sub,
    email: identity.email,
    domain: identity.domain,
    roles: heldRoles,
    permissions: heldPermissions,
    can: (permission) => wildcard || heldPermissions.includes(permission),
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringList(value: unknown, at: string): string[] {
  if (!Array.isArray(value)) throw new Error(`${at} must be an array of permission strings.`);
  const result: string[] = [];
  for (const entry of value) {
    if (typeof entry !== 'string' || entry.length === 0) {
      throw new Error(`${at} must be an array of non-empty permission strings.`);
    }
    // Deduplicated rather than refused. Everything downstream is a set, so a
    // repeat changes nothing, and failing the boot over it punishes a policy
    // assembled from JSON where a harmless repeat is somebody else's problem.
    if (!result.includes(entry)) result.push(entry);
  }
  return result;
}

function roleNames(value: unknown, at: string): string[] {
  if (value === undefined) return [];
  const values = Array.isArray(value) ? value : [value];
  if (values.length === 0 || values.some((role) => typeof role !== 'string' || role.length === 0)) {
    throw new Error(`${at} 'role' must be a non-empty role name or array of role names.`);
  }
  return [...new Set(values as string[])];
}

function validateMatch(value: unknown, at: string): Match {
  if (value === undefined) return {};
  if (!isRecord(value)) throw new Error(`${at} 'match' must be an object.`);
  for (const key of Object.keys(value)) {
    if (!['issuer', 'sub', 'email', 'domain', 'claim'].includes(key)) {
      throw new Error(`${at} match has unknown field '${key}'.`);
    }
  }
  for (const key of ['issuer', 'sub', 'email', 'domain'] as const) {
    const field = value[key];
    if (field !== undefined && (typeof field !== 'string' || field.length === 0)) {
      throw new Error(`${at} match '${key}' must be a non-empty string.`);
    }
  }
  const claim = value.claim;
  if (claim !== undefined) {
    if (!isRecord(claim)) throw new Error(`${at} match 'claim' must be an object.`);
    for (const [path, expected] of Object.entries(claim)) {
      if (!path || typeof expected !== 'string' || !expected) {
        throw new Error(`${at} match claim entries must have non-empty string names and values.`);
      }
    }
  }
  return value as Match;
}

function matches(match: Match, identity: Identity): boolean {
  if (match.issuer !== undefined && match.issuer !== identity.issuer) return false;
  if (match.sub !== undefined && match.sub !== identity.sub) return false;
  if (match.email !== undefined && (!identity.emailVerified || !equalsFold(match.email, identity.email))) {
    return false;
  }
  if (match.domain !== undefined && !equalsFold(match.domain, domainOf(identity))) return false;

  for (const [path, expected] of Object.entries(match.claim ?? {})) {
    const actual = claimAt(identity.claims, path);
    const ok = Array.isArray(actual) ? actual.includes(expected) : actual === expected;
    if (!ok) return false;
  }
  return true;
}

function equalsFold(a: string, b: string | undefined): boolean {
  return b !== undefined && a.toLowerCase() === b.toLowerCase();
}

/** The `hd` claim when the AS passes it, otherwise whatever follows the `@`. */
function domainOf(identity: Identity): string | undefined {
  if (!identity.emailVerified || !identity.email) return undefined;
  if (identity.domain) return identity.domain;
  const at = identity.email.lastIndexOf('@');
  return at === -1 ? undefined : identity.email.slice(at + 1);
}

/**
 * A literal claim name wins over a dotted path, because the namespaced claims
 * an IdP actually emits are full of dots — Auth0 writes group memberships to
 * `https://acme.com/groups`, and splitting that on `.` finds nothing.
 */
function claimAt(claims: Identity['claims'], path: string): unknown {
  if (path in claims) return claims[path];

  let value: unknown = claims;
  for (const key of path.split('.')) {
    if (typeof value !== 'object' || value === null) return undefined;
    value = (value as Record<string, unknown>)[key];
  }
  return value;
}

export type Drift = {
  /** A capability no role can reach. Fatal: it is dead code that looks live. */
  error?: string;
  /**
   * A permission no capability requires. A warning rather than a failure, because
   * granting a role ahead of the tool that uses it is how a staged rollout
   * works, and failing the boot on it just teaches people to add dummy tools.
   */
  warning?: string;
};

/**
 * Compare what the tools demand against what the roles grant.
 *
 * A gateway cannot run this check at all — it does not learn the tool list
 * until traffic arrives, and its rules were never compiled alongside the
 * implementation.
 */
export function reconcile(
  roles: ReadonlyMap<string, readonly string[]>,
  required: ReadonlyMap<string, string>,
): Drift {
  const grantedBy = new Map<string, string[]>();
  for (const [role, permissions] of roles) {
    for (const permission of permissions) {
      grantedBy.set(permission, [...(grantedBy.get(permission) ?? []), role]);
    }
  }
  const wildcard = grantedBy.has('*');

  const unreachable = wildcard ? [] : [...required].filter(([, permission]) => !grantedBy.has(permission));
  const unused = [...grantedBy]
    .filter(([permission]) => permission !== '*')
    .filter(([permission]) => ![...required.values()].includes(permission));

  const drift: Drift = {};

  if (unreachable.length > 0) {
    const report = ['MCP policy validation failed', '', 'Unreachable capability:'];
    for (const [tool, permission] of unreachable) {
      report.push(`  ${tool}`, `    requires: ${permission}`, '    granted by: no role', '');
    }
    drift.error = report.join('\n');
  }

  if (unused.length > 0) {
    const report = ['MCP policy has unused permissions:'];
    for (const [permission, byRoles] of unused) {
      const by = byRoles.map((role) => `"${role}"`).join(', ');
      report.push(
        `  ${permission}`,
        `    granted by: ${by}`,
        '    required by: no registered capability',
        '',
      );
    }
    drift.warning = report.join('\n');
  }

  return drift;
}
