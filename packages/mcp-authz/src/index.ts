export { discoverOAuth, type DiscoverOptions } from './discovery';
export { gate, type GateOptions, type PermissionMap } from './gate';
export {
  createMcpFetch,
  type AuthorizationDecisionEvent,
  type AuthorizationDecisionSink,
  type McpFetchOptions,
} from './handler';
export { AccessDeniedError, type DenialReason, type Identity } from './identity';
export {
  definePolicy,
  definePermissions,
  createPrincipal,
  reconcile,
  type Explanation,
  type Match,
  type MatchedRule,
  type PermissionOf,
  type PermissionCatalog,
  type Policy,
  type PolicySpec,
  type Principal,
  type Rule,
} from './policy';
export {
  scopesFromMcpHeaders,
  scopesForCapability,
  decodeMcpNameHeader,
  type CapabilityScopeMap,
  type ScopeRequirement,
  type ToolScopeMap,
} from './scopes';
export type { TrustedMcpRoute } from './routing';
export {
  authz,
  ApprovalRefusedError,
  type ApprovalDecision,
  type ApprovalRequest,
  type ApprovalSink,
  type AuditEvent,
  type AuditDeliveryFailure,
  type AuditErrorSink,
  type AuditSink,
  type Capability,
  type Definition,
  type PromptConfig,
  type ResourceConfig,
  type ServerOptions,
  type ToolConfig,
} from './tools';
export { identityFromAuth, jwksVerifier, type VerifierOptions } from './verifier';
