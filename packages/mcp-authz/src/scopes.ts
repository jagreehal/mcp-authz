/**
 * Helpers for deriving required OAuth scopes from Streamable HTTP headers
 * (SEP-2243). Use with `createMcpFetch({ scopesForRequest })`.
 */

export type ScopeRequirement = string | readonly string[];
export type ToolScopeMap = Readonly<Record<string, ScopeRequirement>>;
export type CapabilityScopeMap = ToolScopeMap;

const BASE64_SENTINEL = /^=\?base64\?([A-Za-z0-9+/]*(?:={0,2}))\?=$/;
const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * Tools use their bare name (or `tool:name`); prompts use `prompt:name`; and
 * resources use `resource:<uri>`. Everything else needs only the baseline.
 */
export function scopesFromMcpHeaders(request: Request, toolScopes: ToolScopeMap, baseline = 'mcp'): string[] {
  const method = request.headers.get('mcp-method');
  const rawName = request.headers.get('mcp-name');
  const name = rawName === null ? undefined : decodeMcpNameHeader(rawName);
  return scopesForCapability(method ?? undefined, name, toolScopes, baseline);
}

/** Select scopes from an already validated MCP method/name pair. */
export function scopesForCapability(
  method: string | undefined,
  name: string | undefined,
  capabilityScopes: CapabilityScopeMap,
  baseline = 'mcp',
): string[] {
  if (!name) return [baseline];
  const key =
    method === 'tools/call'
      ? capabilityScopes[name] === undefined
        ? `tool:${name}`
        : name
      : method === 'prompts/get'
        ? `prompt:${name}`
        : method === 'resources/read'
          ? `resource:${name}`
          : undefined;
  const required = (key ? capabilityScopes[key] : undefined) ?? baseline;
  return typeof required === 'string' ? [required] : [...required];
}

/** Decode SEP-2243's optional Base64 sentinel without accepting non-canonical input. */
export function decodeMcpNameHeader(value: string): string | undefined {
  const normalized = value.trim();
  if (!normalized.startsWith('=?base64?') || !normalized.endsWith('?=')) return normalized;
  const match = BASE64_SENTINEL.exec(normalized);
  const encoded = match?.[1];
  if (encoded === undefined || !CANONICAL_BASE64.test(encoded)) return undefined;
  try {
    const binary = atob(encoded);
    const bytes = Uint8Array.from(binary, (character) => character.codePointAt(0) ?? 0);
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  }
}
