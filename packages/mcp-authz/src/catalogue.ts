import { capabilityLabel } from './ladder';
import type { Principal } from './policy';

type Named = { name: string };

function filterByPermission<T extends Named, P extends string>(
  items: readonly T[],
  kind: 'tool' | 'prompt' | 'resource',
  principal: Principal<P>,
  permissions: ReadonlyMap<string, string>,
): T[] {
  return items.filter((item) => {
    const label = capabilityLabel(kind, item.name);
    const permission = permissions.get(label);
    if (permission === undefined) return false;
    return principal.can(permission as P);
  });
}

export function filterToolsList<T extends Named, P extends string>(
  tools: readonly T[],
  principal: Principal<P>,
  permissions: ReadonlyMap<string, string>,
): T[] {
  return filterByPermission(tools, 'tool', principal, permissions);
}

export function filterPromptsList<T extends Named, P extends string>(
  prompts: readonly T[],
  principal: Principal<P>,
  permissions: ReadonlyMap<string, string>,
): T[] {
  return filterByPermission(prompts, 'prompt', principal, permissions);
}

export function filterResourcesList<T extends Named, P extends string>(
  resources: readonly T[],
  principal: Principal<P>,
  permissions: ReadonlyMap<string, string>,
): T[] {
  return filterByPermission(resources, 'resource', principal, permissions);
}

export function filterResourceTemplatesList<T extends Named, P extends string>(
  templates: readonly T[],
  principal: Principal<P>,
  permissions: ReadonlyMap<string, string>,
): T[] {
  return filterByPermission(templates, 'resource', principal, permissions);
}

const LISTING_FIELDS = {
  'tools/list': 'tools',
  'prompts/list': 'prompts',
  'resources/list': 'resources',
  'resources/templates/list': 'resourceTemplates',
} as const;

type ListingMethod = keyof typeof LISTING_FIELDS;

export function isListingMethod(method: string | undefined): method is ListingMethod {
  return method !== undefined && Object.hasOwn(LISTING_FIELDS, method);
}

export function isInvocationMethod(method: string | undefined): boolean {
  return method === 'tools/call' || method === 'prompts/get' || method === 'resources/read';
}

export function filterListingResult<P extends string>(
  method: ListingMethod,
  result: Record<string, unknown>,
  principal: Principal<P>,
  permissions: ReadonlyMap<string, string>,
): Record<string, unknown> {
  const field = LISTING_FIELDS[method];
  const items = result[field];
  if (!Array.isArray(items)) return result;

  const filtered =
    field === 'tools'
      ? filterToolsList(items as Named[], principal, permissions)
      : field === 'prompts'
        ? filterPromptsList(items as Named[], principal, permissions)
        : field === 'resources'
          ? filterResourcesList(items as Named[], principal, permissions)
          : filterResourceTemplatesList(items as Named[], principal, permissions);

  return { ...result, [field]: filtered };
}
