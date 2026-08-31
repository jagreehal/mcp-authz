#!/usr/bin/env node
import { mintToken } from './dev-auth';

/**
 * Print a bearer token for the MCP Inspector.
 *
 *   pnpm token dana@acme.com                  reader  (domain rule)
 *   pnpm token alice@acme.com                 editor  (named rule)
 *   pnpm token sam@other.com                  nobody  — expect HTTP 403
 *   pnpm token dana@acme.com --scope mcp      reader, but no `write` scope
 */

const [email, ...rest] = process.argv.slice(2);
if (!email) {
  console.error('usage: pnpm token <email> [--scope "mcp write"] [--group qa-leads]');
  process.exit(1);
}

const flag = (name: string) => {
  const at = rest.indexOf(`--${name}`);
  return at === -1 ? undefined : rest[at + 1];
};

const group = flag('group');

console.log(
  await mintToken({
    email,
    port: Number(process.env.PORT ?? 8200),
    scope: flag('scope'),
    claims: group ? { 'https://acme.com/groups': [group] } : undefined,
  }),
);
