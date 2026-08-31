#!/usr/bin/env node
import { listenMcp } from 'mcp-authz/node';
import { devAuthEnv, withDevAuth } from './dev-auth';
import { mcpFromEnv } from './mcp';

const port = Number(process.env.PORT ?? 8200);
const devAuth = process.env.MCP_DEV_AUTH === '1';

// Dev defaults fill in only what nobody set, so a real .env still wins.
const env = devAuth ? { ...devAuthEnv(port), ...process.env } : process.env;

const fetch = devAuth ? withDevAuth(mcpFromEnv(env), port) : mcpFromEnv(env);

await listenMcp(fetch, {
  port,
  name: 'mcp-authz-node-example',
  info: {
    resource: env.MCP_PUBLIC_URL,
    issuer: env.OAUTH_ISSUER,
    ...(devAuth ? { auth: 'DEV — tokens minted locally, not a real login' } : {}),
  },
});
