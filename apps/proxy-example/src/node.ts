#!/usr/bin/env node
import { listenMcp } from 'mcp-authz/node';
import { proxyFromEnv } from './proxy';

const port = Number(process.env.PORT ?? 8300);
const fetch = proxyFromEnv(process.env);

await listenMcp(fetch, {
  port,
  name: 'mcp-authz-proxy-example',
  info: {
    mode: 'proxy',
    resource: process.env.MCP_PUBLIC_URL,
    upstream: process.env.UPSTREAM_URL,
    issuer: process.env.OAUTH_ISSUER,
  },
});
