#!/usr/bin/env node
import { listenMcp } from 'mcp-authz/node';
import { proxyFromEnv } from './proxy';

await listenMcp(proxyFromEnv(process.env), {
  port: Number(process.env.PORT ?? 8500),
  name: 'mcp-authz-login-example',
  info: {
    mode: 'proxy',
    provider: process.env.PROVIDER,
    resource: process.env.MCP_PUBLIC_URL,
    upstream: process.env.UPSTREAM_URL,
  },
});
