#!/usr/bin/env node
import { listenMcp } from 'mcp-authz/node';
import { mcpFromEnv } from './mcp';

const port = Number(process.env.PORT ?? 8400);

await listenMcp(mcpFromEnv(), {
  port,
  name: 'mcp-authz-helpscout-example',
  info: { resource: process.env.MCP_PUBLIC_URL, auth: 'static bearer' },
});
