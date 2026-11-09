import { wrapModule } from 'autotel-cloudflare';
import { proxyFromEnv } from './proxy';

/**
 * Built once per isolate, not once per request.
 *
 * `createMcpProxy` validates the permission map and reconciles it against the
 * policy on the way up, and the JWKS it verifies against is cached inside the
 * verifier it returns. Rebuilding per request would redo both, and re-fetch
 * signing keys for every call.
 */
let proxy: ((request: Request) => Promise<Response>) | undefined;

export default wrapModule(
  {
    service: { name: 'mcp-authz-proxy-example' },
    nativeTracing: 'auto',
  },
  {
    fetch(request: Request, env: Record<string, string | undefined>): Promise<Response> {
      proxy ??= proxyFromEnv(env);
      return proxy(request);
    },
  },
);
