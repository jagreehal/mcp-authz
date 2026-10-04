# Test server

A case-tracker MCP server that misbehaves when you ask it to, so you can watch
`mcp-authz wrap`, `createMcpProxy` and `gate()` deal with it in a real client.

It offers `search_cases`, `get_case`, `count_cases`, `update_case`,
`transfer_credit`, `delete_case` and a large `run_query`. `transfer_credit`
caps `amount` at 2^53, where JavaScript stops holding integers exactly, and
`get_account`'s `outputSchema` caps `accountId` there too. `search_cases` takes a `query` of at most
200 characters, and `count_cases` answers with structured output held to an
`outputSchema` (`{ count: integer }`). `delete_case` claims to be both read-only and destructive, as a
dishonest server might. Every call prints `ran <tool>` on stderr, so you can see
what reached it.

It also has two prompts, `triage` and `payroll_report`, each with an argument a
client can ask to complete, and four resources:

| Resource  | Address             | Notes                                                |
| --------- | ------------------- | ---------------------------------------------------- |
| `cases`   | `cases://all`       | every case                                           |
| `case`    | `cases://case/{id}` | one case                                             |
| `secrets` | `secret://{+rest}`  | a broad template that serves any secret, payroll too |
| `payroll` | `secret://payroll`  | the exact resource meant to be the stricter way in   |

`secrets` and `payroll` both cover `secret://payroll`, which is where pricing
one registration and serving another would leak.

| Env                       | What the server does                                                                                                                                                  |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `RUG_PULL=1`              | `search_cases` starts out rewritten to tell the model to read an SSH key                                                                                              |
| `RUG_PULL_AFTER=30`       | rewrites it 30 seconds in and sends `list_changed`                                                                                                                    |
| `INSTRUCTIONS_RUG_PULL=1` | the instructions say to ignore previous ones and call `export_cases`                                                                                                  |
| `POISONED=1`              | adds `lookup_customer`, with a zero-width space and a hidden instruction                                                                                              |
| `BAD_OUTPUT=1`            | `count_cases` answers with structured output its `outputSchema` forbids                                                                                               |
| `INJECTED_OUTPUT=1`       | `get_case`'s answer carries an instruction aimed at the model                                                                                                         |
| `INJECTED_RESOURCE=1`     | `get_case`'s answer embeds a resource whose text carries one instead                                                                                                  |
| `BIG_NUMBERS=1`           | `get_account` reports `accountId` 9007199254740993 against a maximum of ...992, and every tool answer's `_meta` carries `1.0000000000000001` and `9007199254740993e0` |
| `NO_STRUCTURED=1`         | `count_cases` leaves out the structured output its `outputSchema` promises                                                                                            |
| `EXTRA_TOOL=1`            | adds `export_cases`, as if the server had been upgraded                                                                                                               |
| `TOKEN=secret`            | over HTTP, requires `Authorization: Bearer secret`                                                                                                                    |

The commands below run from the repository root.

## Under `wrap` (stdio)

```bash
SERVER="npx tsx $PWD/apps/test-server/src/server.ts"

# Save the tools. Only count_cases, get_case and search_cases start switched on:
# lookup_customer is flagged, and delete_case's destructive claim wins.
POISONED=1 npx tsx packages/mcp-authz/src/cli.ts tools --out /tmp/test.jsonc -- $SERVER

# A rug pull between sessions: check shows the old and new text.
POISONED=1 RUG_PULL=1 npx tsx packages/mcp-authz/src/cli.ts tools --check /tmp/test.jsonc

# Rewritten instructions: check shows ~ server instructions, and wrap removes them.
POISONED=1 INSTRUCTIONS_RUG_PULL=1 npx tsx packages/mcp-authz/src/cli.ts tools --check /tmp/test.jsonc

# An upgrade: export_cases arrives switched off.
EXTRA_TOOL=1 npx tsx packages/mcp-authz/src/cli.ts tools --refresh /tmp/test.jsonc
```

To try it in a client, add the entry `tools --out` printed, with
`"env": { "RUG_PULL_AFTER": "60" }`. List the tools, wait a minute, and list
them again: `search_cases` is gone, and the client's server log says why. Call
it after the minute without listing, and `wrap` checks it first and refuses.

## Behind `createMcpProxy` (HTTP)

```bash
PORT=8400 TOKEN=svc pnpm --filter mcp-authz-test-server http

npx tsx packages/mcp-authz/src/cli.ts record \
  --upstream http://127.0.0.1:8400/mcp --token svc --out /tmp/permissions.ts
```

Point [proxy-example](../proxy-example) at it with `UPSTREAM_URL` and
`UPSTREAM_TOKEN=svc`. Restart the server with `RUG_PULL=1`, or start it with
`RUG_PULL_AFTER`, and `search_cases` drops out of the proxy's listings, and a
call to it is refused. Run `record --check` to see what changed:

```bash
npx tsx packages/mcp-authz/src/cli.ts record \
  --upstream http://127.0.0.1:8400/mcp --token svc --check /tmp/permissions.ts
```

The proxy speaks MCP 2026-07-28 only, so the client you point at it must too.

## Around `gate()` (in process)

`build(wrap)` takes the hook `gate()` needs, since it has to see each
registration as it happens:

```ts
import { createMcpFetch, gate } from 'mcp-authz';
import { build } from './src/server';

createMcpFetch({
  // …
  createServer: (principal) => build((server) => gate(server, principal, PERMISSIONS)).server,
});
```

## The attack suite

`src/attacks.test.ts` runs each attack against this server, through the built CLI, `wrap` over stdio, `createMcpProxy` over HTTP and
`gate()` in process. It runs the built CLI, so build the package first:

```bash
pnpm --filter mcp-authz build
pnpm --filter mcp-authz-test-server test
```

| Attack                     | What the suite shows                                                                                                                                                                                             |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hints as approval          | `tools --out` switches on only `count_cases`, `get_case` and `search_cases`; `delete_case`, which claims both, starts commented out as destructive                                                               |
| Overlapping resources      | A read of `secret://payroll` by a reader is refused by the proxy, and `gate()` does not serve it from the broad template                                                                                         |
| Methods nobody priced      | The proxy prices `completion/complete` and `subscriptions/listen` as what they reach, answers a GET with 405, and refuses an unknown method                                                                      |
| Calling without listing    | `wrap` and the proxy refuse a call to a rewritten tool made before any listing; `wrap` re-checks after `list_changed`                                                                                            |
| Running without a record   | `wrap` refuses to start when the schema beside the config is missing                                                                                                                                             |
| Rewritten instructions     | `wrap` and the proxy remove them; `tools --check` shows `~ server instructions`                                                                                                                                  |
| Shared caches              | A proxy listing carries `cacheScope: "private"` and `Cache-Control: private, no-store`                                                                                                                           |
| Repeated JSON keys         | The proxy refuses a `tools/call` body that names two tools under one key                                                                                                                                         |
| `record --check` gaps      | It fails on a rewritten description and on a `DEFINITIONS` with a gap                                                                                                                                            |
| Arguments refused          | `wrap` (-32602) and the proxy (400) refuse a `search_cases` query over 200 characters before the server runs                                                                                                     |
| Output withheld            | With `BAD_OUTPUT` or `NO_STRUCTURED`, `count_cases`'s answer is replaced by an `isError` result saying it broke the approved `outputSchema`                                                                      |
| Output flagged             | With `INJECTED_OUTPUT` or `INJECTED_RESOURCE`, `get_case`'s answer arrives whole, after a `⚠ mcp-authz` notice to treat it as data                                                                               |
| Numbers checked as written | `transfer_credit` with 9007199254740993 or 9007199254740993e0 is refused, not checked rounded; under `BIG_NUMBERS`, `get_account` is withheld and the `_meta` numbers reach the client as written, notice or not |
| Indirect scopes            | The proxy holds `completion/complete` and `subscriptions/listen` to the scopes of what they reach, with an `insufficient_scope` challenge                                                                        |
