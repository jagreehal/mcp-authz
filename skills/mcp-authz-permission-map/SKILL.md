---
name: mcp-authz-permission-map
description: >
  Use when building or maintaining an mcp-authz permission map: recordCapabilities,
  recordUpstream, toPermissionsModule, the mcp-authz record and check CLI, and
  catching an upstream that changes underneath you.
metadata:
  type: core
  library: mcp-authz
  library_version: '0.1.0'
  sources:
    - 'jagreehal/mcp-authz:packages/mcp-authz/src/testing.ts'
    - 'jagreehal/mcp-authz:packages/mcp-authz/src/cli.ts'
---

# mcp-authz — record → price → check

A permission map has to name every capability a server registers. Do not type it
twice; read it off the server.

## Setup

```bash
# A server you build, from a module whose default export returns it
npx mcp-authz record ./connector.ts --out src/permissions.ts

# A server you can only reach by URL, with a service credential
npx mcp-authz record --upstream https://vendor.example/mcp --token "$TOKEN" --out src/permissions.ts
```

Or from a test, which is where the drift check belongs:

```ts
import { recordCapabilities } from 'mcp-authz/testing';

const { names, fingerprints } = await recordCapabilities(() => buildServer(TEST_CONFIG));

expect(names).toEqual(Object.keys(PERMISSIONS).sort());
expect(fingerprints).toMatchSnapshot();
```

`@modelcontextprotocol/client` is an optional peer, needed only by this subpath
and the `record` command.

## Core Patterns

### Build the server ungated

A gated server answers per principal, so recording one hands you a map missing
exactly the capabilities that most need a price. `recordCapabilities` connects a
real client over an in-memory pair and asks — the answer is the one a caller
gets. `recordUpstream` does the same over HTTP; a service credential is shown
everything, so that map is complete too.

### The generated module

```ts
export const PERMISSIONS = {
  get_case: 'TODO:unassigned',
  'prompt:triage': 'TODO:unassigned',
  'resource:case': 'TODO:unassigned',
} as const;

export type Permission = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

export const FINGERPRINTS = { get_case: '9f2c…' } as const;
export const RESOURCE_URIS = { 'resource:case': 'cases://case/{id}' } as const;
```

Every capability is priced `TODO:unassigned`, which no role grants, so
reconciliation calls it unreachable and the boot refuses until a person decides
what each one costs. Generate once; after that it is source you edit, not an
artefact you regenerate.

`FINGERPRINTS` is separate because `gate()` takes the flat map and CI needs a
baseline it can compare. `RESOURCE_URIS` appears only when the server has
resources, and only `createMcpProxy` needs it.

### Drift, in CI

```bash
npx mcp-authz record --upstream https://vendor.example/mcp --token "$TOKEN" --check src/permissions.ts
```

Exits non-zero and says what moved:

```text
The server no longer matches the recorded capabilities:

  + update_case
      never priced, so nobody decided who may reach it
  ~ get_case
      same name, different definition than the one recorded
```

`~` is the one `gate()` cannot catch for you. It already throws at boot on a
capability with no permission, which covers a dependency adding a tool. It
cannot see a tool that keeps its name and changes underneath — a description
carrying injected instructions, or an input schema widened to accept more under
a permission you already granted. Fingerprints digest the whole definition as
served, so that lands as a diff on a pull request.

## Common Mistakes

### CRITICAL Seeding permissions from tool annotations

Wrong:

```ts
const permission = tool.annotations?.readOnlyHint ? 'cases:read' : 'cases:write';
```

The MCP specification is explicit that annotations are hints, not guarantees,
and that clients should never make tool-use decisions from annotations on an
untrusted server. Seeding a permission from one lets the server being priced
decide its own access level. That is why nothing is guessed and every entry
starts unassigned.

Source: packages/mcp-authz/src/testing.ts

### HIGH Enforcing fingerprints at boot

Wrong:

```ts
if (digest(liveTool) !== FINGERPRINTS.get_case) throw new Error('drift');
```

A digest shipped to production is a second source of truth, and turns a
description edit into an outage. The snapshot or `--check` is the gate; your
lockfile pins what runs.

Source: packages/mcp-authz/src/testing.ts

### MEDIUM Committing a map with no FINGERPRINTS and assuming --check is complete

A map recorded before fingerprints existed compares names only. `--check` says
so rather than passing quietly:

```text
— src/permissions.ts carries no FINGERPRINTS, so definitions were not compared; re-record to add one
```

Re-record to get a baseline.

Source: packages/mcp-authz/src/cli.ts

See also: mcp-authz-gate/SKILL.md — the map's main consumer
See also: mcp-authz-proxy/SKILL.md — needs RESOURCE_URIS as well
