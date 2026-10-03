---
name: mcp-authz-wrap
description: >
  Use when a stdio MCP server exposes more tools than a model should reach:
  mcp-authz tools to save the catalogue, a JSONC allow list, wrap --config in
  the client entry, check and --refresh when the server changes.
metadata:
  type: core
  library: mcp-authz
  library_version: '0.2.0'
  sources:
    - 'jagreehal/mcp-authz:packages/mcp-authz/src/wrap.ts'
    - 'jagreehal/mcp-authz:packages/mcp-authz/src/wrap-config.ts'
    - 'jagreehal/mcp-authz:packages/mcp-authz/src/cli.ts'
---

# mcp-authz: `wrap` for a stdio server

`wrap` runs a stdio MCP server and shows the client only the tools in an allow
list. It needs no policy, no sign-in and no code change to the server.

## Setup

```bash
# Save the catalogue, and add the client entry to .mcp.json.
npx -y mcp-authz tools --out cases.jsonc --client-out .mcp.json -- npx -y @acme/cases-mcp
```

`cases.jsonc` lists every tool on its own line. Destructive tools start
commented out; uncomment a line to switch that tool on.

```jsonc
{
  "$schema": "./cases.schema.json",
  "server": { "command": "npx", "args": ["-y", "@acme/cases-mcp"], "cwd": "." },
  "allow": [
    "search_cases", // read-only · Find cases by text, label or owner.
    // "delete_case", // destructive · Remove a case and its history.
  ],
}
```

The client entry runs `npx -y mcp-authz wrap --config /abs/path/cases.jsonc`.
Credentials go in that entry's `env`, never in the JSONC file.

## Core Patterns

### Allow by exact name

`allow` lists the visible tools. A tool the server adds later stays hidden until
someone lists it. `deny` is the inverse and shows new tools, so prefer `allow`
for anything committed. There are no globs.

### Hints inform, names decide

The comment beside each tool carries the server's `readOnlyHint` or
`destructiveHint`, or `unknown`. `wrap` filters by name only; a hint picks the
starting comment state and nothing more.

### Upgrades

```bash
npx -y mcp-authz tools --check cases.jsonc          # exits 1 on drift
npx -y mcp-authz tools --config cases.jsonc --refresh
```

`--refresh` reruns the saved command in the saved `cwd`, keeps every choice,
and adds new tools commented out.

`tools --check`, `--refresh` and `wrap --config` all start the command the file
names. `mcp-authz check` reads files only and points a wrap config at
`tools --check`.

### What a hidden tool looks like

`tools/list` omits it. A `tools/call` naming it gets JSON-RPC error `-32602`,
`Tool "x" is blocked by mcp-authz wrap`, and the server never sees the call.
`wrap` also answers batches, unparseable lines and messages with a repeated key
itself, and forwards every other line byte for byte.

## Common Mistakes

### Treating `wrap` as a credential boundary

`wrap` limits one session. Any other program holding the same API key keeps
the key's full access. Scope the key where the service supports it.

### Relative paths in a client entry

Clients start servers from their own working directory. Use the absolute path
`tools` prints for `--config`; `server.cwd` in the JSONC file resolves relative
to the file itself.

### Different tools for different people

`wrap` has no caller identity. For per-person access, use `gate()` or
`authz()` with a policy; the tool names carry over.
