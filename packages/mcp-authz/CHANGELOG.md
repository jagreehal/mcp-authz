# mcp-authz

## 0.4.0

### Minor Changes

- 37ab42c: Add `mcp-authz wrap`, which runs a stdio MCP server and shows the client only the tools you choose. `mcp-authz tools --out` saves a server's tools as a commented config with an editor schema, `tools --check` reports what changed on the server, and `tools --refresh` records it with your choices kept. `@modelcontextprotocol/client` is now a dependency, so every command runs from `npx`.

## 0.3.0

### Minor Changes

- 111c593: `verifier.requireEmail: false` accepts a token with no email, such as an agent's OAuth client-credentials token. The caller's identity is its `sub`, which a policy rule names. Email and domain rules never match it.

## 0.2.0

### Minor Changes

- 9b0cf40: Human approval for permitted actions, policy explain and a CLI, plus security and audit fixes.

  **Approval.** A capability can declare `approval: true`, or a predicate over its
  arguments, and the call waits for a person before it runs. Pass `onApproval` to
  `server()` (or to `gate()`, for tools you did not write) and return
  `{ approved: true, by }`. The approving branch will not compile without a name,
  an approval that arrives naming nobody is refused at runtime as well, and that
  name lands on the `success` audit event beside the caller's. Silence is
  a refusal after `approvalTimeoutMs` (45s by default), as is an `onApproval` that
  throws. Nothing is stored: the caller is still on an open request, so a process
  that dies mid-question takes the request with it.

  **Explain a decision, and inspect a policy from a terminal.**
  `policy.explain(identity)` returns the principal alongside every rule that
  matched, each with its index in your own `rules` array, plus the deny that
  emptied the grant when one did. It shares the single matcher with the decision,
  so an explanation cannot disagree with what the gate did. Nothing on the request
  path calls it.

  The package now ships an `mcp-authz` binary over the same engine:

  - `mcp-authz explain policy.json --identity alice.json` prints the derivation.
  - `mcp-authz check policy.json --capabilities caps.json` runs the same
    `reconcile` the server runs at boot, so a capability no role can reach fails
    the pull request rather than the deploy.

  No new dependencies: `node:util` parses the arguments.

  **The body is no longer read before authentication.** Per-capability scopes are
  checked against the token the request already carries, not by the bearer gate, so
  the read that names the capability now happens after it. An unauthenticated
  caller can no longer make this process parse anything, and `maxRequestBytes` now
  bounds an authenticated caller rather than anyone who can reach the port.

  **An unpermitted call is refused the same way with or without scopes.** Naming an
  unregistered capability now answers `403 forbidden / policy_denied` and reaches
  `onDecision`, instead of falling through to the SDK's unknown-capability error
  with nothing written to the log.

  **Identities without an email no longer fail with a 500.** `Principal.email` is
  optional everywhere else, but the gate demanded one, so any opaque-token or
  introspection identity carrying only a subject was rejected as an invalid
  principal.

  **Audit and construction.** Keep a completed capability result when its terminal
  audit write fails, and send the delivery failure to the new `onAuditError` hook.
  Attempt-audit failures still stop the handler before it runs.

  Validate declarative OAuth scope maps during construction. Unknown capability
  keys, duplicate tool aliases, missing baselines, empty requirements, and invalid
  scope tokens now fail before the server accepts traffic.

  Python-only, so no npm package moves. Recorded here because the fix crosses both
  implementations.

  `gate()` now exists in Python: a permission map over an `MCPServer` somebody
  else builds, given one wrap hook in their builder. Unpriced registrations raise,
  unpermitted tools and prompts are removed after registration, and unpermitted
  resources are never registered at all.

  `asyncio.wait_for` raises `asyncio.TimeoutError`, which before Python 3.11 is
  not the builtin `TimeoutError`. Catching the builtin meant a silent approver on
  3.10 was reported as an unnamed error rather than a missed deadline, and the
  suite failed there. Both implementations now share one `request_approval`, so
  the refusal has one shape and one place to fix.

  An approver renders the arguments it is handed into a Slack message or a ticket,
  which means serialising them. The SDK's injected `Context` holds the open
  session, so it is dropped before the request is built.

- e6037bc: Gate an HTTP API by `operationId`, and give the audit trail a shape a log store can query.

  **`mcp-authz/openapi`.** An OpenAPI document is the other catalogue an agent
  reads, so the bet `gate()` makes works there too: `createOpenApiFetch` serves the
  document filtered to each caller, and checks the request whether or not they ever
  read it. `recordOperations(spec)` builds the permission map from the document —
  no running server, no introspection — and `toPermissionsModule` prices every
  operation `TODO:unassigned` so the boot refuses until somebody decides what each
  one costs. Construction fails on an unpriced operation, on an entry naming an
  operation the document no longer has, and on a permission no role grants. A route
  the document does not describe is refused with a 404 that says so. It is its own
  entry point: the MCP handler, its route classification and its scope step-up stay
  out of an OpenAPI-only bundle.

  **Events say what they are.** `onAudit` and `onDecision` now emit
  `mcp_authz.audit.v1` and `mcp_authz.decision.v1`. Each carries its own `type`, so
  the two can share a store and still be told apart; a new optional field does not
  move the version, and changing what an existing field means does.

  Three fields join the audit event for whoever reads it later. `callId` is the
  same on both events of one call and different for every other, so an attempt and
  its outcome can be joined without guessing from timestamps. `domain` is the
  verified Workspace domain, the nearest thing to an organisation this can prove —
  key one by `(issuer, domain)`. `emitter` names the deployment, set it the same in
  every entry point and a reader can tell which server a call reached. `kind` now
  spans `operation` alongside `tool`, `prompt` and `resource`, so one query covers
  both surfaces of a product.

  `conformance/v1/audit/events.json` pins the type strings and the key sets, and
  both language packages read it.

  **Python reaches the same surface.** `mcp_authz` gains `on_audit`,
  `on_audit_error` and `on_decision` on `AuthorizedMCPServer` and `gate`, emitting
  the events above with the same JSON keys through `event.to_dict()`.
  `mcp_authz.openapi` and `mcp_authz.proxy` are ASGI equivalents of the TypeScript
  entry points, sharing the policy, the boot-time checks and the events.

- 145ef27: Add `mcp-authz/proxy`: enforce OAuth and RBAC in front of an MCP server you can
  only reach by URL.

  `createMcpProxy` verifies each caller's token, runs your policy, filters
  catalogue listings to what they may reach, and forwards permitted calls with a
  service credential. It shares the request ladder with `createMcpFetch` and is
  stricter where a proxy has to be, because nothing downstream re-checks anything
  and the credential it forwards on outranks the caller: routing headers that
  disagree with the body are refused rather than forwarded, a request without them
  is authorized from the JSON-RPC body, an unpriced capability is refused, and a
  listing it cannot read is withheld instead of passed through. The caller's
  `Authorization` and `Cookie` stay at the edge.

  `resources/read` is priced by URI rather than by label, since that is what the
  request carries, so `recordCapabilities` now emits a `RESOURCE_URIS` map beside
  `PERMISSIONS` and the proxy refuses to boot without one for every priced
  resource.

  Also fixes a step-up scope that never fired for resources reached through a URI
  template, in `createMcpFetch` and `gate()` as well as the proxy. `capabilityScopes`
  is keyed by the resource as registered — `resource:cases://case/{id}` — while a
  read carries one concrete URI, and the two were compared as strings, so a
  baseline-only token could reach a resource priced for step-up.

- 145ef27: Read the capability list off your own server, instead of maintaining it by hand.

  `check --capabilities` has always taken a map somebody typed. Nothing produced
  it, so the map drifted from the server quietly, and the failure mode is the bad
  one: a capability nobody priced.

  `mcp-authz/testing` exports `recordCapabilities`, which builds your server,
  connects a client to it over an in-memory pair, and returns every capability the
  way `gate()` labels them — bare name for a tool, `prompt:` and `resource:` for
  the rest, resource templates included.

  ```ts
  import { recordCapabilities } from 'mcp-authz/testing';

  const { names, fingerprints } = await recordCapabilities(() => buildServer(TEST_CONFIG));

  expect(names).toEqual(Object.keys(PERMISSIONS).sort());
  expect(fingerprints).toMatchSnapshot();
  ```

  `toPermissionsModule(record)` renders the starting map as TypeScript source —
  `as const` with the derived permission type, so `gate()` infers its union and a
  typo is a build error. Every capability is priced `'TODO:unassigned'`, which no
  role grants, so `reconcile` calls it unreachable and the boot refuses until a
  person decides what each capability costs. A default would make that decision
  for them, quietly.

  Build the server **ungated** there. A gated server answers per principal, so
  listing one hands you a map missing exactly the capabilities that most need a
  price.

  The second line is the part `gate()` cannot do for you. It already throws at
  boot on a capability with no permission, which covers a dependency that adds a
  tool. It cannot see a tool that keeps its name and changes underneath — a
  description carrying injected instructions, or an input schema widened to accept
  more under a permission you already granted. `fingerprints` digests each
  capability's whole definition as served — a tool's input schema, a prompt's
  arguments, a resource template's URI — so that change fails a snapshot on the
  pull request rather than shipping.

  Nothing is enforced at boot: a digest shipped to production is a second source of
  truth that turns a description edit into an outage. The snapshot is the gate, and
  your lockfile pins what runs.

  `@modelcontextprotocol/client` is an optional peer, needed only by this subpath.

  A CLI command for connector maintainers who would rather not write the test
  scaffolding by hand:

  ```bash
  npx mcp-authz record ./connector.ts --out src/permissions.ts
  ```

  It imports the module, calls its default export to build the server, and writes
  the same map. `mcp-authz/testing` is loaded lazily, so the other commands keep
  the CLI's no-dependency property and only `record` asks you to install the
  client.

  `recordUpstream(url, { bearer })` records a server you can only reach by URL, in
  the same labels `gate()` uses, so one map serves either enforcement location:

  ```bash
  npx mcp-authz record --upstream https://vendor.example/mcp --token $SERVICE_TOKEN
  ```

  The objection that rules out listing a gated server does not apply upstream: a
  service credential is shown everything, so the map is complete. Fingerprints
  matter more here than anywhere — an upstream you do not control can change its
  capability surface underneath you, and this is what turns that into a diff.

### Patch Changes

- 8947f18: Add a Help Scout example for an org agent that presents a static bearer. A
  custom `tokenVerifier` checks the key, the policy grants `helpscout:read`, and
  the server lists the Mailbox tools once you set their credentials. The
  `mcp-authz-authz` skill and the docs show the pattern.
- 22c4ca3: Update `@modelcontextprotocol/server` to 2.1, `awaitly` to 6.2 and `jose` to 6.2.12.
