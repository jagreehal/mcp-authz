---
'mcp-authz': minor
---

Read the capability list off your own server, instead of maintaining it by hand.

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
