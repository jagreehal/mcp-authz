# User Stories

## src/e2e.story.test.ts

### A published server somebody else wrote, gated per person

### ✅ gives a reader a catalogue that stops at what she may do

Tags: `e2e`, `gate`

- **Given** case-tracker 3.2.0, a server this library did not write

  > The fixture is deliberately not a stub with one tool on it. It registers all four kinds of capability, because the three that are not tools are the ones deployments forget to gate.
  > **What the package registers**

  ```json
  {
    "tools": ["search_cases", "get_case", "update_case"],
    "prompts": ["triage"],
    "resources": ["cases"],
    "resourceTemplates": ["case"]
  }
  ```

- **And** a permission map that puts a price on every one of them

  > gate() throws on a registration it cannot find here, so a partial map fails the boot.
  > **Permission map**

  ```json
  {
    "search_cases": "cases:read",
    "get_case": "cases:read",
    "update_case": "cases:write",
    "close_run": "cases:write",
    "prompt:triage": "cases:read",
    "resource:cases": "cases:read",
    "resource:case": "cases:read"
  }
  ```

- **And** Dana, whom the policy makes a reader
  > Her token is signed by the test issuer and verified against a real JWKS, like any other.
  - **label:** Grants
  - **value:** cases:read
- **When** she connects with a real MCP client and lists all four kinds

  > A real Client on a real Streamable HTTP transport, whose fetch is the handler. Framing, negotiation, SSE and the bearer header are the genuine article; no port is bound.
  > **Catalogue**

    <details>
    <summary>snapshot</summary>

  ```json
  {
    "tools": ["get_case", "search_cases"],
    "prompts": ["triage"],
    "resources": ["cases"],
    "resourceTemplates": ["case"]
  }
  ```

    </details>

- **Then** the two read tools are there, and the write tool is not
- **And** the prompt, the resource and the template she may read all survive the gate
- **And** what she can see, she can actually run
  **get_case C1**

  ```text
  case C1
  ```

### ✅ refuses the write tool even when the client names it without listing

Tags: `e2e`, `gate`, `security`

- **Given** the same reader, and a client that skips tools/list entirely
  > Absence from the catalogue is a context saving, not a security boundary. A model that guessed the name, or a malicious client that read the docs, never consults the list.
- **When** she calls update_case by name
  **What the client got back**

  ```text
  Tool update_case disabled
  ```

- **Then** the server refuses it, so the hidden entry was never what protected the write

### ✅ widens the same catalogue for a lead, from the same server

Tags: `e2e`, `gate`

- **Given** one handler, one permission map, two people
  > Nothing about the server changes between these two connections. The only difference is which token arrives, which is the whole claim this library makes.
- **When** the reader connects
  **Catalogue**

    <details>
    <summary>snapshot</summary>

  ```json
  {
    "tools": ["get_case", "search_cases"],
    "prompts": ["triage"],
    "resources": ["cases"],
    "resourceTemplates": ["case"]
  }
  ```

    </details>

- **And** the lead connects to the very same handler
  **Catalogue**
  - - tools[2]: "update_case"

    <details>
    <summary>snapshot</summary>

  ```json
  {
    "tools": ["get_case", "search_cases", "update_case"],
    "prompts": ["triage"],
    "resources": ["cases"],
    "resourceTemplates": ["case"]
  }
  ```

    </details>

- **Then** update_case has appeared, and nothing else has
- **And** it runs, so the extra grant is real and not a listing artefact

### ✅ gates a capability the server only registers on some deployments

Tags: `e2e`, `gate`

- **Given** the same package with its optional close_run tool switched on
  > A real server registers a different catalogue per configuration — a feature flag, a licence tier, an env var. The map prices every branch, so turning one on cannot quietly widen what a reader sees.
- **When** the reader and the lead each list tools
  **Who sees the optional tool**

  | Caller        | Tools                                          |
  | ------------- | ---------------------------------------------- |
  | Dana (reader) | get_case, search_cases                         |
  | Alice (lead)  | close_run, get_case, search_cases, update_case |

- **Then** the reader does not see it
- **And** the lead does, because the map priced it as a write

### The same guarantees on the seam you own

### ✅ presents an authz-defined server identically to a real client

Tags: `authz`, `e2e`

- **Given** the same policy, over tools you declared rather than wrapped
  > gate() is for code you cannot change; authz() is for code you wrote. This checks the two seams are indistinguishable from outside — the choice is about whose source you can reach, not about how strong the result is.
- **When** the same reader lists tools against it
  **Catalogue**

    <details>
    <summary>snapshot</summary>

  ```json
  {
    "tools": ["get_case"]
  }
  ```

    </details>

- **Then** she sees exactly what the gated server showed her
- **And** and the write tool is refused here too

### A client from before this protocol version

### ✅ is refused by default, and served when the deployment opts in

Tags: `compatibility`, `e2e`

- **Given** an unmodified SDK client, which opens with an initialize handshake
  > Revision 2026-07-28 removed that handshake, and the client shipping today still sends it. So "legacy" here does not mean old software — it means every client you can install now.
  > [SEP-2567 — no initialize handshake](https://modelcontextprotocol.io/specification/2026-07-28)
- **When** it connects to a deployment left on the default setting
  **What the client is told**

  ```text
  Error POSTing to endpoint: {"jsonrpc":"2.0","error":{"code":-32022,"message":"Unsupported protocol version: 2025-11-25. No MCP client currently ships without the initialize handshake, so this refuses every client available today. Set legacy: 'stateless' to serve them.","data":{"supported":["2026-07-28"],"requested":"2025-11-25"}},"id":0}
  ```

- **Then** it is turned away, because `legacy: 'reject'` is the default
- **And** the refusal names the setting that would serve it
  > This is the first thing anybody wiring up the library sees go wrong, and the protocol error alone does not say that a setting exists, let alone which one.
- **And** the same client is served once the deployment sets `legacy: 'stateless'`
- **But** the gate still holds on that path — an older handshake is not a way around it

### A client that cannot prove who it is

### ✅ is turned away before any catalogue exists to filter

Tags: `e2e`, `security`

- **Given** a token minted for a different resource

  > The audience check is what stops a token issued for another service being replayed here. Everything else in this file is about what a verified caller may reach; this is about not being one.
  > **Token audience**

  ```json
  {
    "issued_for": "https://elsewhere.example",
    "this_server": "https://mcp.acme.com/mcp"
  }
  ```

- **When** a client connects with it
  **What the client is told**

  ```text
  Unauthorized
  ```

- **Then** the connection fails, rather than degrading to an anonymous session

### Building the map this file gates with

### ✅ reads the same capability set the permission map prices

Tags: `e2e`, `gate`

- **Given** case-tracker with every capability its configuration can register
  > A catalogue that varies by configuration has to be recorded with the branches on. Record it with close_run switched off and the map is short by exactly the tool most worth pricing.
- **When** the capabilities are read off the ungated server
- **Then** they are precisely the labels PERMISSIONS gives a price to
  > The two vocabularies are written by different code. This is what keeps them one.

## src/mcp.story.test.ts

### Connecting Claude through Google

### ✅ refuses an unpermitted call with a 403 whether or not scopes are configured

Tags: `audit`, `security`

- **Given** a server whose tools declare permissions, and no scope step-up map
- **When** a reader names the tool it was never shown
- **Then** it is the same actionable 403 a scope-configured server would give
  > Non-registration already makes the tool unreachable, but on its own it answers a probe with the SDK’s "unknown tool" and writes no record. The refusal a person has to explain later is worth naming, and worth auditing.
- **And** the denied attempt reaches the decision sink

### ✅ points an unauthenticated caller at the authorization server

Tags: `discovery`, `oauth`

- **Given** Claude has never seen this server and holds no token
- **When** it calls a tool
- **Then** it is refused with the challenge that starts the whole flow
- **And** the challenge names where to find the resource metadata (RFC 9728)
  > Without this header Claude has nowhere to begin: it cannot guess the authorization server.

### ✅ publishes metadata naming this exact host

Tags: `discovery`, `oauth`

- **Given** a client following the challenge to the metadata document
- **When** it fetches the protected resource metadata
- **Then** the resource is the URL clients actually call
  > Advertise a different host and a conforming client never attaches its token, so the flow loops forever with a valid token it refuses to use. No error says "wrong host".

### ✅ refuses a token minted for a different resource

Tags: `oauth`, `security`

- **Given** a valid, correctly signed token issued for another service
- **When** it is presented here
- **Then** the signature being good is not enough
  > RFC 8707 audience binding: a token is for one resource, not for any resource.

### ✅ refuses someone outside the Workspace domain

Tags: `oauth`, `security`

- **Given** a token for a personal Google account rather than the company one
- **When** they call a tool
- **Then** the domain check refuses them

### ✅ answers a permitted-nowhere person with an actionable 403, not an internal error

Tags: `access`, `security`

- **Given** Leo, who signs in with Google but is not on the access list
- **When** he calls a tool over HTTP
- **Then** he gets a refusal that tells him what to do about it
  > Resolving inside the MCP factory instead makes this a 500: the SDK owns factory failures, so the reason never reaches the caller. Resolve before handing off.

### ✅ challenges for write when Mcp-Name names a mutating tool

Tags: `oauth`, `scopes`

- **Given** Dana holds only the baseline mcp scope
- **When** she calls a tool that needs write, named on Mcp-Name
- **Then** the gate refuses with an actionable insufficient_scope challenge
  > A tool returning isError cannot set WWW-Authenticate, so the client has nothing to step up to.

### Asking a person before a permitted action runs

### ✅ runs a permitted call only once a named person says yes

Tags: `approval`, `security`

- **Given** an editor who already holds cases:delete
  > Approval is not the permission check again. Alice is permitted; the question is whether this particular call should happen, and that is a second person’s to answer.
- **When** she deletes with force, which this tool says needs a person
- **Then** the approver saw who was asking and what it would touch
- **And** the action ran
- **And** the audit trail names the approver, not just the caller
  > One service account downstream, two people upstream. The success event is the only place both of them appear.

### ✅ refuses a runtime approval that does not name the approver

Tags: `approval`, `security`

- **Given** an untyped approval adapter that accidentally returns yes without a name
- **When** a destructive call asks that adapter
- **Then** the runtime check fails closed even though TypeScript was bypassed

### ✅ refuses when the person says no, and when nobody answers in time

Tags: `approval`, `security`

- **Given** an approver who declines
- **When** the call is made
- **Then** the handler never runs, and the reason reaches the caller
- **And** silence is a refusal too, so an unanswered request cannot hold a connection open
  > The deadline is what keeps this a library. Nothing has to survive a restart, because a process that dies mid-question takes the open request with it and the action correctly did not happen.
- **And** a sink that throws refuses rather than letting the action through

### ✅ measures the wait for a person, so the log shows what a call really cost

Tags: `approval`, `operations`

- **Given** an approver who takes a moment, as a person does
  > A duration that stopped at the handler would say a destructive call took a millisecond, when it actually held a connection open while somebody decided.
- **When** the call is approved
- **Then** the success event covers the whole wait, not just the handler
- **And** the events are stamped in the order they happened
- **And** the attempt is recorded before the answer, so a refusal still has a start

### ✅ asks nobody for the calls that did not ask for a person

Tags: `approval`

- **Given** the same tool called without force, and a tool that never asks
- **When** both run
- **Then** neither interrupted anyone
  > The predicate reads the arguments, so the cheap path stays as cheap as it was.

### ✅ asks for a person before a prompt, which is a tool call somebody else composed

Tags: `approval`, `security`

- **Given** the destructive call reachable through a prompt as well as directly
  > Gating the tool alone leaves the prompt as a way to reach the same action without a person. A prompt costs what the call it composes costs, approval included.
- **When** the prompt is fetched
- **Then** the same person was asked, and the same refusal reached the caller

### ✅ treats an answer that arrives after the deadline as no answer

Tags: `approval`, `security`

- **Given** an approver who says yes, forty milliseconds too late
  > Fail closed. A yes that arrives after the caller has been told no would run an action nobody is still watching, and the audit trail would disagree with itself.
- **When** the call is made
- **Then** the deadline already answered, and the late yes changes nothing

### ✅ refuses to boot when a capability asks for a person and none can be reached

Tags: `approval`, `operations`

- **Given** a tool declaring approval, and a server built without a sink
- **When** the server is built
- **Then** it fails at boot rather than at the first destructive call

### Gating everything a caller can reach

### ✅ hides the prompt and the resource from someone who may only read

Tags: `access`, `security`

- **Given** a reader, and a prompt that costs the same permission as the write it composes
  > MCP exposes tools, prompts and resources. Gating tools alone leaves two doors open, and a prompt is a tool call somebody else already wrote.
- **When** each of them connects
- **Then** the boot-time check counts all three, keyed so a prompt cannot shadow a tool
- **And** each of them gets a server, carrying only what their permissions cover
  > What the reader is refused is proved over HTTP in the example app, where prompts/list comes back without triage_case.

### Starting up with a policy that does not match the tools

### ✅ refuses to boot rather than serving a tool nobody can reach

Tags: `operations`, `policy`

- **Given** a policy whose roles have drifted from the registered tools
- **When** the server is constructed
- **Then** it throws before serving a request, naming both directions of the drift
  > The compiler already rejects the permission name; this is the same check for a policy loaded from JSON or YAML, where there was never a literal to check.

### ✅ still checks the tools when a factory of your own wraps them

Tags: `operations`, `policy`

- **Given** a context richer than the principal, so createServer wraps the built server
- **When** the wrapper is handed the permissions map the wrapping hid
- **Then** the unreachable tool still fails the boot
- **And** omitting it is how the check goes silent
  > A wrapper is a plain function, so there is no map to read off it. Nothing can tell that apart from a hand-written factory that has no tool list at all.

### Configuring against a real authorization server

### ✅ reads the endpoints off the authorization server instead of a config file

Tags: `oauth`, `operations`

- **Given** an AS that publishes only the OIDC document, as Auth0 and Google do
  > RFC 8414 puts the well-known segment before the issuer path and OIDC appends it. Trying one path only works for about half of the providers people actually use.
- **When** the application discovers it at boot
- **Then** the RFC 8414 location is tried first, then the OIDC one
- **And** the JWKS comes with it, so nothing about the AS is written twice
- **And** a document claiming a different issuer is refused rather than trusted
  > Endpoints from somebody else’s server would send your users there to sign in.
- **And** an AS that publishes nothing fails the boot naming what was tried

### Putting a policy in front of a server somebody else wrote

### ✅ asks for a person before a tool somebody else wrote, and refuses to wire it without a sink

Tags: `approval`, `security`

- **Given** their destructive tool, priced by you, with an approver of yours behind it
  > Their builder knows nothing about approval. The permission map already says what their tools cost; naming one here says which of them wants a second person too.
- **When** a permitted lead calls it
- **Then** the person was asked, and their handler never ran
- **And** naming a tool for approval with no sink fails when it is wired, not at the call
  > The same boot-time refusal `authz` makes, for capabilities it never defined.

### ✅ hides the tools a caller may not use, without changing their code

Tags: `access`, `policy`

- **Given** an MCP server from another package, whose tools declare no permissions
  > The SDK keeps a built server’s tool list private, so nothing can filter what it never saw. Gating the server before it registers needs one hook from its builder.
- **When** a reader connects through the gate
- **Then** their write tool is absent from tools/list for the reader
- **And** the lead sees both, from the same unchanged builder
- **And** their tool calls land in your audit log, which their code never writes
  > TestRail or Jira sees one service account on every call. This is the only record tying the person to what they did.
- **And** a tool nobody priced fails loudly rather than defaulting either way
- **And** an SDK handle that cannot be disabled fails closed

### Reading the body that names the capability

### ✅ never parses a body for a caller it has not authenticated

Tags: `operations`, `security`

- **Given** per-capability scopes, whose selection needs the capability name from the body
  > The scope is checked against the token this request already carries, not by the bearer gate itself, so the read can wait until a valid token has proved somebody is entitled to make this process do work.
- **When** an unauthenticated caller posts far more than the cap
- **Then** the bearer gate refuses it without reading a byte of the body
- **And** the cap still bounds an authenticated caller
- **And** a body that is not JSON at all is a 415 rather than a parse error
  > The SDK asks hand-wired compositions to answer 415 themselves.
- **And** malformed JSON within the cap is still a parse error

### ✅ never lets an unvalidated header pick the scope on a request with no body

Tags: `security`

- **Given** a GET, which carries no body for its routing headers to disagree with
- **When** it arrives claiming a cheap capability
- **Then** the baseline scope applies and the bearer gate still refuses it
  > Only a POST can be checked body against headers, so anything else is held to the baseline rather than to what its headers asked for.

### ✅ survives a routed capability when the resolver mode has no principal

Tags: `resolver`

- **Given** a server whose capabilities carry route permissions
- **And** a gate wired in resolver mode, which decides access itself and has no principal
- **When** somebody calls the routed tool
- **Then** the request is answered rather than crashing on the missing principal

### ✅ requires the step-up scope on a resource reached through a URI template

Tags: `resources`, `scopes`

- **Given** a templated resource priced for a scope beyond the baseline
- **When** a reader holding only the baseline scope reads one instance of it
  **Challenge**

  ```text
  Bearer error="insufficient_scope", error_description="Insufficient scope", scope="mcp cases:sensitive", resource_metadata="https://mcp.acme.com/.well-known/oauth-protected-resource/mcp"
  ```

- **Then** the step-up is demanded, even though the key is a template and the request a URI
  > The scope map is keyed by the template as registered; the request carries one concrete URI. An exact-string lookup between the two silently skips the step-up.

## src/policy.story.test.ts

### Deciding what a caller may do

### ✅ grants nothing to someone no rule matches

Tags: `policy`, `security`

- **Given** a policy that opens the company domain and names one editor
- **Then** a colleague gets the domain role
- **And** the named editor gets both roles, and the permissions union
- **And** an outsider gets nothing at all
  > There is no default setting to get wrong. Matching no rule means no permissions, and a policy that fails open is invisible: it works for everybody, including the people it was written to exclude.

### ✅ lets deny win over a grant that nobody tidied up

Tags: `policy`, `security`

- **Given** a contractor who left, denied by subject but still on the editor rule
- **When** they connect
- **Then** deny wins, and it is keyed to the subject rather than the email
  > The half-finished revocation is the realistic one. Denying by `sub` also survives the email being reassigned to a new joiner.

### ✅ matches an IdP group claim so the list is maintained in one place

Tags: `policy`

- **Given** a policy keyed to a group the identity provider already maintains
- **Then** an array claim matches when it contains the value
- **And** somebody in a different group is refused without being named anywhere

### ✅ matches a namespaced claim whose own name contains dots

Tags: `policy`

- **Given** the namespaced claim an IdP actually emits
  > Auth0 writes group memberships to a URL-shaped claim. Treating the name as a dotted path splits it at `https://acme` and matches nothing, so the rule looks correct and silently grants no one.
- **Then** the literal claim name wins over splitting it on dots

### ✅ refuses to start on a policy that cannot mean what it says

Tags: `operations`, `policy`

- **Given** a rule naming a role that was renamed or never existed
- **Then** it throws at construction, naming the rule and the role
- **And** a repeated permission is tidied rather than fatal
  > Everything downstream is a set, so a repeat changes nothing. Failing the boot over it punishes a policy assembled from JSON, where a duplicate is somebody else's bug.
- **And** a rule that grants nothing is a mistake rather than a subtle deny
- **And** runtime-loaded match values are validated before the first request

### Reconciling the policy against the tools at startup

### ✅ reports drift in both directions

Tags: `operations`, `policy`

- **Given** a role granting a permission no tool requires
- **And** a tool requiring a permission no role grants
- **When** the server boots
- **Then** the unreachable tool is fatal
  > A tool no role can reach is dead code that looks live. A gateway cannot run this check — it does not learn the tool list until traffic arrives.
- **And** the unused permission is only a warning
  > Granting a role ahead of the tool that will use it is how a staged rollout works. Failing the boot on it teaches people to add dummy tools to deploy.
- **And** a policy that matches its tools starts silently

## src/proxy.story.test.ts

### createMcpProxy

### ✅ returns 401 before the upstream is contacted when there is no bearer

Tags: `proxy`, `security`

- **When** a client connects with no bearer token
  **What the client got back**

  ```text
  Error POSTing to endpoint: {"error":"invalid_token","error_description":"Missing Authorization header"}
  ```

- **Then** the proxy refuses it and the upstream is never called

### ✅ returns 403 when the policy grants nothing

Tags: `policy`, `proxy`

- **When** someone whose policy role grants no permissions connects
- **Then** the proxy refuses before forwarding

### ✅ filters tools/list to what the reader may reach

Tags: `catalogue`, `proxy`

**Catalogue**

<details>
<summary>snapshot</summary>

```json
{
  "tools": ["get_case", "search_cases"],
  "prompts": ["triage"],
  "resources": ["cases"],
  "resourceTemplates": ["case"]
}
```

</details>

- **Then** read tools survive and write tools are hidden

### ✅ forwards a permitted tools/call

Tags: `proxy`

- **When** the reader calls a read tool
  **get_case C1**

  ```text
  case C1
  ```

- **Then** the upstream answer comes back through the proxy

### ✅ refuses a denied tools/call before the upstream runs

Tags: `proxy`, `security`

- **When** the reader names a write tool without listing first
- **Then** the proxy refuses it and the upstream is never asked for the call

### ✅ filters prompts and resources the same way as tools

Tags: `catalogue`, `proxy`

- **Then** the reader sees the read catalogue across all four kinds

### ✅ returns insufficient_scope when the token lacks a required step-up scope

Tags: `proxy`, `scopes`

- **When** the lead calls a write tool with only the baseline scope
  **What the client got back**

  ```text
  {"error":"insufficient_scope","error_description":"Insufficient scope"}
  ```

- **Then** the proxy asks for the missing scope instead of forwarding

### ✅ passes SSE upstream bodies through without parsing them

Tags: `proxy`, `streaming`

- **Then** the event stream is forwarded unchanged

### ✅ filters JSON listing responses from the upstream

Tags: `catalogue`, `proxy`

### ✅ refuses a POST whose routing headers disagree with its body

Tags: `proxy`, `security`

- **Given** a reader who may not write
- **When** they label a write call as a harmless listing in the Mcp-Method header
  **What the client got back**

  ```json
  {
    "jsonrpc": "2.0",
    "error": {
      "code": -32020,
      "message": "Bad Request: the request headers and body disagree: the body names method tools/call but the Mcp-Method header names tools/list",
      "data": {
        "mismatch": {
          "header": "tools/list",
          "body": "the body names method tools/call but the Mcp-Method header names tools/list"
        }
      }
    },
    "id": 1
  }
  ```

- **Then** the proxy refuses it rather than trusting the header
- **And** the upstream never sees the smuggled call

### ✅ authorises a resources/read by URI, template included

Tags: `proxy`, `resources`

- **When** the reader reads the static resource the catalogue offered her
- **Then** the upstream answer comes back
- **And** she reads one that only a URI template covers
- **And** the template matches and the read is allowed

### ✅ refuses a resources/read that no priced URI covers

Tags: `proxy`, `security`

- **When** the reader names a URI outside every priced resource
  **What the client got back**

  ```text
  Error POSTing to endpoint: {"error":"forbidden","reason":"policy_denied","error_description":"dana@acme.com matches no rule in the capability 'secrets://payroll' is not priced in the permission map, so they hold no permissions. Ask an administrator to grant them a role."}
  ```

- **Then** the proxy refuses it and the upstream never sees the read

### ✅ does not put the upstream framing headers on a body it rewrote

Tags: `proxy`, `streaming`

**Framing**

<details>
<summary>snapshot</summary>

```json
{
  "contentLength": null,
  "contentEncoding": null,
  "actualBytes": 69
}
```

</details>

- **Then** the stale length and encoding are dropped rather than copied onto the shorter body

### ✅ does not forward the caller credentials meant for the proxy

Tags: `proxy`, `security`

- **When** a browser-borne request arrives carrying a session cookie
  **Upstream saw**

    <details>
    <summary>snapshot</summary>

  ```json
  {
    "cookie": null,
    "authorization": "Bearer service-token"
  }
  ```

    </details>

- **Then** the upstream gets the service credential and none of the caller cookies

### ✅ lets a genuine failure reach the host instead of flattening it to a 500

Tags: `operations`, `proxy`

- **When** a step fails for a reason that is nobody policy decision
  **What escaped the proxy**

  ```text
  TypeError: upstream DNS exploded
  ```

- **Then** the original error propagates, with its type and message intact
  > A refusal is a considered answer and is returned. A bug is not, and belongs to whatever runs this process — swallowing it into a 500 would lose the stack that explains it.

### ✅ requires a resource step-up scope, matched by URI against the label it was keyed by

Tags: `proxy`, `scopes`

- **When** a reader with only the baseline scope reads a resource priced for step-up
  **Challenge**

  ```text
  Bearer error="insufficient_scope", error_description="Insufficient scope", scope="mcp cases:sensitive", resource_metadata="https://mcp.acme.com/.well-known/oauth-protected-resource/mcp"
  ```

- **Then** the proxy asks for the missing scope rather than serving the read
  > The scope map is keyed by label, and the request carries a URI. Looking one up as the other is a step-up that silently never happens.

### ✅ refuses a URI a privileged template also covers, whatever the map order

Tags: `proxy`, `security`

- **Given** a broad readable template listed before a narrow privileged one
- **When** a reader reads a URI both of them match
- **Then** the proxy refuses, because it cannot know which one the upstream will route to

### ✅ filters an SSE listing whatever shape the event framing takes

Tags: `proxy`, `streaming`

**What reached the client**

```text
event: message
data: {"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search_cases"}]}}


```

- **Then** the write tool is gone from the stream, not merely from the JSON shape

### ✅ refuses a listing it cannot read rather than passing it through

Tags: `proxy`, `security`

- **When** the upstream answers a listing in a content type the proxy cannot filter
  **What reached the client**

  ```text
  {"jsonrpc":"2.0","id":1,"error":{"code":-32010,"message":"Bad Gateway: this catalogue could not be filtered — tools/list came back as 'text/plain'."}}
  ```

- **Then** the catalogue is withheld rather than served unfiltered
  > Failing open here would hand every caller the full catalogue on a content-type change.

### ✅ delivers a filtered event before the upstream stream has finished

Tags: `proxy`, `streaming`

- **When** the upstream sends one event and then holds the connection open
  **First event through**

  ```text
  data: {"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search_cases"}]}}


  ```

- **Then** the filtered event arrives while the stream is still open
- **And** the write tool never appears in it

### ✅ filters an SSE listing framed with bare carriage returns and a byte-order mark

Tags: `proxy`, `streaming`

**What reached the client**

```text
event: message
data: {"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search_cases"}]}}
```

- **Then** the catalogue is filtered rather than passed through unread

### ✅ refuses an SSE event that never ends rather than growing to hold it

Tags: `proxy`, `security`

- **When** an upstream sends an event with no terminator, larger than the cap
  **What reached the client**

  ```text
  event: message
  data: {"jsonrpc":"2.0","id":1,"error":{"code":-32010,"message":"Bad Gateway: this catalogue could not be filtered — tools/list sent an event over 512 bytes."}}


  ```

- **Then** the proxy stops rather than buffering whatever the upstream sends
  > Otherwise a broken or hostile upstream decides how much memory this process spends.

### ✅ filters an SSE listing whose two line endings differ from each other

Tags: `proxy`, `streaming`

**What reached the client**

```text
event: message
data: {"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search_cases"}]}}


```

- **Then** the boundary is recognised and the catalogue filtered, without waiting for EOF

### ✅ refuses an oversized event whether or not its terminator shares a chunk

Tags: `proxy`, `security`

**What reached the client**

```text
event: message
data: {"jsonrpc":"2.0","id":1,"error":{"code":-32010,"message":"Bad Gateway: this catalogue could not be filtered — tools/list sent an event over 512 bytes."}}


```

- **Then** the cap holds regardless of how the transport happened to split it
  > A limit that depends on chunk boundaries is a limit an upstream can choose to miss.

### ✅ answers an unfilterable event under the id the client is waiting on

Tags: `proxy`, `streaming`

- **When** the upstream sends an event the proxy cannot read
  **Error envelope**

    <details>
    <summary>snapshot</summary>

  ```json
  {
    "jsonrpc": "2.0",
    "id": 1,
    "error": {
      "code": -32010,
      "message": "Bad Gateway: this catalogue could not be filtered — tools/list carried an unreadable event."
    }
  }
  ```

    </details>

- **Then** the error carries the request id, so the caller stops waiting on it
  > An error with id null matches no pending request. A client that ignores it leaves the original listing outstanding for as long as the stream stays open.

### ✅ refuses a JSON catalogue larger than the cap instead of buffering it

Tags: `proxy`, `security`

- **When** the upstream answers a listing with a body far over the cap
  **What reached the client**

  ```text
  {"jsonrpc":"2.0","id":1,"error":{"code":-32010,"message":"Bad Gateway: this catalogue could not be filtered — tools/list was over 512 bytes or not readable as JSON-RPC."}}
  ```

- **Then** the cap applies to what comes back, not only to what goes out
  > It is advertised as bounding a message in either direction, so it has to.

### ✅ measures the event cap in bytes, not in UTF-16 units

Tags: `proxy`, `security`

**What reached the client**

```text
event: message
data: {"jsonrpc":"2.0","id":1,"error":{"code":-32010,"message":"Bad Gateway: this catalogue could not be filtered — tools/list sent an event over 700 bytes."}}


```

- **Then** a cap in bytes is enforced in bytes, whatever alphabet the content is in
  > Otherwise the advertised limit is three times larger for anyone not writing ASCII.

### ✅ finds an event boundary split across two chunks

Tags: `proxy`, `streaming`

**What reached the client**

```text
event: message
data: {"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search_cases"}]}}


```

- **Then** the event is recognised and filtered without waiting for the stream to end

### ✅ counts bytes correctly when multibyte characters straddle chunks

Tags: `proxy`, `streaming`

- **Then** the byte cap still refuses it, counted over the reassembled event
