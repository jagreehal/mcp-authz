# User Stories

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
