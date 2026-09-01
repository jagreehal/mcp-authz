# 1. The proxy ladder, and where identity provenance sits

Status: accepted, nothing built beyond `recordUpstream`.

## Context

This library has always answered "all you have is a URL" with "use a gateway".
A proxy mode would change that answer. Before building one, the shape it would
have to take was worked through, and the useful part of that is the constraints
rather than the design.

`recordUpstream` shipped first, deliberately. It is the only rung that needs no
new component, and how it gets used is the evidence for whether the rest of the
ladder should exist.

## The four constraints

Every later decision follows from these, and none of them is negotiable without
changing what this library is.

1. **Observation must not change outcomes.** A component that watches traffic
   must not decide whether a request succeeds. The moment it can refuse, it is a
   security boundary and inherits every obligation of one.
2. **Verification must not imply enforcement.** Checking a signature to attribute
   an action is a different act from checking it to permit one. A proxy may
   verify a token for the audit trail and still forward a request whose token
   failed to verify, leaving the upstream authoritative.
3. **Drift must come from a controlled recording identity.** A user-facing
   `tools/list` is not a catalogue; it is a catalogue projected through one
   caller's permissions. Fingerprinting live traffic conflates "the upstream
   changed" with "this caller sees less", which are the two things drift
   detection exists to tell apart.
4. **Enforcement is an explicit promotion.** Becoming the boundary is something
   an operator opts into, never a default and never a side effect of enabling
   observability.

The dividing question is not "does this component understand authentication?"
It is **"can this component change the outcome?"**

## The ladder

| Rung               | Traffic path | Identity                        | Authoritative |
| ------------------ | ------------ | ------------------------------- | ------------- |
| `record`           | none         | fixed recording credential      | upstream      |
| `observe`          | transparent  | absent or explicitly unverified | upstream      |
| `observe + verify` | transparent  | verified, never rejected        | upstream      |
| `enforce`          | terminating  | verified                        | this library  |

Each rung is independently useful, and adoption cost rises with each. The first
asks for nothing but a URL; the last asks an operator to trust a new component
with authorization.

## Identity provenance

An audit trail whose identity comes from an unverified token is not an audit
trail. Decoded JWT claims are attacker-controlled, and putting them in a field
named `sub` presents low-integrity data in a high-trust schema — the failure
mode is that it reads exactly like evidence.

The intended shape, when there is a consumer for it:

```ts
type AuditIdentity =
  | { status: 'verified'; issuer: string; sub: string; email?: string }
  | { status: 'unverified'; issuer?: string; sub?: string; email?: string; reason?: string }
  | { status: 'anonymous' };
```

**`AuditEvent` is deliberately unchanged for now.** Its `issuer` and `sub` are
required strings, and they are honest: both come from a `Principal`, which only
ever exists downstream of a verified bearer token. There is no code path today
that possesses less than it claims. `AuditEvent` is exported and published, so
changing it now would break consumers to accommodate a mode that does not exist —
which is the proxy arriving early in the type system.

If a passthrough mode ships before that change is made, it must **omit identity
entirely** rather than populate trustworthy-looking fields from decoded claims.

## What would justify building further

The rungs are not all equally supported by the same evidence:

| Observed behaviour                         | What it argues for                                  |
| ------------------------------------------ | --------------------------------------------------- |
| `record` run once                          | inventory is useful                                 |
| generated map committed and reviewed       | reviewability is useful                             |
| `record` wired into CI                     | drift is useful — the strongest signal for the rest |
| asks about fronting URL-only servers       | proxy demand                                        |
| asks for identity or audit output          | observability demand                                |
| asks to deny newly discovered capabilities | enforcement demand                                  |

`record` in CI is worth more than `record` run once, because it means somebody
cares about the relationship between an upstream's capability surface and their
own security assumptions over time. That is the thesis the rest of the ladder
rests on.

## Reuse, if it is built

Transparent mode cannot be `createMcpFetch` with the policy left out.
`oauthMetadata` is a required option, the handler publishes RFC 9728
protected-resource metadata, and `requireBearerAuth` is on the path — all of
which a transparent hop must not do. The reuse boundary sits lower:

```text
shared          request classifier, capability extraction, audit vocabulary,
                resource mapping, catalogue and fingerprint primitives
createMcpFetch  owns the auth boundary and policy enforcement
createMcpProxy  owns transparent forwarding, with annotation and enforcement
                as separate layers above it
```

The consequence is worth stating plainly: **enforcement mode is the cheaper
build**, because the existing architecture already assumes it owns
authentication. Transparency is the harder thing to add, not the easier.

## Open: the name

If the journey people actually take is record → fingerprint → observe → verify,
and most never enable enforcement, then authorization is not the centre of the
product they experience. That tension is real rather than theoretical, and it
should not be argued away with "authz is the organizing model". Nothing is
renamed now, and the same evidence that decides the ladder decides this.
