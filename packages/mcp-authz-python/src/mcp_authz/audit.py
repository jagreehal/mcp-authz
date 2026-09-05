"""What happened, in the shape the TypeScript package emits it.

The downstream API sees one service account. These events are the only record
tying a person to an action, so they leave the process for somebody's log store
and are kept for years — which makes their shape an interface, not a detail.

Both packages emit the same two records under the same two names, with the same
JSON keys (``to_dict`` is the wire form; the attributes stay snake_case because
this is Python). One query over one store covers a deployment that runs both.
"""

from __future__ import annotations

import inspect
import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, TypeVar

from .policy import Principal

AUDIT_EVENT_TYPE = "mcp_authz.audit.v1"
DECISION_EVENT_TYPE = "mcp_authz.decision.v1"

_T = TypeVar("_T")


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One capability call, from the attempt to whatever became of it.

    ``kind`` is wider than the MCP capability kinds because ``mcp_authz.openapi``
    records HTTP operations through the same events: ``tool``, ``prompt``,
    ``resource`` or ``operation``.

    ``call_id`` is the same on the attempt and on whatever became of it, and
    different for every other call. Correlating those two rows by identity and
    timestamp instead breaks under exactly the concurrency that makes the
    question worth asking.

    ``domain`` is the verified Workspace domain, the nearest thing to an
    organisation this library can prove: key one by ``(issuer, domain)``.
    ``emitter`` names the deployment, when you set it.

    A new optional field does not move the ``v1``. Changing what an existing
    field means does, because a stored query cannot tell that apart.
    """

    call_id: str
    issuer: str
    sub: str
    kind: str
    name: str
    permission: str
    decision: str
    phase: str
    at: str
    email: str | None = None
    domain: str | None = None
    emitter: str | None = None
    resource: str | None = None
    approved_by: str | None = None
    duration_ms: float | None = None
    error: str | None = None
    type: str = AUDIT_EVENT_TYPE

    def to_dict(self) -> dict[str, Any]:
        """The wire form: the TypeScript event's keys, absent where unset."""

        event: dict[str, Any] = {
            "type": self.type,
            "callId": self.call_id,
            "issuer": self.issuer,
            "sub": self.sub,
            "kind": self.kind,
            "name": self.name,
            "permission": self.permission,
            "decision": self.decision,
            "phase": self.phase,
            "at": self.at,
        }
        for key, value in (
            ("email", self.email),
            ("domain", self.domain),
            ("emitter", self.emitter),
            ("resource", self.resource),
            ("approvedBy", self.approved_by),
            ("durationMs", self.duration_ms),
            ("error", self.error),
        ):
            if value is not None:
                event[key] = value
        return event


@dataclass(frozen=True, slots=True)
class AuditDeliveryFailure:
    """A terminal write that did not land, and the event it lost."""

    error: BaseException
    event: AuditEvent


@dataclass(frozen=True, slots=True)
class AuthorizationDecisionEvent:
    """Who was let in or turned away, and why. See ``AuditEvent.type``."""

    issuer: str
    sub: str
    decision: str
    roles: Sequence[str]
    permissions: Sequence[str]
    at: str
    email: str | None = None
    domain: str | None = None
    emitter: str | None = None
    reason: str | None = None
    type: str = DECISION_EVENT_TYPE

    def to_dict(self) -> dict[str, Any]:
        event: dict[str, Any] = {
            "type": self.type,
            "issuer": self.issuer,
            "sub": self.sub,
            "decision": self.decision,
            "roles": list(self.roles),
            "permissions": list(self.permissions),
            "at": self.at,
        }
        for key, value in (
            ("email", self.email),
            ("domain", self.domain),
            ("emitter", self.emitter),
            ("reason", self.reason),
        ):
            if value is not None:
                event[key] = value
        return event


AuditSink = Callable[[AuditEvent], Awaitable[None] | None]
AuditErrorSink = Callable[[AuditDeliveryFailure], Awaitable[None] | None]
AuthorizationDecisionSink = Callable[[AuthorizationDecisionEvent], Awaitable[None] | None]


def new_call_id() -> str:
    """One id for both events of one call. See ``AuditEvent.call_id``."""

    return str(uuid.uuid4())


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def principal_label(principal: Principal) -> str:
    return principal.email or f"{principal.issuer}#{principal.sub}"


async def _call(sink: Callable[[Any], Awaitable[None] | None], value: Any) -> None:
    """Sinks may be sync or async: a logger call is not worth a coroutine."""

    result = sink(value)
    if inspect.isawaitable(result):
        await result


async def emit_decision(
    sink: AuthorizationDecisionSink | None,
    principal: Principal | None,
    decision: str,
    reason: str | None = None,
    emitter: str | None = None,
) -> None:
    if sink is None or principal is None:
        return
    await _call(
        sink,
        AuthorizationDecisionEvent(
            issuer=principal.issuer,
            sub=principal.sub,
            email=principal.email,
            domain=principal.domain,
            emitter=emitter,
            decision=decision,
            roles=list(principal.roles),
            permissions=list(principal.permissions),
            reason=reason,
            at=now(),
        ),
    )


async def deliver_terminal_audit(
    sink: AuditSink | None,
    on_error: AuditErrorSink | None,
    event: AuditEvent,
) -> None:
    """A terminal write happens after the action reached its result.

    Its failure cannot change that result, so it is caught here and offered to
    ``on_audit_error`` instead — a retry queue, or an operator alert.
    """

    if sink is None:
        return
    try:
        await _call(sink, event)
    except Exception as error:  # noqa: BLE001 - an observer cannot change the result
        if on_error is None:
            return
        try:
            await _call(on_error, AuditDeliveryFailure(error=error, event=event))
        except Exception:  # noqa: BLE001, S110 - nor can the observer of the observer
            pass
