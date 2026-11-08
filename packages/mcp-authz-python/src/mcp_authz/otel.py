"""OpenTelemetry sinks for mcp-authz.

The sinks use ``opentelemetry.trace``. You initialise the SDK yourself;
``autotel.init(..., instrumentation=["mcp"])`` adds MCP tool spans.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from typing import Any, TypedDict

from opentelemetry import trace

from .audit import (
    AuditEvent,
    AuditSink,
    AuthorizationDecisionEvent,
    AuthorizationDecisionSink,
)

TAIL_KEEP = "autotel.sampling.tail.keep"
TAIL_EVALUATED = "autotel.sampling.tail.evaluated"


class OtelAuthzSinks(TypedDict):
    on_audit: AuditSink
    on_decision: AuthorizationDecisionSink


def create_identifier_hasher(hash_key: str) -> Callable[[str], str]:
    """Return a keyed digest function: HMAC-SHA-256 over UTF-8, first 32 hex characters.

    The TypeScript package produces the same digest for the same key.
    """

    key = hash_key.encode("utf-8")

    def hash_value(value: str) -> str:
        return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:32]

    return hash_value


def _force_keep(span: trace.Span) -> None:
    span.set_attribute(TAIL_EVALUATED, True)
    span.set_attribute(TAIL_KEEP, True)
    span.set_attribute("security.force_keep", True)


def _actor_attrs(
    event: AuditEvent | AuthorizationDecisionEvent,
    hash_value: Callable[[str], str] | None,
) -> dict[str, Any]:
    attrs: dict[str, Any] = {"mcp_authz.issuer": event.issuer}
    if hash_value:
        sub = hash_value(event.sub)
        attrs["mcp_authz.sub.hash"] = sub
        attrs["enduser.id"] = sub
        if event.email:
            attrs["mcp_authz.email.hash"] = hash_value(event.email)
    if event.domain:
        attrs["mcp_authz.domain"] = event.domain
    if event.emitter:
        attrs["mcp_authz.emitter"] = event.emitter
    return attrs


def create_otel_audit_sink(*, force_keep: bool = True, hash_key: str | None = None) -> AuditSink:
    """Writes ``mcp_authz.audit.v1`` onto the active span.

    With ``hash_key``, identifiers land as keyed digests. Without it, the sink
    leaves them off the span.
    """

    hash_value = create_identifier_hasher(hash_key) if hash_key else None

    def sink(event: AuditEvent) -> None:
        span = trace.get_current_span()
        if not span.is_recording():
            return
        attrs = {
            **_actor_attrs(event, hash_value),
            "mcp_authz.event": event.type,
            "mcp_authz.audit.call_id": event.call_id,
            "mcp_authz.audit.kind": event.kind,
            "mcp_authz.audit.name": event.name,
            "mcp_authz.audit.permission": event.permission,
            "mcp_authz.audit.phase": event.phase,
            "mcp_authz.audit.decision": event.decision,
            "security.event": f"mcp_authz.audit.{event.phase}",
            "security.category": "authorization",
            "security.outcome": (
                "failure" if event.decision == "deny" or event.phase in {"failure", "refused"} else "success"
            ),
        }
        if event.resource is not None:
            attrs["mcp_authz.audit.resource"] = event.resource
        if event.approved_by is not None and hash_value:
            attrs["mcp_authz.audit.approved_by.hash"] = hash_value(event.approved_by)
        if event.duration_ms is not None:
            attrs["mcp_authz.audit.duration_ms"] = event.duration_ms
        if event.error is not None:
            attrs["mcp_authz.audit.error"] = event.error[:500]
        span.set_attributes(attrs)
        if force_keep:
            _force_keep(span)

    return sink


def create_otel_decision_sink(*, force_keep: bool = True, hash_key: str | None = None) -> AuthorizationDecisionSink:
    """Writes ``mcp_authz.decision.v1`` onto the active span."""

    hash_value = create_identifier_hasher(hash_key) if hash_key else None

    def sink(event: AuthorizationDecisionEvent) -> None:
        span = trace.get_current_span()
        if not span.is_recording():
            return
        attrs = {
            **_actor_attrs(event, hash_value),
            "mcp_authz.event": event.type,
            "mcp_authz.decision": event.decision,
            "mcp_authz.roles": ",".join(event.roles),
            "mcp_authz.permissions": ",".join(event.permissions),
            "security.event": "mcp_authz.access.decision",
            "security.category": "authorization",
            "security.outcome": "success" if event.decision == "allow" else "failure",
            "security.severity": "info" if event.decision == "allow" else "warning",
        }
        if event.reason is not None:
            attrs["mcp_authz.decision.reason"] = event.reason
        span.set_attributes(attrs)
        if force_keep:
            _force_keep(span)

    return sink


def create_otel_authz_sinks(*, force_keep: bool = True, hash_key: str | None = None) -> OtelAuthzSinks:
    """Both sinks for ``on_audit`` / ``on_decision``."""

    return {
        "on_audit": create_otel_audit_sink(force_keep=force_keep, hash_key=hash_key),
        "on_decision": create_otel_decision_sink(force_keep=force_keep, hash_key=hash_key),
    }
