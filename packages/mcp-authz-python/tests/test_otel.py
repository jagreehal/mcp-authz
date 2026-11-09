from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from mcp_authz.audit import AuditEvent, AuthorizationDecisionEvent
from mcp_authz.otel import (
    create_identifier_hasher,
    create_otel_audit_sink,
    create_otel_decision_sink,
)


def test_identifier_hasher_matches_typescript() -> None:
    assert create_identifier_hasher("test-key")("alice@acme.com") == "6161c1d257155902ecdc1d474288baa8"
    assert create_identifier_hasher("other-key")("alice@acme.com") != "6161c1d257155902ecdc1d474288baa8"


def _mock_span() -> tuple[MagicMock, dict[str, Any]]:
    attrs: dict[str, Any] = {}
    span = MagicMock()
    span.is_recording.return_value = True

    def set_attribute(key: str, value: Any) -> None:
        attrs[key] = value

    def set_attributes(values: dict[str, Any]) -> None:
        attrs.update(values)

    span.set_attribute.side_effect = set_attribute
    span.set_attributes.side_effect = set_attributes
    return span, attrs


def test_audit_sink_writes_attributes() -> None:
    span, attrs = _mock_span()
    with patch("mcp_authz.otel.trace.get_current_span", return_value=span):
        create_otel_audit_sink(hash_key="test-key")(
            AuditEvent(
                call_id="c1",
                issuer="https://auth.example",
                sub="user-1",
                email="alice@acme.com",
                kind="tool",
                name="get_case",
                permission="cases:read",
                decision="allow",
                phase="success",
                at="2026-01-01T00:00:00Z",
                resource="case:C1234",
            )
        )

    assert attrs["mcp_authz.audit.phase"] == "success"
    assert attrs["mcp_authz.audit.name"] == "get_case"
    assert attrs["mcp_authz.audit.resource"] == "case:C1234"
    assert attrs["mcp_authz.email.hash"] == "6161c1d257155902ecdc1d474288baa8"
    assert attrs["autotel.sampling.tail.keep"] is True


def test_decision_sink_records_deny() -> None:
    span, attrs = _mock_span()
    with patch("mcp_authz.otel.trace.get_current_span", return_value=span):
        create_otel_decision_sink()(
            AuthorizationDecisionEvent(
                issuer="https://auth.example",
                sub="user-2",
                decision="deny",
                roles=(),
                permissions=(),
                reason="policy_denied",
                at="2026-01-01T00:00:00Z",
            )
        )

    assert attrs["mcp_authz.decision"] == "deny"
    assert attrs["mcp_authz.decision.reason"] == "policy_denied"
    assert attrs["security.outcome"] == "failure"
    assert "mcp_authz.sub.hash" not in attrs
    assert "enduser.id" not in attrs


def test_audit_sink_noop_without_recording_span() -> None:
    span = MagicMock()
    span.is_recording.return_value = False
    with patch("mcp_authz.otel.trace.get_current_span", return_value=span):
        create_otel_audit_sink()(
            AuditEvent(
                call_id="c2",
                issuer="https://auth.example",
                sub="user-1",
                kind="tool",
                name="get_case",
                permission="cases:read",
                decision="allow",
                phase="attempt",
                at="2026-01-01T00:00:00Z",
            )
        )
    span.set_attributes.assert_not_called()


def test_audit_sink_keeps_error_text_off_unless_asked() -> None:
    event = AuditEvent(
        call_id="c3",
        issuer="https://auth.example",
        sub="user-1",
        kind="tool",
        name="get_case",
        permission="cases:read",
        decision="allow",
        phase="failure",
        at="2026-01-01T00:00:00Z",
        error="row for alice@acme.com not found",
    )
    span, attrs = _mock_span()
    with patch("mcp_authz.otel.trace.get_current_span", return_value=span):
        create_otel_audit_sink()(event)
    assert "mcp_authz.audit.error" not in attrs
    assert attrs["security.outcome"] == "failure"

    span, attrs = _mock_span()
    with patch("mcp_authz.otel.trace.get_current_span", return_value=span):
        create_otel_audit_sink(capture_errors=True)(event)
    assert attrs["mcp_authz.audit.error"] == "row for alice@acme.com not found"
