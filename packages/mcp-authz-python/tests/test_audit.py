"""The record that ties a person to an action, on both enforcement seams."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.context import ServerRequestContext
from mcp.shared.exceptions import MCPError

from mcp_authz import (
    ApprovalDecision,
    ApprovalRequest,
    AuditDeliveryFailure,
    AuditEvent,
    AuthorizationDecisionEvent,
    AuthorizationMiddleware,
    Principal,
    define_policy,
    gate,
)

FIXTURES = Path(__file__).resolve().parents[3] / "conformance" / "v1" / "audit" / "events.json"

POLICY = define_policy(
    {
        "roles": {"reader": ["cases:read"]},
        "rules": [{"match": {"domain": "acme.com"}, "role": "reader"}],
    }
)


@pytest.fixture(autouse=True)
def authenticated_user() -> Any:
    access_token = AccessToken(
        token="test",
        client_id="client",
        scopes=["mcp"],
        subject="user-1",
        claims={
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "email": "reader@acme.com",
            "email_verified": True,
            "hd": "acme.com",
        },
    )
    reset = auth_context_var.set(AuthenticatedUser(access_token))
    yield
    auth_context_var.reset(reset)


def _middleware(**options: Any) -> AuthorizationMiddleware:
    return AuthorizationMiddleware(
        POLICY,
        {("tools/call", "read_case"): "cases:read", ("tools/call", "delete_case"): "cases:write"},
        **options,
    )


def _context(name: str = "read_case") -> ServerRequestContext[Any, Any]:
    return cast(ServerRequestContext[Any, Any], SimpleNamespace(method="tools/call", params={"name": name}))


async def _ran(_: Any) -> dict[str, Any]:
    return {"ok": True}


class TestTheWireShape:
    """Both packages emit the same keys under the same names, or a query breaks."""

    def test_matches_the_conformance_fixture(self) -> None:
        fixture = json.loads(FIXTURES.read_text())
        event = AuditEvent(
            call_id="a1b2",
            issuer="https://auth.example.com",
            sub="user-1",
            email="reader@acme.com",
            domain="acme.com",
            emitter="cases",
            kind="tool",
            name="read_case",
            permission="cases:read",
            resource="case:C1",
            decision="allow",
            phase="success",
            at="2026-01-01T00:00:00+00:00",
            approved_by="sam@acme.com",
            duration_ms=1.5,
        )
        assert event.type == fixture["audit"]["type"]
        assert set(event.to_dict()) <= set(fixture["audit"]["keys"])
        assert set(fixture["audit"]["required"]) <= set(event.to_dict())
        assert event.kind in fixture["audit"]["kinds"]
        assert event.phase in fixture["audit"]["phases"]

        decision = AuthorizationDecisionEvent(
            issuer="https://auth.example.com",
            sub="user-1",
            email="reader@acme.com",
            domain="acme.com",
            emitter="cases",
            decision="deny",
            roles=["reader"],
            permissions=["cases:read"],
            reason="not_permitted",
            at="2026-01-01T00:00:00+00:00",
        )
        assert decision.type == fixture["decision"]["type"]
        assert set(decision.to_dict()) <= set(fixture["decision"]["keys"])
        assert set(fixture["decision"]["required"]) <= set(decision.to_dict())

    def test_omits_what_was_never_set(self) -> None:
        event = AuditEvent(
            call_id="a1b2",
            issuer="i",
            sub="s",
            kind="tool",
            name="t",
            permission="p",
            decision="allow",
            phase="attempt",
            at="now",
        )
        assert "email" not in event.to_dict()
        assert "domain" not in event.to_dict()
        assert "emitter" not in event.to_dict()
        assert "durationMs" not in event.to_dict()


class TestTheDeclaredSeam:
    async def test_records_the_attempt_and_what_became_of_it(self) -> None:
        events: list[AuditEvent] = []
        await _middleware(on_audit=events.append, emitter="cases")(_context(), _ran)
        assert [event.phase for event in events] == ["attempt", "success"]
        assert events[-1].to_dict() | {"at": "", "durationMs": 0, "callId": "*"} == {
            "type": "mcp_authz.audit.v1",
            "callId": "*",
            "issuer": "https://auth.example.com",
            "sub": "user-1",
            "email": "reader@acme.com",
            "domain": "acme.com",
            "emitter": "cases",
            "kind": "tool",
            "name": "read_case",
            "permission": "cases:read",
            "decision": "allow",
            "phase": "success",
            "at": "",
            "durationMs": 0,
        }

    async def test_gives_both_events_of_one_call_one_id(self) -> None:
        events: list[AuditEvent] = []
        middleware = _middleware(on_audit=events.append)
        await middleware(_context(), _ran)
        await middleware(_context(), _ran)
        assert len({event.call_id for event in events}) == 2
        assert events[0].call_id == events[1].call_id
        assert events[2].call_id == events[3].call_id

    async def test_records_a_handler_that_raised_and_still_raises(self) -> None:
        events: list[AuditEvent] = []

        async def explodes(_: Any) -> dict[str, Any]:
            raise RuntimeError("handler exploded")

        with pytest.raises(RuntimeError):
            await _middleware(on_audit=events.append)(_context(), explodes)
        assert [event.phase for event in events] == ["attempt", "failure"]
        assert events[-1].error == "handler exploded"

    async def test_a_rejected_attempt_write_stops_the_call(self) -> None:
        def refuse(event: AuditEvent) -> None:
            raise RuntimeError("audit store unavailable")

        async def must_not_run(_: Any) -> dict[str, Any]:
            raise AssertionError("an unrecorded call must not happen")

        with pytest.raises(RuntimeError, match="audit store unavailable"):
            await _middleware(on_audit=refuse)(_context(), must_not_run)

    async def test_a_failed_terminal_write_reaches_the_error_sink(self) -> None:
        failures: list[AuditDeliveryFailure] = []

        def sink(event: AuditEvent) -> None:
            if event.phase != "attempt":
                raise RuntimeError("sink down")

        result = await _middleware(on_audit=sink, on_audit_error=failures.append)(_context(), _ran)
        assert result == {"ok": True}
        assert str(failures[0].error) == "sink down"

    async def test_names_the_approver_beside_the_caller(self) -> None:
        events: list[AuditEvent] = []

        async def approve(request: ApprovalRequest) -> ApprovalDecision:
            return ApprovalDecision(True, by="sam@acme.com")

        middleware = AuthorizationMiddleware(
            POLICY,
            {("tools/call", "read_case"): "cases:read"},
            approvals={("tools/call", "read_case"): True},
            on_approval=approve,
            on_audit=events.append,
        )
        await middleware(_context(), _ran)
        assert [event.phase for event in events] == ["attempt", "success"]

    async def test_records_a_refusal_as_its_own_phase(self) -> None:
        events: list[AuditEvent] = []

        async def refuse(request: ApprovalRequest) -> ApprovalDecision:
            return ApprovalDecision(False, by="sam@acme.com", reason="not this one")

        middleware = AuthorizationMiddleware(
            POLICY,
            {("tools/call", "read_case"): "cases:read"},
            approvals={("tools/call", "read_case"): True},
            on_approval=refuse,
            on_audit=events.append,
        )
        with pytest.raises(MCPError):
            await middleware(_context(), _ran)
        assert [event.phase for event in events] == ["attempt", "refused"]
        assert events[-1].decision == "deny"
        assert events[-1].approved_by == "sam@acme.com"


class TestTheDecisions:
    async def test_reports_the_allow_and_the_probe_for_something_never_shown(self) -> None:
        decisions: list[AuthorizationDecisionEvent] = []
        middleware = _middleware(on_decision=decisions.append)
        await middleware(_context(), _ran)

        with pytest.raises(MCPError):
            await middleware(_context("delete_case"), _ran)
        with pytest.raises(MCPError):
            await middleware(_context("never_registered"), _ran)

        assert [(event.decision, event.reason) for event in decisions] == [
            ("allow", None),
            ("deny", "policy_denied"),
            ("deny", "undeclared_capability"),
        ]

    async def test_reports_a_caller_the_policy_grants_nothing(self) -> None:
        decisions: list[AuthorizationDecisionEvent] = []
        policy = define_policy({"roles": {"reader": ["cases:read"]}, "rules": []})
        middleware = AuthorizationMiddleware(policy, {}, on_decision=decisions.append)
        with pytest.raises(MCPError):
            await middleware(_context(), _ran)
        assert decisions[0].reason == "not_permitted"
        assert decisions[0].permissions == []


class TestTheWrappedSeam:
    """gate(): their tools, your log."""

    def _reader(self) -> Principal:
        return Principal(
            issuer="https://auth.example.com",
            sub="user-1",
            email="reader@acme.com",
            domain="acme.com",
            roles=("reader",),
            permissions=("cases:read",),
        )

    async def test_records_a_call_into_a_server_somebody_else_wrote(self) -> None:
        events: list[AuditEvent] = []
        server = gate(
            MCPServer("theirs"),
            self._reader(),
            {"get_case": "cases:read", "delete_run": "cases:delete"},
            on_audit=events.append,
        )
        server.add_tool(lambda: {"id": "C1"}, name="get_case")
        server.add_tool(lambda: {"ok": True}, name="delete_run")

        assert sorted(tool.name for tool in await server.list_tools()) == ["get_case"]
        await server.call_tool("get_case", {})
        assert [event.phase for event in events] == ["attempt", "success"]
        assert events[-1].name == "get_case"
        assert events[-1].kind == "tool"
        assert events[-1].email == "reader@acme.com"

    async def test_records_a_tool_that_raised(self) -> None:
        events: list[AuditEvent] = []

        def explodes() -> dict[str, Any]:
            raise RuntimeError("their tool exploded")

        server = gate(MCPServer("theirs"), self._reader(), {"boom": "cases:read"}, on_audit=events.append)
        server.add_tool(explodes, name="boom")
        with pytest.raises(Exception, match="their tool exploded"):
            await server.call_tool("boom", {})
        assert [event.phase for event in events] == ["attempt", "failure"]
