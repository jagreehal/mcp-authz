"""The OpenAPI middleware: the document per caller, and every way it says no."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from typing import Any, cast

import httpx
import pytest
from mcp.server.auth.provider import AccessToken

from mcp_authz import AuditEvent, AuthorizationDecisionEvent, define_policy
from mcp_authz.openapi import (
    OpenApiAuthorizationMiddleware,
    filter_spec,
    record_operations,
    to_permissions_module,
)

RESOURCE = "https://api.acme.com"
ISSUER = "https://auth.acme.com"

SPEC: dict[str, Any] = {
    "openapi": "3.1.0",
    "info": {"title": "case-tracker", "version": "3.2.0"},
    "paths": {
        "/cases": {
            "get": {"operationId": "listCases"},
            "post": {"operationId": "createCase"},
        },
        # Listed before the template on purpose: a document is written for
        # people, and the matcher may not depend on which order they chose.
        "/cases/search": {"get": {"operationId": "searchCases"}},
        "/cases/{id}": {
            "parameters": [{"name": "id", "in": "path"}],
            "get": {"operationId": "getCase"},
            "delete": {"operationId": "deleteCase"},
        },
    },
}

PERMISSIONS = {
    "listCases": "cases:read",
    "searchCases": "cases:read",
    "getCase": "cases:read",
    "createCase": "cases:write",
    "deleteCase": "cases:delete",
}

POLICY = define_policy(
    {
        "roles": {
            "reader": ["cases:read"],
            "lead": ["cases:read", "cases:write", "cases:delete"],
        },
        "rules": [
            {"match": {"email": "dana@acme.com"}, "role": "reader"},
            {"match": {"email": "alice@acme.com"}, "role": "lead"},
        ],
    }
)


class _Verifier:
    """Tokens are a name here: verification itself is covered by test_verifier."""

    async def verify_token(self, token: str) -> AccessToken | None:
        if "@" not in token:
            return None
        return AccessToken(
            token=token,
            client_id="agent",
            scopes=["api"],
            subject=f"auth0|{token}",
            claims={"iss": ISSUER, "sub": f"auth0|{token}", "email": token, "email_verified": True},
        )


async def _served(scope: MutableMapping[str, Any], receive: Any, send: Any) -> None:
    """The API itself: it never learns that any of this happened."""

    body = f'{{"served":"{scope["method"]} {scope["path"]}"}}'.encode()
    status = 409 if scope["path"].endswith("/conflict") else 200
    await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": body})


def _gated(**overrides: Any) -> OpenApiAuthorizationMiddleware:
    options: dict[str, Any] = {
        "spec": SPEC,
        "permissions": PERMISSIONS,
        "policy": POLICY,
        "token_verifier": _Verifier(),
        "resource_server_url": RESOURCE,
        "authorization_servers": [ISSUER],
    }
    options.update(overrides)
    return OpenApiAuthorizationMiddleware(_served, **options)


async def _call(
    app: OpenApiAuthorizationMiddleware, method: str, path: str, token: str | None = "dana@acme.com"
) -> httpx.Response:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    transport = httpx.ASGITransport(app=cast(Any, app))
    async with httpx.AsyncClient(transport=transport, base_url=RESOURCE) as client:
        return await client.request(method, path, headers=headers)


def _offered(document: Mapping[str, Any]) -> list[str]:
    return sorted(
        f"{method.upper()} {path}"
        for path, item in document["paths"].items()
        for method, value in item.items()
        if isinstance(value, Mapping) and value.get("operationId")
    )


class TestRecordOperations:
    def test_names_every_operation_sorted(self) -> None:
        assert record_operations(SPEC).names == [
            "createCase",
            "deleteCase",
            "getCase",
            "listCases",
            "searchCases",
        ]

    def test_refuses_an_operation_with_no_id(self) -> None:
        with pytest.raises(ValueError, match=r"GET /x has no operationId"):
            record_operations({"paths": {"/x": {"get": {"summary": "no id"}}}})

    def test_refuses_one_id_on_two_routes(self) -> None:
        with pytest.raises(ValueError, match=r"used by both GET /a and GET /b"):
            record_operations(
                {"paths": {"/a": {"get": {"operationId": "same"}}, "/b": {"get": {"operationId": "same"}}}}
            )

    def test_ignores_path_items_that_are_not_operations(self) -> None:
        record = record_operations({"paths": {"/x": {"parameters": [], "summary": "nothing"}, "/y": None}})
        assert record.names == []

    def test_scaffolds_a_map_nobody_can_forget_to_price(self) -> None:
        module = to_permissions_module(record_operations(SPEC))
        assert '"deleteCase": "TODO:unassigned",' in module


class TestFilterSpec:
    def test_drops_an_emptied_path_and_keeps_the_document(self) -> None:
        reader = POLICY.__call__(_identity("dana@acme.com"))
        filtered = filter_spec(SPEC, reader, PERMISSIONS)
        assert _offered(filtered) == ["GET /cases", "GET /cases/search", "GET /cases/{id}"]
        assert "delete" not in filtered["paths"]["/cases/{id}"]
        assert filtered["openapi"] == "3.1.0"

    def test_a_caller_with_nothing_gets_no_paths(self) -> None:
        nobody = POLICY.__call__(_identity("sam@other.com"))
        assert filter_spec(SPEC, nobody, PERMISSIONS)["paths"] == {}


class TestBootChecks:
    def test_refuses_an_operation_the_map_does_not_price(self) -> None:
        with pytest.raises(ValueError, match=r"puts no price on 'createCase'"):
            _gated(permissions={"listCases": "cases:read"})

    def test_refuses_a_map_entry_with_no_operation(self) -> None:
        with pytest.raises(ValueError, match=r"prices 'closeCase'"):
            _gated(permissions={**PERMISSIONS, "closeCase": "cases:write"})

    def test_refuses_a_permission_no_role_grants(self) -> None:
        with pytest.raises(ValueError, match=r"Unreachable operation"):
            _gated(permissions={**PERMISSIONS, "deleteCase": "cases:purge"})


class TestTheDocument:
    async def test_each_caller_is_offered_only_what_they_may_do(self) -> None:
        app = _gated()
        dana = await _call(app, "GET", "/openapi.json", "dana@acme.com")
        alice = await _call(app, "GET", "/openapi.json", "alice@acme.com")
        assert _offered(dana.json()) == ["GET /cases", "GET /cases/search", "GET /cases/{id}"]
        assert "DELETE /cases/{id}" in _offered(alice.json())
        assert "POST /cases" in _offered(alice.json())

    async def test_what_the_document_offers_is_served(self) -> None:
        response = await _call(_gated(), "GET", "/cases/C1234")
        assert response.status_code == 200
        assert response.json() == {"served": "GET /cases/C1234"}


class TestTheRefusals:
    async def test_challenges_a_request_with_no_token(self) -> None:
        response = await _call(_gated(), "GET", "/cases", None)
        assert response.status_code == 401
        assert "resource_metadata=" in response.headers["www-authenticate"]

    async def test_refuses_a_token_missing_the_baseline_scope(self) -> None:
        app = _gated(required_scopes=["api", "cases"])
        response = await _call(app, "GET", "/cases")
        assert response.status_code == 403
        assert response.json()["error"] == "insufficient_scope"

    async def test_refuses_a_caller_the_policy_grants_nothing(self) -> None:
        response = await _call(_gated(), "GET", "/cases", "sam@other.com")
        assert response.status_code == 403
        assert response.json()["reason"] == "policy_denied"

    async def test_refuses_the_operation_an_agent_never_saw(self) -> None:
        response = await _call(_gated(), "DELETE", "/cases/C1234", "dana@acme.com")
        assert response.status_code == 403
        assert "cases:delete" in response.json()["error_description"]

    async def test_refuses_a_route_the_document_does_not_describe(self) -> None:
        response = await _call(_gated(), "POST", "/cases/C1/export", "alice@acme.com")
        assert response.status_code == 404
        assert "Describe it in the OpenAPI document" in response.json()["error_description"]

    async def test_a_template_does_not_swallow_a_deeper_path(self) -> None:
        assert (await _call(_gated(), "GET", "/cases/C1/notes")).status_code == 404

    async def test_a_concrete_path_beats_a_template_that_would_also_fit(self) -> None:
        assert (await _call(_gated(), "GET", "/cases/search")).status_code == 200

    async def test_explains_a_path_outside_the_url_tokens_are_bound_to(self) -> None:
        app = _gated(resource_server_url="https://api.acme.com/v1")
        response = await _call(app, "GET", "/cases")
        assert response.status_code == 404
        assert "/v1" in response.text

    async def test_serves_protected_resource_metadata_unauthenticated(self) -> None:
        response = await _call(_gated(), "GET", "/.well-known/oauth-protected-resource", None)
        assert response.status_code == 200
        assert response.json()["authorization_servers"] == [ISSUER]


class TestTheAuditTrail:
    async def test_records_who_called_what(self) -> None:
        events: list[AuditEvent] = []
        decisions: list[AuthorizationDecisionEvent] = []
        app = _gated(on_audit=events.append, on_decision=decisions.append, emitter="cases-api")
        assert (await _call(app, "POST", "/cases", "alice@acme.com")).status_code == 200
        assert [event.phase for event in events] == ["attempt", "success"]
        assert len({event.call_id for event in events}) == 1
        assert events[-1].to_dict() | {"at": "", "durationMs": 0, "callId": "*"} == {
            "type": "mcp_authz.audit.v1",
            "callId": "*",
            "emitter": "cases-api",
            "issuer": ISSUER,
            "sub": "auth0|alice@acme.com",
            "email": "alice@acme.com",
            "kind": "operation",
            "name": "createCase",
            "permission": "cases:write",
            "resource": "/cases",
            "decision": "allow",
            "phase": "success",
            "at": "",
            "durationMs": 0,
        }
        assert [decision.decision for decision in decisions] == ["allow"]
        assert decisions[0].emitter == "cases-api"

    async def test_records_a_failure_when_the_api_answers_with_one(self) -> None:
        events: list[AuditEvent] = []
        spec = {"paths": {"/cases/conflict": {"post": {"operationId": "conflictCase"}}}}
        app = _gated(spec=spec, permissions={"conflictCase": "cases:write"}, on_audit=events.append)
        response = await _call(app, "POST", "/cases/conflict", "alice@acme.com")
        assert response.status_code == 409
        assert [event.phase for event in events] == ["attempt", "failure"]
        assert events[-1].error == "HTTP 409"

    async def test_refuses_the_call_when_the_attempt_write_is_rejected(self) -> None:
        def refuse(event: AuditEvent) -> None:
            raise RuntimeError("audit store unavailable")

        response = await _call(_gated(on_audit=refuse), "GET", "/cases")
        assert response.status_code == 503

    async def test_offers_a_failed_terminal_write_to_the_error_sink(self) -> None:
        failures: list[Any] = []

        def sink(event: AuditEvent) -> None:
            if event.phase != "attempt":
                raise RuntimeError("sink down")

        app = _gated(on_audit=sink, on_audit_error=failures.append)
        assert (await _call(app, "GET", "/cases")).status_code == 200
        assert str(failures[0].error) == "sink down"


def _identity(email: str) -> Any:
    from mcp_authz import Identity

    return Identity(issuer=ISSUER, sub=f"auth0|{email}", email=email, email_verified=True)
