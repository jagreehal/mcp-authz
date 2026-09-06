"""The proxy: enforcement at the edge, for a server reachable only by URL."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterable, Mapping
from typing import Any, cast

import httpx
import httpx2
import pytest
from mcp.server.auth.provider import AccessToken

from mcp_authz import AuthorizationDecisionEvent, define_policy
from mcp_authz.proxy import McpProxy

RESOURCE = "https://mcp.acme.com/mcp"
UPSTREAM = "https://vendor.example.com/mcp"
ISSUER = "https://auth.acme.com"

PERMISSIONS = {
    "get_case": "cases:read",
    "update_case": "cases:write",
    "prompt:triage": "cases:read",
    "resource:cases": "cases:read",
    "resource:case": "cases:write",
}
RESOURCE_URIS = {"resource:cases": "cases://all", "resource:case": "cases://case/{id}"}

POLICY = define_policy(
    {
        "roles": {"reader": ["cases:read"], "lead": ["cases:read", "cases:write"]},
        "rules": [
            {"match": {"email": "dana@acme.com"}, "role": "reader"},
            {"match": {"email": "alice@acme.com"}, "role": "lead"},
        ],
    }
)

CATALOGUE = {
    "jsonrpc": "2.0",
    "id": 1,
    "result": {"tools": [{"name": "get_case"}, {"name": "update_case"}, {"name": "unpriced"}]},
}


class _Verifier:
    async def verify_token(self, token: str) -> AccessToken | None:
        if "@" not in token:
            return None
        return AccessToken(
            token=token,
            client_id="agent",
            scopes=["mcp"],
            subject=f"auth0|{token}",
            claims={"iss": ISSUER, "sub": f"auth0|{token}", "email": token, "email_verified": True},
        )


class _Upstream:
    """The vendor's server, and a record of exactly what reached it."""

    def __init__(self, response: httpx2.Response | None = None) -> None:
        self.requests: list[httpx2.Request] = []
        self.response = response or httpx2.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    def client(self) -> httpx2.AsyncClient:
        async def handle(request: httpx2.Request) -> httpx2.Response:
            await request.aread()
            self.requests.append(request)
            return self.response

        return httpx2.AsyncClient(transport=httpx2.MockTransport(handle))


def _sse(chunks: Iterable[bytes], status: int = 200) -> httpx2.Response:
    async def stream() -> AsyncIterator[bytes]:
        for chunk in chunks:
            yield chunk

    return httpx2.Response(status, headers={"content-type": "text/event-stream"}, content=stream())


def _proxy(upstream: _Upstream | None = None, **overrides: Any) -> McpProxy:
    options: dict[str, Any] = {
        "resource_server_url": RESOURCE,
        "upstream_url": UPSTREAM,
        "upstream_bearer": "service-credential",
        "policy": POLICY,
        "token_verifier": _Verifier(),
        "permissions": PERMISSIONS,
        "resource_uris": RESOURCE_URIS,
        "authorization_servers": [ISSUER],
        "http_client": (upstream or _Upstream()).client(),
    }
    options.update(overrides)
    return McpProxy(**options)


async def _rpc(
    proxy: McpProxy,
    method: str,
    params: Mapping[str, Any] | None = None,
    token: str | None = "dana@acme.com",
    headers: Mapping[str, str] | None = None,
    path: str = "/mcp",
) -> httpx.Response:
    sent = {"content-type": "application/json", **(headers or {})}
    if token:
        sent["authorization"] = f"Bearer {token}"
    transport = httpx.ASGITransport(app=cast(Any, proxy))
    async with httpx.AsyncClient(transport=transport, base_url="https://mcp.acme.com") as client:
        return await client.post(
            path,
            headers=sent,
            content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}),
        )


def _events(body: str) -> list[dict[str, Any]]:
    payloads = []
    for block in body.replace("\r\n", "\n").replace("\r", "\n").split("\n\n"):
        data = [line.split(":", 1)[1].lstrip(" ") for line in block.split("\n") if line.startswith("data:")]
        if data:
            payloads.append(json.loads("\n".join(data)))
    return payloads


class TestTheBearerGate:
    async def test_refuses_before_the_upstream_is_contacted(self) -> None:
        upstream = _Upstream()
        response = await _rpc(_proxy(upstream), "tools/list", token=None)
        assert response.status_code == 401
        assert "resource_metadata=" in response.headers["www-authenticate"]
        assert upstream.requests == []

    async def test_refuses_a_caller_the_policy_grants_nothing(self) -> None:
        upstream = _Upstream()
        decisions: list[AuthorizationDecisionEvent] = []
        proxy = _proxy(upstream, on_decision=decisions.append)
        response = await _rpc(proxy, "tools/list", token="sam@other.com")
        assert response.status_code == 403
        assert response.json()["reason"] == "policy_denied"
        assert upstream.requests == []
        assert decisions[0].reason == "not_permitted"

    async def test_answers_health_and_metadata_without_a_token(self) -> None:
        transport = httpx.ASGITransport(app=cast(Any, _proxy()))
        async with httpx.AsyncClient(transport=transport, base_url="https://mcp.acme.com") as client:
            health = await client.get("/health")
            metadata = await client.get("/.well-known/oauth-protected-resource/mcp")
        assert health.json() == {
            "ok": True,
            "mode": "proxy",
            "resource": RESOURCE,
            "authorization": {"mode": "policy", "roles": 2},
            "capabilities": 5,
        }
        assert UPSTREAM not in health.text
        assert metadata.json()["authorization_servers"] == [ISSUER]

    async def test_explains_a_path_the_tokens_are_not_bound_to(self) -> None:
        response = await _rpc(_proxy(), "tools/list", path="/somewhere-else")
        assert response.status_code == 404
        assert "/mcp" in response.text


class TestPricingTheCall:
    async def test_forwards_a_permitted_call_on_the_service_credential(self) -> None:
        upstream = _Upstream()
        response = await _rpc(_proxy(upstream), "tools/call", {"name": "get_case"})
        assert response.status_code == 200
        assert upstream.requests[0].headers["authorization"] == "Bearer service-credential"

    async def test_refuses_a_denied_call_before_the_upstream_runs(self) -> None:
        upstream = _Upstream()
        response = await _rpc(_proxy(upstream), "tools/call", {"name": "update_case"})
        assert response.status_code == 403
        assert "cases:write" in response.json()["error_description"]
        assert upstream.requests == []

    async def test_refuses_a_call_nobody_priced(self) -> None:
        upstream = _Upstream()
        response = await _rpc(_proxy(upstream), "tools/call", {"name": "unpriced"}, token="alice@acme.com")
        assert response.status_code == 403
        assert "not priced" in response.json()["error_description"]
        assert upstream.requests == []

    async def test_refuses_an_invocation_that_names_nothing(self) -> None:
        response = await _rpc(_proxy(), "tools/call", {})
        assert response.status_code == 403
        assert "names no capability" in response.json()["error_description"]

    async def test_authorises_a_read_by_uri_template_included(self) -> None:
        upstream = _Upstream()
        proxy = _proxy(upstream)
        allowed = await _rpc(proxy, "resources/read", {"uri": "cases://all"})
        assert allowed.status_code == 200

        refused = await _rpc(proxy, "resources/read", {"uri": "cases://case/C1"})
        assert refused.status_code == 403
        assert "cases:write" in refused.json()["error_description"]

    async def test_refuses_a_read_no_priced_uri_covers(self) -> None:
        response = await _rpc(_proxy(), "resources/read", {"uri": "cases://secret"})
        assert response.status_code == 403
        assert "not priced" in response.json()["error_description"]

    async def test_does_not_forward_the_callers_credentials(self) -> None:
        upstream = _Upstream()
        proxy = _proxy(upstream)
        await _rpc(proxy, "tools/call", {"name": "get_case"}, headers={"cookie": "session=secret"})
        forwarded = upstream.requests[0].headers
        assert forwarded["authorization"] == "Bearer service-credential"
        assert "cookie" not in forwarded


class TestClassification:
    async def test_refuses_a_body_that_is_not_json(self) -> None:
        upstream = _Upstream()
        transport = httpx.ASGITransport(app=cast(Any, _proxy(upstream)))
        async with httpx.AsyncClient(transport=transport, base_url="https://mcp.acme.com") as client:
            response = await client.post(
                "/mcp",
                headers={"authorization": "Bearer dana@acme.com", "content-type": "text/plain"},
                content="not json",
            )
        assert response.status_code == 415
        assert upstream.requests == []

    async def test_refuses_a_malformed_json_body(self) -> None:
        transport = httpx.ASGITransport(app=cast(Any, _proxy()))
        async with httpx.AsyncClient(transport=transport, base_url="https://mcp.acme.com") as client:
            response = await client.post(
                "/mcp",
                headers={"authorization": "Bearer dana@acme.com", "content-type": "application/json"},
                content="{",
            )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == -32700

    async def test_refuses_routing_headers_that_disagree_with_the_body(self) -> None:
        upstream = _Upstream()
        response = await _rpc(
            _proxy(upstream),
            "tools/call",
            {"name": "get_case"},
            headers={
                "mcp-protocol-version": "2026-07-28",
                "mcp-method": "tools/call",
                "mcp-name": "update_case",
            },
        )
        assert response.status_code == 400
        assert upstream.requests == []

    async def test_refuses_a_body_over_the_cap(self) -> None:
        upstream = _Upstream()
        proxy = _proxy(upstream, max_request_bytes=64)
        response = await _rpc(proxy, "tools/call", {"name": "get_case", "padding": "x" * 200})
        assert response.status_code == 413
        assert upstream.requests == []

    async def test_prices_a_request_that_carries_no_routing_headers(self) -> None:
        upstream = _Upstream()
        response = await _rpc(_proxy(upstream), "tools/call", {"name": "update_case"})
        assert response.status_code == 403
        assert upstream.requests == []


class TestFilteringTheCatalogue:
    async def test_filters_a_json_listing_to_what_the_caller_may_reach(self) -> None:
        upstream = _Upstream(httpx2.Response(200, json=CATALOGUE))
        response = await _rpc(_proxy(upstream), "tools/list")
        assert [tool["name"] for tool in response.json()["result"]["tools"]] == ["get_case"]

    async def test_widens_the_same_listing_for_a_lead(self) -> None:
        upstream = _Upstream(httpx2.Response(200, json=CATALOGUE))
        response = await _rpc(_proxy(upstream), "tools/list", token="alice@acme.com")
        assert [tool["name"] for tool in response.json()["result"]["tools"]] == ["get_case", "update_case"]

    async def test_filters_prompts_and_resources_the_same_way(self) -> None:
        listing = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"resources": [{"name": "cases"}, {"name": "case"}]},
        }
        upstream = _Upstream(httpx2.Response(200, json=listing))
        response = await _rpc(_proxy(upstream), "resources/list")
        assert [item["name"] for item in response.json()["result"]["resources"]] == ["cases"]

    async def test_passes_an_error_reply_through_untouched(self) -> None:
        reply = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "no"}}
        upstream = _Upstream(httpx2.Response(200, json=reply))
        response = await _rpc(_proxy(upstream), "tools/list")
        assert response.json() == reply

    async def test_withholds_a_listing_it_cannot_read(self) -> None:
        upstream = _Upstream(httpx2.Response(200, headers={"content-type": "text/plain"}, content=b"tools"))
        response = await _rpc(_proxy(upstream), "tools/list")
        assert response.status_code == 502
        assert "could not be filtered" in response.json()["error"]["message"]

    async def test_withholds_a_listing_larger_than_the_cap(self) -> None:
        big = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "x" * 500}]}}
        upstream = _Upstream(httpx2.Response(200, json=big))
        response = await _rpc(_proxy(upstream, max_request_bytes=200), "tools/list")
        assert response.status_code == 502

    async def test_does_not_keep_framing_headers_for_a_body_it_rewrote(self) -> None:
        upstream = _Upstream(
            httpx2.Response(
                200,
                headers={"content-type": "application/json", "content-encoding": "identity"},
                json=CATALOGUE,
            )
        )
        response = await _rpc(_proxy(upstream), "tools/list")
        assert "content-encoding" not in response.headers
        assert "content-length" not in response.headers  # the server frames what we actually sent


class TestFilteringAnEventStream:
    def _event(self, payload: Mapping[str, Any], terminator: bytes = b"\n\n") -> bytes:
        return b"data: " + json.dumps(payload).encode() + terminator

    async def test_filters_a_listing_carried_over_sse(self) -> None:
        upstream = _Upstream(_sse([self._event(CATALOGUE)]))
        response = await _rpc(_proxy(upstream), "tools/list")
        assert [tool["name"] for tool in _events(response.text)[0]["result"]["tools"]] == ["get_case"]

    async def test_filters_events_framed_with_bare_carriage_returns_and_a_bom(self) -> None:
        body = "﻿".encode() + self._event(CATALOGUE, b"\r\r")
        upstream = _Upstream(_sse([body]))
        response = await _rpc(_proxy(upstream), "tools/list")
        assert [tool["name"] for tool in _events(response.text)[0]["result"]["tools"]] == ["get_case"]

    async def test_filters_an_event_split_across_chunks(self) -> None:
        raw = self._event(CATALOGUE, b"\r\n\r\n")
        upstream = _Upstream(_sse([raw[:20], raw[20:-3], raw[-3:]]))
        response = await _rpc(_proxy(upstream), "tools/list")
        assert [tool["name"] for tool in _events(response.text)[0]["result"]["tools"]] == ["get_case"]

    async def test_filters_a_payload_spread_over_several_data_lines(self) -> None:
        # A pretty-printed payload arrives as one `data:` line per line, which
        # the client rejoins. A filter that reads only the first one sees a
        # fragment, decides it is unreadable, and withholds a valid catalogue.
        lines = "".join(f"data: {line}\n" for line in json.dumps(CATALOGUE, indent=0).split("\n"))
        body = f"event: message\n{lines}\n".encode()
        upstream = _Upstream(_sse([body]))
        response = await _rpc(_proxy(upstream), "tools/list")
        assert [tool["name"] for tool in _events(response.text)[0]["result"]["tools"]] == ["get_case"]

    async def test_refuses_an_event_that_never_ends(self) -> None:
        upstream = _Upstream(_sse([b"data: " + b"x" * 400]))
        response = await _rpc(_proxy(upstream, max_request_bytes=200), "tools/list")
        assert _events(response.text)[0]["error"]["code"] == -32010
        assert _events(response.text)[0]["id"] == 1

    async def test_counts_the_cap_in_bytes_not_characters(self) -> None:
        # 100 characters, 300 bytes: a cap read in characters would let it past.
        payload = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "☃" * 100}]}}
        upstream = _Upstream(_sse([self._event(payload)]))
        response = await _rpc(_proxy(upstream, max_request_bytes=200), "tools/list")
        assert _events(response.text)[0]["error"]["code"] == -32010

    async def test_counts_bytes_when_multibyte_characters_straddle_chunks(self) -> None:
        payload = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "get_case", "d": "é" * 20}]}}
        raw = b"data: " + json.dumps(payload, ensure_ascii=False).encode() + b"\n\n"
        split = raw.index(b"\xc3") + 1  # between the two bytes of an é
        upstream = _Upstream(_sse([raw[:split], raw[split:]]))
        response = await _rpc(_proxy(upstream), "tools/list")
        assert [tool["name"] for tool in _events(response.text)[0]["result"]["tools"]] == ["get_case"]

    async def test_answers_an_unreadable_event_under_the_id_the_client_awaits(self) -> None:
        upstream = _Upstream(_sse([b"data: not json\n\n"]))
        response = await _rpc(_proxy(upstream), "tools/list")
        answered = _events(response.text)[0]
        assert answered["id"] == 1
        assert "unreadable event" in answered["error"]["message"]

    async def test_passes_a_non_listing_stream_through_unparsed(self) -> None:
        upstream = _Upstream(_sse([b"data: not json at all\n\n"]))
        response = await _rpc(_proxy(upstream), "tools/call", {"name": "get_case"})
        assert response.text == "data: not json at all\n\n"


class TestTheBootChecks:
    def test_refuses_a_priced_resource_with_no_uri_to_match_reads_against(self) -> None:
        with pytest.raises(ValueError, match=r"resources/read by URI"):
            _proxy(resource_uris={"resource:cases": "cases://all"})

    def test_refuses_a_uri_naming_no_priced_capability(self) -> None:
        with pytest.raises(ValueError, match=r"names no priced capability"):
            _proxy(resource_uris={**RESOURCE_URIS, "resource:ghost": "cases://ghost"})

    def test_refuses_an_empty_permission(self) -> None:
        with pytest.raises(ValueError, match=r"non-empty"):
            _proxy(permissions={"get_case": ""}, resource_uris={})

    def test_refuses_a_permission_no_role_grants(self) -> None:
        with pytest.raises(ValueError, match=r"Unreachable capability"):
            _proxy(permissions={"get_case": "cases:purge"}, resource_uris={})
