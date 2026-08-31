from typing import Any, cast

import httpx
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from pydantic import AnyHttpUrl

from mcp_authz import AuthorizedMCPServer, define_policy

_META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
}


class _Verifier:
    async def verify_token(self, token: str) -> AccessToken | None:
        if token != "reader-token":
            return None
        return AccessToken(
            token=token,
            client_id="test-client",
            scopes=["mcp"],
            subject="reader-1",
            claims={
                "iss": "https://auth.example.com",
                "sub": "reader-1",
                "email": "reader@acme.com",
                "email_verified": True,
                "hd": "acme.com",
            },
        )


async def test_http_transport_hides_and_refuses_an_unpermitted_tool() -> None:
    policy = define_policy(
        {
            "roles": {"reader": ["cases:read"], "editor": ["cases:write"]},
            "rules": [{"match": {"sub": "reader-1"}, "role": "reader"}],
        }
    )
    server = AuthorizedMCPServer(
        "test",
        policy=policy,
        token_verifier=_Verifier(),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl("https://auth.example.com"),
            resource_server_url=AnyHttpUrl("https://mcp.example.com/mcp"),
            required_scopes=["mcp"],
        ),
    )

    @server.tool(permission="cases:read")
    def get_case() -> dict[str, str]:
        return {"id": "C1234"}

    @server.tool(permission="cases:write")
    def update_case() -> dict[str, str]:
        raise AssertionError("an unpermitted tool must not run")

    app = server.streamable_http_app(stateless_http=True, json_response=True, host="mcp.example.com")
    headers = {
        "Authorization": "Bearer reader-token",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
    }
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="https://mcp.example.com") as client,
    ):
        listed = await _request(client, headers, "tools/list", {})
        refused = await _request(client, headers, "tools/call", {"name": "update_case", "arguments": {}})

    assert [tool["name"] for tool in listed["result"]["tools"]] == ["get_case"]
    assert refused["error"]["code"] == -32003
    assert refused["error"]["data"]["reason"] == "policy_denied"


async def _request(
    client: httpx.AsyncClient, headers: dict[str, str], method: str, params: dict[str, Any]
) -> dict[str, Any]:
    name = params.get("name")
    response = await client.post(
        "/mcp",
        headers={**headers, "Mcp-Method": method, **({"Mcp-Name": name} if isinstance(name, str) else {})},
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": {**params, "_meta": _META}},
    )
    assert response.status_code == 200
    return cast(dict[str, Any], response.json())
