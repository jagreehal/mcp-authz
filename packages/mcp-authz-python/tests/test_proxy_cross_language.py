"""The Python proxy against the shared test server, with definitions the TypeScript CLI recorded.

Two implementations of one contract can each pass their own tests and still
disagree: a record written by one and compared by the other is where a
canonicalisation difference shows up, as a false positive that hides an honest
tool. So this records with the real CLI and enforces with the real proxy.

Needs Node 24, the workspace's node_modules and a built CLI
(``pnpm install && pnpm --filter mcp-authz build``); skips without them.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
from mcp.server.auth.provider import AccessToken

from mcp_authz import define_policy
from mcp_authz.proxy import McpProxy

ROOT = Path(__file__).parents[3]
CLI = ROOT / "packages" / "mcp-authz" / "dist" / "cli.js"
TEST_SERVER = ROOT / "apps" / "test-server"
NODE = shutil.which("node")
MODERN = "2026-07-28"

# CI sets this, so the test runs there rather than skipping.
REQUIRED = os.environ.get("MCP_AUTHZ_CROSS_LANGUAGE") == "1"

pytestmark = pytest.mark.skipif(
    not REQUIRED and (NODE is None or not CLI.exists() or not (TEST_SERVER / "node_modules" / "tsx").exists()),
    reason="needs node, apps/test-server/node_modules and a built TypeScript CLI "
    "(pnpm install && pnpm --filter mcp-authz build)",
)

PRICES = {
    "search_cases": "cases:read",
    "get_case": "cases:read",
    "count_cases": "cases:read",
    "get_account": "cases:read",
    "transfer_credit": "cases:write",
    "prompt:triage": "cases:read",
    "resource:cases": "cases:read",
    "resource:case": "cases:read",
    "resource:secrets": "cases:read",
    "update_case": "cases:write",
    "delete_case": "cases:write",
    "run_query": "cases:write",
    "prompt:payroll_report": "payroll:read",
    "resource:payroll": "payroll:read",
}

POLICY = define_policy(
    {
        "roles": {"reader": ["cases:read"], "admin": ["cases:read", "cases:write", "payroll:read"]},
        "rules": [
            {"match": {"email": "dana@acme.com"}, "role": "reader"},
            {"match": {"email": "root@acme.com"}, "role": "admin"},
        ],
    }
)


class _Verifier:
    async def verify_token(self, token: str) -> AccessToken | None:
        return AccessToken(
            token=token,
            client_id="agent",
            scopes=["mcp"],
            subject=token,
            claims={"iss": "https://auth.acme.com", "sub": token, "email": token, "email_verified": True},
        )


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return cast(int, probe.getsockname()[1])


@contextmanager
def _upstream(**env: str) -> Iterator[str]:
    """The test server over HTTP, behind the service token ``svc``."""

    port = _free_port()
    process = subprocess.Popen(
        [cast(str, NODE), "--import", "tsx", "src/server.ts", "--http"],
        cwd=TEST_SERVER,
        env={**os.environ, "PORT": str(port), "TOKEN": "svc", **env},
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stderr is not None
        line = process.stderr.readline()  # blocks until it listens, or exits
        assert "test server on" in line, f"test server did not start: {line}{process.stderr.read()}"
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        process.terminate()
        process.wait(timeout=10)


def _node(*args: str) -> str:
    return subprocess.run([cast(str, NODE), *args], check=True, capture_output=True, text=True, cwd=ROOT).stdout


@pytest.fixture(scope="module")
def recorded(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """PERMISSIONS, DEFINITIONS and RESOURCE_URIS as the TypeScript CLI writes them, from a clean server."""

    module = tmp_path_factory.mktemp("record") / "permissions.ts"
    with _upstream() as url:
        _node(str(CLI), "record", "--upstream", url, "--token", "svc", "--out", str(module))
    # Node 24 strips the module's types natively, so it is read as written.
    script = (
        "const m = await import(process.argv[1]);"
        "console.log(JSON.stringify({permissions: m.PERMISSIONS, definitions: m.DEFINITIONS, uris: m.RESOURCE_URIS}))"
    )
    return cast(dict[str, Any], json.loads(_node("--input-type=module", "-e", script, module.as_uri())))


def _proxy(recorded: Mapping[str, Any], url: str) -> McpProxy:
    assert all(value.startswith("TODO") for value in recorded["permissions"].values())
    assert set(recorded["permissions"]) == set(PRICES)
    return McpProxy(
        resource_server_url="https://mcp.acme.com/mcp",
        upstream_url=url,
        upstream_bearer="svc",
        policy=POLICY,
        token_verifier=_Verifier(),
        permissions=PRICES,
        definitions=recorded["definitions"],
        resource_uris=recorded["uris"],
    )


async def _rpc(
    proxy: McpProxy,
    method: str,
    params: Mapping[str, Any] | None = None,
    token: str = "dana@acme.com",
    literals: Mapping[str, str] | None = None,
) -> httpx.Response:
    """One request as a 2026-07-28 client sends it, as the reader dana."""

    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": {
            **(params or {}),
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN,
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {"name": "cross-language", "version": "1"},
            },
        },
    }
    headers = {
        "authorization": f"Bearer {token}",
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
        "mcp-protocol-version": MODERN,
        "mcp-method": method,
    }
    named = (params or {}).get("uri" if method == "resources/read" else "name")
    if isinstance(named, str) and method in ("tools/call", "prompts/get", "resources/read"):
        headers["mcp-name"] = named
    transport = httpx.ASGITransport(app=cast(Any, proxy))
    async with httpx.AsyncClient(transport=transport, base_url="https://mcp.acme.com", timeout=30) as client:
        content = json.dumps(body)
        # A string placeholder swapped for a number's literal text, for numbers
        # Python would not write the way a client might.
        for placeholder, literal in (literals or {}).items():
            content = content.replace(json.dumps(placeholder), literal)
        return await client.post("/mcp", headers=headers, content=content)


def _message(response: httpx.Response) -> dict[str, Any]:
    """The JSON-RPC reply, whether it came back as JSON or as an event stream."""

    if "text/event-stream" not in response.headers.get("content-type", ""):
        return cast(dict[str, Any], response.json())
    for block in response.text.replace("\r\n", "\n").split("\n\n"):
        data = [line[5:].lstrip(" ") for line in block.split("\n") if line.startswith("data:")]
        if data and "id" in (message := json.loads("\n".join(data))):
            return cast(dict[str, Any], message)
    raise AssertionError(f"no reply in {response.text!r}")


async def test_a_clean_upstream_matches_its_typescript_record(recorded: dict[str, Any]) -> None:
    with _upstream() as url:
        proxy = _proxy(recorded, url)
        # Before any listing: the proxy reads the catalogue itself, and must not
        # mistake a difference in canonicalisation for a changed definition.
        called = await _rpc(proxy, "tools/call", {"name": "get_case", "arguments": {"id": "C-101"}})
        assert called.status_code == 200, called.text
        assert "result" in _message(called)

        listed = await _rpc(proxy, "tools/list")
        result = _message(listed)["result"]
        assert sorted(tool["name"] for tool in result["tools"]) == [
            "count_cases",
            "get_account",
            "get_case",
            "search_cases",
        ]
        assert result["cacheScope"] == "private"
        assert listed.headers["cache-control"] == "private, no-store"

        discovered = _message(await _rpc(proxy, "server/discover"))["result"]
        assert discovered["instructions"] == recorded["definitions"]["server:instructions"]["instructions"]


async def test_a_rug_pulled_tool_is_refused_before_any_listing(recorded: dict[str, Any]) -> None:
    with _upstream(RUG_PULL="1") as url:
        proxy = _proxy(recorded, url)
        refused = await _rpc(proxy, "tools/call", {"name": "search_cases", "arguments": {"query": "login"}})
        assert refused.status_code == 403
        assert "'search_cases' changed since it was recorded" in refused.json()["error_description"]
        allowed = await _rpc(proxy, "tools/call", {"name": "get_case", "arguments": {"id": "C-101"}})
        assert allowed.status_code == 200


async def test_rewritten_instructions_are_withheld(recorded: dict[str, Any]) -> None:
    with _upstream(INSTRUCTIONS_RUG_PULL="1") as url:
        discovered = _message(await _rpc(_proxy(recorded, url), "server/discover"))["result"]
        assert "instructions" not in discovered


async def test_completion_and_subscription_are_priced_as_what_they_reach(recorded: dict[str, Any]) -> None:
    with _upstream() as url:
        proxy = _proxy(recorded, url)
        payroll = {"ref": {"type": "ref/prompt", "name": "payroll_report"}, "argument": {"name": "month", "value": "2"}}
        assert (await _rpc(proxy, "completion/complete", payroll)).status_code == 403

        triage = {"ref": {"type": "ref/prompt", "name": "triage"}, "argument": {"name": "case", "value": "C-1"}}
        completed = await _rpc(proxy, "completion/complete", triage)
        assert completed.status_code == 200, completed.text
        assert _message(completed)["result"]["completion"]["values"] == ["C-101", "C-102"]

        listen = {"notifications": {"resourceSubscriptions": ["secret://payroll"]}}
        assert (await _rpc(proxy, "subscriptions/listen", listen)).status_code == 403


async def test_a_read_covered_by_a_broad_template_and_an_exact_resource_needs_both(
    recorded: dict[str, Any],
) -> None:
    with _upstream() as url:
        proxy = _proxy(recorded, url)
        refused = await _rpc(proxy, "resources/read", {"uri": "secret://payroll"})
        assert refused.status_code == 403
        assert "payroll:read" in refused.json()["error_description"]
        # The broad template alone is the reader's to use.
        allowed = await _rpc(proxy, "resources/read", {"uri": "secret://notes"})
        assert allowed.status_code == 200, allowed.text


async def test_arguments_are_held_to_the_recorded_input_schema(recorded: dict[str, Any]) -> None:
    with _upstream() as url:
        proxy = _proxy(recorded, url)
        long = await _rpc(proxy, "tools/call", {"name": "search_cases", "arguments": {"query": "x" * 201}})
        assert long.status_code == 400
        assert long.json()["error"]["code"] == -32602
        assert "inputSchema recorded for 'search_cases'" in long.json()["error"]["message"]
        fine = await _rpc(proxy, "tools/call", {"name": "search_cases", "arguments": {"query": "login"}})
        assert fine.status_code == 200, fine.text


async def test_structured_output_is_held_to_the_recorded_output_schema(recorded: dict[str, Any]) -> None:
    with _upstream() as url:
        honest = _message(await _rpc(_proxy(recorded, url), "tools/call", {"name": "count_cases", "arguments": {}}))
        assert honest["result"]["structuredContent"] == {"count": 2}
    with _upstream(BAD_OUTPUT="1") as url:
        bad = _message(await _rpc(_proxy(recorded, url), "tools/call", {"name": "count_cases", "arguments": {}}))
        assert bad["result"]["isError"] is True
        assert "does not match the outputSchema you approved" in bad["result"]["content"][0]["text"]
        assert "structuredContent" not in bad["result"]


async def test_output_addressed_to_the_model_is_flagged(recorded: dict[str, Any]) -> None:
    with _upstream(INJECTED_OUTPUT="1") as url:
        called = await _rpc(_proxy(recorded, url), "tools/call", {"name": "get_case", "arguments": {"id": "C-101"}})
        content = _message(called)["result"]["content"]
        assert content[0]["text"].startswith("⚠ mcp-authz: the output of 'get_case' contains text addressed")
        assert "attacker@example.com" in content[1]["text"]


async def test_an_embedded_resource_addressed_to_the_model_is_flagged(recorded: dict[str, Any]) -> None:
    with _upstream(INJECTED_RESOURCE="1") as url:
        called = await _rpc(_proxy(recorded, url), "tools/call", {"name": "get_case", "arguments": {"id": "C-101"}})
        content = _message(called)["result"]["content"]
        assert content[0]["text"].startswith("⚠ mcp-authz: the output of 'get_case' contains text addressed")
        assert any("id_rsa" in str(item.get("resource", {}).get("text", "")) for item in content[1:])


async def test_a_success_missing_its_promised_structured_output_is_withheld(recorded: dict[str, Any]) -> None:
    with _upstream(NO_STRUCTURED="1") as url:
        called = await _rpc(_proxy(recorded, url), "tools/call", {"name": "count_cases", "arguments": {}})
        result = _message(called)["result"]
        assert result["isError"] is True
        assert "does not match the outputSchema you approved" in result["content"][0]["text"]


async def test_an_argument_past_its_maximum_is_refused_however_it_is_written(recorded: dict[str, Any]) -> None:
    with _upstream() as url:
        proxy = _proxy(recorded, url)
        call = {"name": "transfer_credit", "arguments": {"amount": "AMOUNT"}}
        over = await _rpc(proxy, "tools/call", call, token="root@acme.com", literals={"AMOUNT": "9007199254740993e0"})
        assert over.status_code == 400
        assert "9007199254740993 is greater than the maximum" in over.json()["error"]["message"]
        at = await _rpc(proxy, "tools/call", call, token="root@acme.com", literals={"AMOUNT": "9007199254740992e0"})
        assert at.status_code == 200, at.text


async def test_big_numbers_are_checked_and_passed_on_exactly(recorded: dict[str, Any]) -> None:
    with _upstream(BIG_NUMBERS="1") as url:
        proxy = _proxy(recorded, url)
        account = _message(await _rpc(proxy, "tools/call", {"name": "get_account", "arguments": {}}))
        assert account["result"]["isError"] is True
        assert "does not match the outputSchema you approved" in account["result"]["content"][0]["text"]

        # Nothing to change, so the upstream's own bytes, numbers as written.
        counted = await _rpc(proxy, "tools/call", {"name": "count_cases", "arguments": {}})
        assert '"ratio":1.0000000000000001,"ref":9007199254740993e0' in counted.text
        assert _message(counted)["result"]["structuredContent"] == {"count": 2}


async def test_a_notice_keeps_every_number_as_written(recorded: dict[str, Any]) -> None:
    with _upstream(BIG_NUMBERS="1", INJECTED_OUTPUT="1") as url:
        called = await _rpc(_proxy(recorded, url), "tools/call", {"name": "get_case", "arguments": {"id": "C-101"}})
        assert '"ratio": 1.0000000000000001, "ref": 9007199254740993e0' in called.text
        content = _message(called)["result"]["content"]
        assert content[0]["text"].startswith("⚠ mcp-authz: the output of 'get_case' contains text addressed")
