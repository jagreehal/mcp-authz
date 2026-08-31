"""Public seams for gate(): wrap somebody else's MCPServer before registration."""

from __future__ import annotations

import pytest
from mcp.server import MCPServer
from mcp.server.mcpserver import Context

from mcp_authz import Principal, gate


def _reader() -> Principal:
    return Principal(
        issuer="https://auth.example.com",
        sub="dana",
        email="dana@acme.com",
        domain="acme.com",
        roles=("reader",),
        permissions=("testrail:read",),
    )


PERMISSIONS = {"get_case": "testrail:read", "delete_run": "testrail:delete"}


def _lead() -> Principal:
    return Principal(
        issuer="https://auth.example.com",
        sub="lead",
        email="lead@acme.com",
        domain="acme.com",
        roles=("lead",),
        permissions=("testrail:read", "testrail:delete"),
    )


def _their_builder(server: MCPServer) -> MCPServer:
    server.add_tool(lambda: {"ok": True}, name="get_case")
    server.add_tool(lambda: {"ok": True}, name="delete_run")
    return server


async def test_undeclared_tool_registration_raises() -> None:
    server = gate(MCPServer("theirs"), _reader(), {})

    with pytest.raises(ValueError, match=r"gate\(\): no permission declared for tool 'surprise'"):
        server.add_tool(lambda: "ok", name="surprise")

    assert [tool.name for tool in await server.list_tools()] == []


async def test_unpermitted_tools_are_hidden_from_list() -> None:
    server = _their_builder(gate(MCPServer("theirs"), _reader(), PERMISSIONS))
    names = sorted(tool.name for tool in await server.list_tools())
    assert names == ["get_case"]


async def test_permitted_tools_are_visible_and_callable() -> None:
    server = _their_builder(gate(MCPServer("theirs"), _lead(), PERMISSIONS))
    names = sorted(tool.name for tool in await server.list_tools())
    assert names == ["delete_run", "get_case"]

    result = await server.call_tool("get_case", {})
    assert result is not None


def test_approval_without_sink_fails_at_registration() -> None:
    with pytest.raises(ValueError, match=r"gate\(\): tool 'delete_run' asks for approval"):
        gate(
            MCPServer("theirs"),
            _lead(),
            PERMISSIONS,
            approval={"delete_run": True},
        ).add_tool(lambda: "gone", name="delete_run")


async def test_approval_refused_stops_the_handler() -> None:
    from mcp.shared.exceptions import MCPError

    from mcp_authz import ApprovalDecision, ApprovalRequest

    ran = False

    async def refuse(_: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(False, by="sam@acme.com", reason="not during the freeze")

    def delete_run() -> str:
        nonlocal ran
        ran = True
        return "gone"

    server = gate(
        MCPServer("theirs"),
        _lead(),
        PERMISSIONS,
        approval={"delete_run": True},
        on_approval=refuse,
    )
    server.add_tool(delete_run, name="delete_run")

    with pytest.raises(MCPError) as error:
        await server.call_tool("delete_run", {})
    assert error.value.data["reason"] == "approval_refused"
    assert error.value.data["detail"] == "not during the freeze"
    assert ran is False


PROMPT_PERMISSIONS = {"prompt:triage_case": "testrail:read", "prompt:close_run": "testrail:delete"}
RESOURCE_PERMISSIONS = {"resource:case://all": "testrail:read", "resource:case://secret": "testrail:delete"}


async def test_undeclared_prompt_registration_raises() -> None:
    server = gate(MCPServer("theirs"), _reader(), {})

    with pytest.raises(ValueError, match=r"gate\(\): no permission declared for prompt 'surprise'"):

        @server.prompt()
        def surprise() -> str:
            return "no"


async def test_unpermitted_prompts_are_hidden() -> None:
    server = gate(MCPServer("theirs"), _reader(), PROMPT_PERMISSIONS)

    @server.prompt()
    def triage_case() -> str:
        return "triage"

    @server.prompt()
    def close_run() -> str:
        return "close"

    names = sorted(prompt.name for prompt in await server.list_prompts())
    assert names == ["triage_case"]


async def test_permitted_prompt_is_callable() -> None:
    server = gate(MCPServer("theirs"), _lead(), PROMPT_PERMISSIONS)

    @server.prompt()
    def triage_case() -> str:
        return "triage"

    result = await server.get_prompt("triage_case")
    assert result is not None


async def test_undeclared_resource_registration_raises() -> None:
    server = gate(MCPServer("theirs"), _reader(), {})

    with pytest.raises(ValueError, match=r"gate\(\): no permission declared for resource 'case://x'"):

        @server.resource("case://x")
        def cases() -> str:
            return "x"


async def test_unpermitted_resources_are_not_registered() -> None:
    server = gate(MCPServer("theirs"), _reader(), RESOURCE_PERMISSIONS)

    @server.resource("case://all")
    def cases() -> str:
        return "all"

    @server.resource("case://secret")
    def secret() -> str:
        return "secret"

    uris = sorted(str(resource.uri) for resource in await server.list_resources())
    assert uris == ["case://all"]


async def test_permitted_resource_is_readable() -> None:
    server = gate(MCPServer("theirs"), _lead(), RESOURCE_PERMISSIONS)

    @server.resource("case://all")
    def cases() -> str:
        return "all cases"

    contents = list(await server.read_resource("case://all"))
    assert getattr(contents[0], "content", None) == "all cases"


async def test_approval_allows_an_async_tool() -> None:
    from mcp_authz import ApprovalDecision, ApprovalRequest

    async def allow(_: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(True, by="sam@acme.com")

    async def delete_run() -> str:
        return "gone"

    server = gate(
        MCPServer("theirs"),
        _lead(),
        PERMISSIONS,
        approval={"delete_run": True},
        on_approval=allow,
    )
    server.add_tool(delete_run, name="delete_run")
    result = await server.call_tool("delete_run", {})
    assert getattr(result, "is_error", True) is False


async def test_imperative_add_resource_skips_unpermitted() -> None:
    from mcp.server.mcpserver.resources import FunctionResource

    server = gate(MCPServer("theirs"), _reader(), RESOURCE_PERMISSIONS)
    server.add_resource(
        FunctionResource.from_function(fn=lambda: "secret", uri="case://secret", name="secret")
    )
    server.add_resource(
        FunctionResource.from_function(fn=lambda: "all", uri="case://all", name="cases")
    )
    uris = sorted(str(resource.uri) for resource in await server.list_resources())
    assert uris == ["case://all"]


async def test_broken_approver_refuses() -> None:
    from mcp.shared.exceptions import MCPError

    from mcp_authz import ApprovalRequest

    async def broken(_: ApprovalRequest) -> None:
        raise RuntimeError("slack is down")

    server = gate(
        MCPServer("theirs"),
        _lead(),
        PERMISSIONS,
        approval={"delete_run": True},
        on_approval=broken,  # type: ignore[arg-type]
    )
    server.add_tool(lambda: "gone", name="delete_run")

    with pytest.raises(MCPError) as error:
        await server.call_tool("delete_run", {})
    assert error.value.data["reason"] == "approval_refused"
    assert error.value.data["detail"] == "slack is down"


async def test_silent_approver_times_out() -> None:
    import asyncio

    from mcp.shared.exceptions import MCPError

    from mcp_authz import ApprovalDecision, ApprovalRequest

    async def never(_: ApprovalRequest) -> ApprovalDecision:
        await asyncio.sleep(10)
        return ApprovalDecision(True, by="sam@acme.com")

    server = gate(
        MCPServer("theirs"),
        _lead(),
        PERMISSIONS,
        approval={"delete_run": True},
        on_approval=never,
        approval_timeout=0.05,
    )
    server.add_tool(lambda: "gone", name="delete_run")

    with pytest.raises(MCPError) as error:
        await server.call_tool("delete_run", {})
    assert error.value.data["reason"] == "approval_refused"
    assert "no answer within" in error.value.data["detail"]


async def test_prompt_approval_wraps_via_add_prompt() -> None:
    from mcp.shared.exceptions import MCPError

    from mcp_authz import ApprovalDecision, ApprovalRequest

    async def refuse(_: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(False, by="sam@acme.com", reason="hold")

    server = gate(
        MCPServer("theirs"),
        _lead(),
        {"prompt:triage_case": "testrail:delete"},
        approval={"prompt:triage_case": True},
        on_approval=refuse,
    )

    @server.prompt()
    def triage_case() -> str:
        return "triage"

    with pytest.raises(MCPError) as error:
        await server.get_prompt("triage_case")
    assert error.value.data["reason"] == "approval_refused"


async def test_imperative_resource_approval() -> None:
    from mcp.server.mcpserver.resources import FunctionResource
    from mcp.shared.exceptions import MCPError

    from mcp_authz import ApprovalDecision, ApprovalRequest

    async def refuse(_: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(False, by="sam@acme.com", reason="hold")

    server = gate(
        MCPServer("theirs"),
        _lead(),
        {"resource:case://all": "testrail:read"},
        approval={"resource:case://all": True},
        on_approval=refuse,
    )
    server.add_resource(
        FunctionResource.from_function(fn=lambda: "all", uri="case://all", name="cases")
    )

    with pytest.raises(MCPError) as error:
        list(await server.read_resource("case://all"))
    assert error.value.data["reason"] == "approval_refused"


async def test_resource_templates_follow_the_template_key() -> None:
    """Templates never reach add_resource, so the decorator prices them itself."""

    server = gate(MCPServer("theirs"), _lead(), {"resource:case://{id}": "testrail:read"})

    @server.resource("case://{id}")
    def one(id: str) -> str:
        return f"case {id}"

    templates = [str(t.uri_template) for t in await server.list_resource_templates()]
    assert templates == ["case://{id}"]

    contents = list(await server.read_resource("case://C1234"))
    assert getattr(contents[0], "content", None) == "case C1234"


async def test_unpermitted_resource_template_is_never_registered() -> None:
    server = gate(MCPServer("theirs"), _reader(), {"resource:case://{id}": "testrail:delete"})

    @server.resource("case://{id}")
    def one(id: str) -> str:
        return f"case {id}"

    assert await server.list_resource_templates() == []


async def test_the_approver_never_sees_the_sdk_context() -> None:
    """An approver renders the arguments; a live Context cannot be rendered."""

    from mcp_authz import ApprovalDecision, ApprovalRequest

    seen: dict[str, object] = {}

    async def allow(request: ApprovalRequest) -> ApprovalDecision:
        seen["arguments"] = request.arguments
        return ApprovalDecision(True, by="sam@acme.com")

    server = gate(
        MCPServer("theirs"),
        _lead(),
        PERMISSIONS,
        approval={"delete_run": True},
        on_approval=allow,
    )

    async def delete_run(case_id: str, ctx: Context) -> str:
        return f"gone {case_id}"

    server.add_tool(delete_run, name="delete_run")
    await server.call_tool("delete_run", {"case_id": "C1234"})

    assert seen["arguments"] == {"case_id": "C1234"}
