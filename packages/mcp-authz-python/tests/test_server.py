import asyncio
from types import SimpleNamespace
from typing import Any, cast

import pytest
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.context import ServerRequestContext
from mcp.shared.exceptions import MCPError
from pydantic import AnyHttpUrl

from mcp_authz import (
    ApprovalDecision,
    ApprovalRequest,
    AuthorizationMiddleware,
    AuthorizedMCPServer,
    current_principal,
    define_policy,
)


@pytest.fixture
def middleware() -> AuthorizationMiddleware:
    policy = define_policy(
        {
            "roles": {"reader": ["cases:read"]},
            "rules": [{"match": {"domain": "acme.com"}, "role": "reader"}],
        }
    )
    return AuthorizationMiddleware(
        policy,
        {
            ("tools/call", "read_case"): "cases:read",
            ("tools/call", "delete_case"): "cases:write",
        },
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


async def test_filters_discovery(middleware: AuthorizationMiddleware) -> None:
    context = SimpleNamespace(method="tools/list", params={})

    async def next_handler(_: Any) -> dict[str, Any]:
        return {"tools": [{"name": "read_case"}, {"name": "delete_case"}]}

    result = await middleware(cast(ServerRequestContext[Any, Any], context), next_handler)
    assert result == {"tools": [{"name": "read_case"}]}


async def test_denies_call_without_permission(middleware: AuthorizationMiddleware) -> None:
    context = SimpleNamespace(method="tools/call", params={"name": "delete_case"})

    async def next_handler(_: Any) -> dict[str, Any]:
        raise AssertionError("denied tools must not execute")

    with pytest.raises(MCPError) as error:
        await middleware(cast(ServerRequestContext[Any, Any], context), next_handler)
    assert error.value.code == -32003
    assert error.value.data["reason"] == "policy_denied"


async def test_allows_call_with_permission(middleware: AuthorizationMiddleware) -> None:
    context = SimpleNamespace(method="tools/call", params={"name": "read_case"})

    async def next_handler(_: Any) -> dict[str, Any]:
        assert current_principal().issuer == "https://auth.example.com"
        return {"content": []}

    assert await middleware(cast(ServerRequestContext[Any, Any], context), next_handler) == {"content": []}


async def test_resource_template_cannot_bypass_permission() -> None:
    policy = define_policy({"roles": {"reader": ["cases:read"]}, "rules": [{"role": "reader"}]})
    from mcp import UriTemplate

    guarded = AuthorizationMiddleware(
        policy,
        {},
        [(UriTemplate.parse("case://{case_id}"), "cases:write")],
    )
    context = SimpleNamespace(method="resources/read", params={"uri": "case://C1234"})

    async def next_handler(_: Any) -> dict[str, Any]:
        raise AssertionError("denied resource must not execute")

    with pytest.raises(MCPError):
        await guarded(cast(ServerRequestContext[Any, Any], context), next_handler)


async def test_resource_template_cannot_bypass_approval() -> None:
    policy = define_policy({"roles": {"reader": ["cases:read"]}, "rules": [{"role": "reader"}]})
    from mcp import UriTemplate

    asked: list[ApprovalRequest] = []

    async def approver(request: ApprovalRequest) -> ApprovalDecision:
        asked.append(request)
        return ApprovalDecision(False, by="sam@acme.com", reason="not this case")

    template = "case://{case_id}"
    guarded = AuthorizationMiddleware(
        policy,
        {("resources/read", template): "cases:read"},
        [(UriTemplate.parse(template), "cases:read")],
        approvals={("resources/read", template): True},
        on_approval=approver,
    )
    context = SimpleNamespace(method="resources/read", params={"uri": "case://C1234"})

    async def next_handler(_: Any) -> dict[str, Any]:
        raise AssertionError("an unapproved resource must not execute")

    with pytest.raises(MCPError) as error:
        await guarded(cast(ServerRequestContext[Any, Any], context), next_handler)
    assert error.value.data["reason"] == "approval_refused"
    assert asked[0].name == "case://C1234"


async def test_denies_a_capability_nobody_priced(middleware: AuthorizationMiddleware) -> None:
    """A tool registered straight on `.mcp` bypasses the decorator that prices it."""

    context = SimpleNamespace(method="tools/call", params={"name": "surprise"})

    async def next_handler(_: Any) -> dict[str, Any]:
        raise AssertionError("an undeclared tool must not execute")

    with pytest.raises(MCPError) as error:
        await middleware(cast(ServerRequestContext[Any, Any], context), next_handler)
    assert error.value.data["reason"] == "undeclared_capability"


async def test_hides_a_capability_nobody_priced(middleware: AuthorizationMiddleware) -> None:
    context = SimpleNamespace(method="tools/list", params={})

    async def next_handler(_: Any) -> dict[str, Any]:
        return {"tools": [{"name": "read_case"}, {"name": "surprise"}]}

    result = await middleware(cast(ServerRequestContext[Any, Any], context), next_handler)
    assert result == {"tools": [{"name": "read_case"}]}


async def test_refuses_a_caller_no_rule_matched() -> None:
    """Matching no rule is a refusal, not a session that lists nothing."""

    policy = define_policy(
        {
            "roles": {"reader": ["cases:read"]},
            "rules": [{"match": {"domain": "other.com"}, "role": "reader"}],
        }
    )
    guarded = AuthorizationMiddleware(policy, {("tools/call", "read_case"): "cases:read"})
    context = SimpleNamespace(method="tools/list", params={})

    async def next_handler(_: Any) -> dict[str, Any]:
        raise AssertionError("an unpermitted caller must not reach the server")

    with pytest.raises(MCPError) as error:
        await guarded(cast(ServerRequestContext[Any, Any], context), next_handler)
    assert error.value.data["reason"] == "policy_denied"


def _approving_middleware(
    on_approval: Any, timeout: float = 45.0, approval: Any = True
) -> AuthorizationMiddleware:
    policy = define_policy(
        {
            "roles": {"editor": ["cases:delete"]},
            "rules": [{"match": {"domain": "acme.com"}, "role": "editor"}],
        }
    )
    return AuthorizationMiddleware(
        policy,
        {("tools/call", "delete_case"): "cases:delete"},
        approvals={("tools/call", "delete_case"): approval},
        on_approval=on_approval,
        approval_timeout=timeout,
    )


async def test_runs_only_once_a_named_person_approves() -> None:
    asked: list[ApprovalRequest] = []

    async def approver(request: ApprovalRequest) -> ApprovalDecision:
        asked.append(request)
        return ApprovalDecision(True, by="sam@acme.com")

    middleware = _approving_middleware(approver)
    context = SimpleNamespace(
        method="tools/call", params={"name": "delete_case", "arguments": {"id": "C1234"}}
    )

    async def next_handler(_: Any) -> dict[str, Any]:
        return {"content": []}

    assert await middleware(cast(ServerRequestContext[Any, Any], context), next_handler) == {"content": []}
    assert len(asked) == 1
    assert asked[0].email == "reader@acme.com"
    assert asked[0].name == "delete_case"
    assert asked[0].arguments == {"id": "C1234"}


async def test_refuses_when_the_person_declines() -> None:
    async def approver(_: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(False, by="sam@acme.com", reason="not during the freeze")

    middleware = _approving_middleware(approver)
    context = SimpleNamespace(method="tools/call", params={"name": "delete_case", "arguments": {}})

    async def next_handler(_: Any) -> dict[str, Any]:
        raise AssertionError("an unapproved call must not execute")

    with pytest.raises(MCPError) as error:
        await middleware(cast(ServerRequestContext[Any, Any], context), next_handler)
    assert error.value.data["reason"] == "approval_refused"
    assert error.value.data["detail"] == "not during the freeze"


async def test_silence_and_a_broken_approver_both_refuse() -> None:
    async def never(_: ApprovalRequest) -> ApprovalDecision:
        await asyncio.sleep(10)
        raise AssertionError("unreachable")

    async def broken(_: ApprovalRequest) -> ApprovalDecision:
        raise RuntimeError("slack is down")

    context = SimpleNamespace(method="tools/call", params={"name": "delete_case", "arguments": {}})

    async def next_handler(_: Any) -> dict[str, Any]:
        raise AssertionError("an unapproved call must not execute")

    ctx = cast(ServerRequestContext[Any, Any], context)
    with pytest.raises(MCPError) as timed_out:
        await _approving_middleware(never, timeout=0.02)(ctx, next_handler)
    assert "no answer within" in timed_out.value.data["detail"]

    with pytest.raises(MCPError) as failed:
        await _approving_middleware(broken)(ctx, next_handler)
    assert failed.value.data["detail"] == "slack is down"


async def test_a_predicate_uses_the_validated_arguments() -> None:
    asked: list[ApprovalRequest] = []
    ran = False

    async def approver(request: ApprovalRequest) -> ApprovalDecision:
        asked.append(request)
        return ApprovalDecision(False, by="sam@acme.com", reason="force needs review")

    policy = define_policy(
        {
            "roles": {"editor": ["cases:delete"]},
            "rules": [{"match": {"domain": "acme.com"}, "role": "editor"}],
        }
    )

    class StubVerifier:
        async def verify_token(self, token: str) -> AccessToken | None:
            return None

    server = AuthorizedMCPServer(
        "test",
        policy=policy,
        token_verifier=StubVerifier(),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl("https://auth.example.com"),
            resource_server_url=AnyHttpUrl("https://mcp.example.com/mcp"),
        ),
        on_approval=approver,
    )

    @server.tool(permission="cases:delete", approval=lambda args: args.get("force") is True)
    def delete_case(force: bool = True) -> None:
        nonlocal ran
        ran = True

    async def next_handler(_: Any) -> dict[str, Any]:
        return cast(dict[str, Any], await server.mcp.call_tool("delete_case", {}))

    context = SimpleNamespace(method="tools/call", params={"name": "delete_case", "arguments": {}})
    with pytest.raises(MCPError) as error:
        await server._authorization(cast(ServerRequestContext[Any, Any], context), next_handler)
    assert error.value.data["reason"] == "approval_refused"
    assert len(asked) == 1
    assert asked[0].arguments["force"] is True
    assert ran is False


def test_an_approval_must_name_who_gave_it() -> None:
    with pytest.raises(ValueError, match="name who gave it"):
        ApprovalDecision(True)


def test_rejects_a_capability_asking_for_an_approver_that_does_not_exist() -> None:
    policy = define_policy({"roles": {"editor": ["cases:delete"]}, "rules": []})

    class StubVerifier:
        async def verify_token(self, token: str) -> AccessToken | None:
            return None

    server = AuthorizedMCPServer(
        "test",
        policy=policy,
        token_verifier=StubVerifier(),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl("https://auth.example.com"),
            resource_server_url=AnyHttpUrl("https://mcp.example.com/mcp"),
        ),
    )
    with pytest.raises(ValueError, match="no 'on_approval' was passed"):

        @server.tool(permission="cases:delete", approval=True)
        def delete_case() -> None:
            pass


def test_rejects_unreachable_capability_permission() -> None:
    policy = define_policy({"roles": {"reader": ["cases:read"]}, "rules": []})

    class StubVerifier:
        async def verify_token(self, token: str) -> AccessToken | None:
            return None

    server = AuthorizedMCPServer(
        "test",
        policy=policy,
        token_verifier=StubVerifier(),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl("https://auth.example.com"),
            resource_server_url=AnyHttpUrl("https://mcp.example.com/mcp"),
        ),
    )
    with pytest.raises(ValueError, match="no policy role grants"):

        @server.tool(permission="cases:write")
        def unreachable() -> None:
            pass
