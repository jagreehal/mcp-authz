"""Permission-aware facade over the official MCP Python server."""

from __future__ import annotations

import asyncio
import contextvars
import functools
import inspect
import time
import warnings
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, TypeVar, cast

from mcp import UriTemplate
from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.context import CallNext, HandlerResult, ServerMiddleware, ServerRequestContext
from mcp.server.mcpserver import Context
from mcp.shared.exceptions import MCPError

from .audit import (
    AuditErrorSink,
    AuditEvent,
    AuditSink,
    AuthorizationDecisionSink,
    deliver_terminal_audit,
    emit_decision,
    new_call_id,
    now,
)
from .identity import Identity
from .policy import Policy, Principal

_CallableT = TypeVar("_CallableT", bound=Callable[..., Any])
_PERMISSION_DENIED = -32003
_principal_context = contextvars.ContextVar[Principal | None]("mcp_authz_principal", default=None)
_capability_context = contextvars.ContextVar[tuple[str, str] | None]("mcp_authz_capability", default=None)
_KINDS = {"tools/call": "tool", "prompts/get": "prompt", "resources/read": "resource"}


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """What a person is being asked to approve, before it happens.

    Everything here was proved rather than claimed: the identity came off a
    verified token and the permission was already checked, so the question left
    for a person is only whether this particular call should happen.
    """

    issuer: str
    sub: str
    email: str | None
    kind: str
    name: str
    permission: str
    arguments: Mapping[str, Any]
    at: str


@dataclass(frozen=True, slots=True)
class ApprovalDecision:
    """Approving anonymously is not a second pair of eyes, so ``by`` is required."""

    approved: bool
    by: str | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.approved and not self.by:
            raise ValueError("An approval must name who gave it.")


ApprovalSink = Callable[[ApprovalRequest], Awaitable[ApprovalDecision]]


def without_context(arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Drop the SDK's injected ``Context`` before anyone outside this process sees it.

    An approver is an adapter: it renders the arguments into a Slack message or
    a ticket, which means serialising them. A live ``Context`` holds the open
    session, so leaving it in raises on the first `json.dumps` and tells a
    reviewer nothing about the call they are being asked to approve.
    """

    return {name: value for name, value in arguments.items() if not isinstance(value, Context)}


async def request_approval(
    *,
    on_approval: ApprovalSink | None,
    approval_timeout: float,
    kind: str,
    name: str,
    permission: str,
    arguments: Mapping[str, Any],
    principal: Principal,
) -> None:
    """Ask a person, but not forever.

    The deadline is what keeps this a library rather than a service. The caller
    is still on the other end of an open request, so nothing has to survive a
    restart: a process that dies mid-question takes the request with it, and
    the action correctly did not happen.

    Shared by `AuthorizedMCPServer` and `gate`, so a refusal is the same shape
    whoever wrote the tool.
    """

    if on_approval is None:  # pragma: no cover - refused at registration
        raise MCPError(_PERMISSION_DENIED, "Approval is required but no approver is configured")

    request = ApprovalRequest(
        issuer=principal.issuer,
        sub=principal.sub,
        email=principal.email,
        kind=kind,
        name=name,
        permission=permission,
        arguments=arguments,
        at=datetime.now(timezone.utc).isoformat(),
    )
    try:
        decision = await asyncio.wait_for(on_approval(request), approval_timeout)
    except asyncio.TimeoutError:
        # Not the builtin: before 3.11 `asyncio.TimeoutError` is its own class,
        # so catching `TimeoutError` there loses the deadline and reports the
        # silence as an unnamed error instead.
        decision = ApprovalDecision(False, reason=f"no answer within {approval_timeout}s")
    except Exception as error:  # noqa: BLE001 - a broken approver refuses, it does not admit
        decision = ApprovalDecision(False, reason=str(error))

    if not decision.approved:
        raise MCPError(
            _PERMISSION_DENIED,
            "Not approved",
            {
                "error": "forbidden",
                "reason": "approval_refused",
                "capability": name,
                "by": decision.by,
                "detail": decision.reason or "refused",
            },
        )
ApprovalPredicate = bool | Callable[[Mapping[str, Any]], bool]


class AuthorizationMiddleware:
    """Official MCP server middleware that gates and filters capabilities."""

    def __init__(
        self,
        policy: Policy,
        permissions: Mapping[tuple[str, str], str],
        resource_templates: Sequence[tuple[UriTemplate, str]] = (),
        approvals: Mapping[tuple[str, str], bool] | None = None,
        on_approval: ApprovalSink | None = None,
        approval_timeout: float = 45.0,
        on_audit: AuditSink | None = None,
        on_audit_error: AuditErrorSink | None = None,
        on_decision: AuthorizationDecisionSink | None = None,
        emitter: str | None = None,
    ) -> None:
        self.policy = policy
        self.permissions = permissions
        self.resource_templates = resource_templates
        self.approvals = approvals if approvals is not None else {}
        self.on_approval = on_approval
        self.approval_timeout = approval_timeout
        self.on_audit = on_audit
        self.on_audit_error = on_audit_error
        self.on_decision = on_decision
        self.emitter = emitter

    async def __call__(self, ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
        principal = await self._principal()
        capability = _requested_capability(ctx.method, ctx.params)
        permission: str | None = None
        if capability is not None:
            permission = self._permission(ctx.method, capability)
            if permission is None:
                # Deny by default, loudly. A capability registered straight on
                # `.mcp`, bypassing the decorators that price it, is otherwise
                # reachable by everyone with nothing in the logs to read.
                await emit_decision(self.on_decision, principal, "deny", "undeclared_capability", self.emitter)
                raise MCPError(
                    _PERMISSION_DENIED,
                    "Permission denied",
                    {
                        "error": "forbidden",
                        "reason": "undeclared_capability",
                        "capability": capability,
                    },
                )
            if not principal.can(permission):
                await emit_decision(self.on_decision, principal, "deny", "policy_denied", self.emitter)
                raise MCPError(
                    _PERMISSION_DENIED,
                    "Permission denied",
                    {
                        "error": "forbidden",
                        "reason": "policy_denied",
                        "permission": permission,
                        "capability": capability,
                    },
                )
        await emit_decision(self.on_decision, principal, "allow", None, self.emitter)
        reset_principal = _principal_context.set(principal)
        reset_capability = _capability_context.set((ctx.method, capability) if capability is not None else None)
        try:
            if capability is None:
                result = await call_next(ctx)
            else:
                assert permission is not None
                result = await self._audited(ctx, capability, permission, principal, call_next)
            if isinstance(result, dict):
                return self._filter_listing(ctx.method, result, principal)
            return result
        finally:
            _capability_context.reset(reset_capability)
            _principal_context.reset(reset_principal)

    async def _audited(
        self,
        ctx: ServerRequestContext[Any, Any],
        capability: str,
        permission: str,
        principal: Principal,
        call_next: CallNext,
    ) -> HandlerResult:
        """Record the attempt, then whatever became of it.

        The attempt write is awaited and its failure stops the call: an action
        nobody could record is an action that should not happen. A terminal
        write happens after the action reached its result, so its failure
        cannot change that result.
        """

        if self.on_audit is None:
            await self._approve(ctx, capability, permission, principal)
            return await call_next(ctx)

        started = time.perf_counter()
        call_id = new_call_id()

        def event(
            phase: str,
            *,
            decision: str = "allow",
            approved_by: str | None = None,
            error: str | None = None,
            timed: bool = True,
        ) -> AuditEvent:
            return AuditEvent(
                call_id=call_id,
                issuer=principal.issuer,
                sub=principal.sub,
                email=principal.email,
                domain=principal.domain,
                emitter=self.emitter,
                kind=_KINDS.get(ctx.method, ctx.method),
                name=capability,
                permission=permission,
                decision=decision,
                phase=phase,
                at=now(),
                approved_by=approved_by,
                duration_ms=(time.perf_counter() - started) * 1000 if timed else None,
                error=error,
            )

        await _call_audit(self.on_audit, event("attempt", timed=False))
        try:
            await self._approve(ctx, capability, permission, principal)
            result = await call_next(ctx)
        except MCPError as mcp_error:
            data = mcp_error.data if isinstance(mcp_error.data, Mapping) else {}
            refused = data.get("reason") == "approval_refused"
            by = data.get("by")
            await deliver_terminal_audit(
                self.on_audit,
                self.on_audit_error,
                event(
                    "refused" if refused else "failure",
                    decision="deny" if refused else "allow",
                    approved_by=by if isinstance(by, str) else None,
                    error=str(data.get("detail") or mcp_error.message),
                ),
            )
            raise
        except Exception as error:
            await deliver_terminal_audit(
                self.on_audit, self.on_audit_error, event("failure", error=str(error))
            )
            raise
        await deliver_terminal_audit(self.on_audit, self.on_audit_error, event("success"))
        return result

    async def _principal(self) -> Principal:
        token = get_access_token()
        if token is None:
            raise MCPError(_PERMISSION_DENIED, "Authentication required")
        principal = self.policy(identity_from_access_token(token))
        if not principal.permissions:
            await emit_decision(self.on_decision, principal, "deny", "not_permitted", self.emitter)
            # Matching no rule means no permissions, and there is no setting to
            # widen it. Refusing the connection is what makes that legible: the
            # alternative is a session that lists nothing and explains nothing,
            # and it is what the TypeScript gate answers with HTTP 403.
            raise MCPError(
                _PERMISSION_DENIED,
                "Permission denied",
                {"error": "forbidden", "reason": "policy_denied"},
            )
        return principal

    async def _approve(
        self,
        ctx: ServerRequestContext[Any, Any],
        capability: str,
        permission: str,
        principal: Principal,
    ) -> None:
        """Ask a person, but not forever.

        The deadline is what keeps this a library rather than a service. The
        caller is still on the other end of an open request, so nothing has to
        survive a restart: a process that dies mid-question takes the request
        with it, and the action correctly did not happen.
        """

        needed = self._approval(ctx.method, capability)
        arguments = ctx.params.get("arguments") if isinstance(ctx.params, Mapping) else None
        arguments = arguments if isinstance(arguments, Mapping) else {}
        if not needed:
            return
        await self._request_approval(ctx.method, capability, permission, arguments, principal)

    async def _request_approval(
        self,
        method: str,
        capability: str,
        permission: str,
        arguments: Mapping[str, Any],
        principal: Principal,
    ) -> None:
        await request_approval(
            on_approval=self.on_approval,
            approval_timeout=self.approval_timeout,
            kind=_KINDS.get(method, method),
            name=capability,
            permission=permission,
            arguments=arguments,
            principal=principal,
        )

    def _approval(self, method: str, capability: str) -> bool | None:
        exact = self.approvals.get((method, capability))
        if exact is not None or method != "resources/read":
            return exact
        for (registered_method, template), approval in self.approvals.items():
            if (
                registered_method == method
                and UriTemplate.is_template(template)
                and UriTemplate.parse(template).match(capability) is not None
            ):
                return approval
        return None

    def _filter_listing(self, method: str, result: dict[str, Any], principal: Principal) -> dict[str, Any]:
        listing = {
            "tools/list": ("tools", "tools/call", "name"),
            "prompts/list": ("prompts", "prompts/get", "name"),
            "resources/list": ("resources", "resources/read", "uri"),
            "resources/templates/list": ("resourceTemplates", "resources/read", "uriTemplate"),
        }.get(method)
        if listing is None:
            return result
        collection, call_method, name_field = listing
        values = result.get(collection)
        if not isinstance(values, list):
            return result
        visible = []
        for value in values:
            name = value.get(name_field) if isinstance(value, dict) else None
            permission = self.permissions.get((call_method, str(name))) if name is not None else None
            # An undeclared capability is hidden as well as refused, so a listing
            # never advertises something the call path will reject.
            if permission is not None and principal.can(permission):
                visible.append(value)
        return {**result, collection: visible}

    def _permission(self, method: str, capability: str) -> str | None:
        exact = self.permissions.get((method, capability))
        if exact is not None or method != "resources/read":
            return exact
        for template, permission in self.resource_templates:
            if template.match(capability) is not None:
                return permission
        return None


class AuthorizedMCPServer:
    """Register permission requirements alongside official MCP capabilities."""

    def __init__(
        self,
        name: str,
        *,
        policy: Policy,
        token_verifier: TokenVerifier,
        auth: AuthSettings,
        middleware: Sequence[ServerMiddleware[Any]] = (),
        on_approval: ApprovalSink | None = None,
        approval_timeout: float = 45.0,
        on_audit: AuditSink | None = None,
        on_audit_error: AuditErrorSink | None = None,
        on_decision: AuthorizationDecisionSink | None = None,
        emitter: str | None = None,
        **server_options: Any,
    ) -> None:
        self.permissions: dict[tuple[str, str], str] = {}
        self.approvals: dict[tuple[str, str], bool] = {}
        self._resource_templates: list[tuple[UriTemplate, str]] = []
        self._policy = policy
        self._on_approval = on_approval
        self._reconciled = False
        self._granted_permissions = {permission for permissions in policy.roles.values() for permission in permissions}
        authorization = AuthorizationMiddleware(
            policy,
            self.permissions,
            self._resource_templates,
            self.approvals,
            on_approval,
            approval_timeout,
            on_audit,
            on_audit_error,
            on_decision,
            emitter,
        )
        self._authorization = authorization
        self.mcp = MCPServer(
            name,
            token_verifier=token_verifier,
            auth=auth,
            middleware=(authorization, *middleware),
            **server_options,
        )

    def tool(
        self, *, permission: str, approval: ApprovalPredicate = False, **options: Any
    ) -> Callable[[_CallableT], _CallableT]:
        def decorate(function: _CallableT) -> _CallableT:
            name = cast(str | None, options.get("name")) or function.__name__
            self._require("tools/call", name, permission, approval)
            guarded = self._guard_predicate(function, "tools/call", name, permission, approval)
            return self.mcp.tool(**options)(guarded)

        return decorate

    def prompt(
        self, *, permission: str, approval: ApprovalPredicate = False, **options: Any
    ) -> Callable[[_CallableT], _CallableT]:
        def decorate(function: _CallableT) -> _CallableT:
            name = cast(str | None, options.get("name")) or function.__name__
            self._require("prompts/get", name, permission, approval)
            guarded = self._guard_predicate(function, "prompts/get", name, permission, approval)
            return self.mcp.prompt(**options)(guarded)

        return decorate

    def resource(
        self, uri: str, *, permission: str, approval: ApprovalPredicate = False, **options: Any
    ) -> Callable[[_CallableT], _CallableT]:
        def decorate(function: _CallableT) -> _CallableT:
            self._require("resources/read", uri, permission, approval)
            if UriTemplate.is_template(uri):
                self._resource_templates.append((UriTemplate.parse(uri), permission))
            guarded = self._guard_predicate(function, "resources/read", uri, permission, approval)
            return self.mcp.resource(uri, **options)(guarded)

        return decorate

    def streamable_http_app(self, **options: Any) -> Any:
        self._validate_reconciliation()
        return self.mcp.streamable_http_app(**options)

    def run(self, transport: str = "stdio", **options: Any) -> None:
        self._validate_reconciliation()
        self.mcp.run(cast(Any, transport), **options)

    def _require(
        self, method: str, name: str, permission: str, approval: ApprovalPredicate = False
    ) -> None:
        if not permission:
            raise ValueError("Capability permissions must not be empty.")
        if "*" not in self._granted_permissions and permission not in self._granted_permissions:
            raise ValueError(f"Capability '{name}' requires '{permission}', but no policy role grants it.")
        # Asking nobody is not approving, so a capability that wants a person and
        # has no way to reach one fails here rather than at the first call.
        if approval is not False and self._on_approval is None:
            raise ValueError(f"Capability '{name}' asks for approval, but no 'on_approval' was passed.")
        self.permissions[(method, name)] = permission
        if approval is True:
            self.approvals[(method, name)] = approval

    def _guard_predicate(
        self,
        function: _CallableT,
        method: str,
        name: str,
        permission: str,
        approval: ApprovalPredicate,
    ) -> _CallableT:
        if not callable(approval):
            return function

        signature = inspect.signature(function)

        @functools.wraps(function)
        async def guarded(*args: Any, **kwargs: Any) -> Any:
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            arguments = without_context(bound.arguments)
            if approval(arguments):
                principal = current_principal()
                active = _capability_context.get()
                capability = active[1] if active is not None and active[0] == method else name
                await self._authorization._request_approval(
                    method,
                    capability,
                    permission,
                    arguments,
                    principal,
                )
            result = function(*args, **kwargs)
            return await result if inspect.isawaitable(result) else result

        return cast(_CallableT, guarded)

    def _validate_reconciliation(self) -> None:
        if self._reconciled:
            return
        required = set(self.permissions.values())
        unused = sorted(set(self._policy.permissions) - required)
        if unused:
            warnings.warn(
                "MCP policy has unused permissions: " + ", ".join(unused),
                stacklevel=2,
            )
        self._reconciled = True


def identity_from_access_token(token: AccessToken) -> Identity:
    """Map verified official MCP token data to the policy identity."""

    claims = token.claims or {}
    issuer = claims.get("iss")
    sub = token.subject or claims.get("sub")
    email = claims.get("email")
    email_verified = claims.get("email_verified") is True
    domain = claims.get("hd")
    if not isinstance(issuer, str) or not issuer or not isinstance(sub, str) or not sub:
        raise MCPError(_PERMISSION_DENIED, "Verified token has no issuer or subject")
    if email is not None and (not isinstance(email, str) or not email):
        raise MCPError(_PERMISSION_DENIED, "Verified token has an invalid email")
    return Identity(
        issuer=issuer,
        sub=sub,
        email=email if isinstance(email, str) else None,
        email_verified=email_verified,
        domain=domain if isinstance(domain, str) else None,
        claims=claims,
    )


def current_principal() -> Principal:
    """Return the authorized principal inside an MCP capability handler."""

    principal = _principal_context.get()
    if principal is None:
        raise RuntimeError("No authorized MCP request is active.")
    return principal


def _requested_capability(method: str, params: Mapping[str, Any] | None) -> str | None:
    field = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}.get(method)
    if field is None or params is None:
        return None
    value = params.get(field)
    return value if isinstance(value, str) else None


async def _call_audit(sink: AuditSink, event: AuditEvent) -> None:
    """The attempt write, awaited. A rejection stops the call before it runs."""

    result = sink(event)
    if inspect.isawaitable(result):
        await result
