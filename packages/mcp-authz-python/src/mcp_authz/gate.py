"""Gate a server somebody else builds.

``AuthorizedMCPServer`` is for tools you write. This is for the ones you
already have: an MCP server from another package, or one you are not ready
to change, whose tools were never declared with a permission.

It cannot read a built server's tool list, so this wraps the server *before*
registration and gates each call as it happens. That needs one hook from
whoever builds it::

    server = options.wrap(MCPServer(...)) if options.wrap else MCPServer(...)
    build_server(config, wrap=lambda s: gate(s, principal, PERMISSIONS))
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Mapping
from typing import Any, TypeVar, cast

from mcp.server import MCPServer

from .policy import Principal
from .server import ApprovalPredicate, ApprovalSink, request_approval, without_context

_CallableT = TypeVar("_CallableT", bound=Callable[..., Any])


def gate(
    server: MCPServer,
    principal: Principal,
    permissions: Mapping[str, str],
    *,
    approval: Mapping[str, ApprovalPredicate] | None = None,
    on_approval: ApprovalSink | None = None,
    approval_timeout: float = 45.0,
) -> MCPServer:
    """Wrap registration so only priced, permitted capabilities stay visible."""

    required = dict(permissions)
    approval_map = dict(approval) if approval is not None else {}

    original_add_tool = server.add_tool
    original_add_prompt = server.add_prompt
    original_add_resource = server.add_resource
    original_resource = server.resource

    def _permission(label: str, kind: str, name: str) -> str:
        permission = required.get(label)
        if permission is None:
            raise ValueError(
                f"gate(): no permission declared for {kind} '{name}'. "
                f"Add '{label}' to the permission map, or stop registering it."
            )
        return permission

    def _approval_for(label: str, kind: str, name: str) -> ApprovalPredicate | None:
        needed = approval_map.get(label)
        if not needed:
            return None
        if on_approval is None:
            raise ValueError(
                f"gate(): {kind} '{name}' asks for approval, but no 'on_approval' was passed."
            )
        return needed

    def _guard(
        function: Callable[..., Any],
        *,
        kind: str,
        name: str,
        permission: str,
        needed: ApprovalPredicate,
    ) -> Callable[..., Any]:
        signature = inspect.signature(function)

        @functools.wraps(function)
        async def guarded(*args: Any, **kwargs: Any) -> Any:
            bound = signature.bind_partial(*args, **kwargs)
            bound.apply_defaults()
            arguments = without_context(bound.arguments)
            ask = needed(arguments) if callable(needed) else bool(needed)
            if ask:
                await request_approval(
                    on_approval=on_approval,
                    approval_timeout=approval_timeout,
                    kind=kind,
                    name=name,
                    permission=permission,
                    arguments=arguments,
                    principal=principal,
                )
            result = function(*args, **kwargs)
            return await result if inspect.isawaitable(result) else result

        return guarded

    def add_tool(fn: Callable[..., Any], name: str | None = None, **options: Any) -> None:
        tool_name = name or getattr(fn, "__name__", None) or "tool"
        permission = _permission(tool_name, "tool", tool_name)
        needed = _approval_for(tool_name, "tool", tool_name)
        wrapped = (
            _guard(fn, kind="tool", name=tool_name, permission=permission, needed=needed)
            if needed is not None
            else fn
        )
        original_add_tool(wrapped, name=name, **options)
        if not principal.can(permission):
            server.remove_tool(tool_name)

    def add_prompt(prompt: Any) -> None:
        prompt_name = str(prompt.name)
        label = f"prompt:{prompt_name}"
        permission = _permission(label, "prompt", prompt_name)
        needed = _approval_for(label, "prompt", prompt_name)
        to_add = prompt
        if needed is not None and getattr(prompt, "fn", None) is not None:
            wrapped_fn = _guard(
                prompt.fn, kind="prompt", name=prompt_name, permission=permission, needed=needed
            )
            to_add = prompt.model_copy(update={"fn": wrapped_fn})
        original_add_prompt(to_add)
        if not principal.can(permission):
            server.remove_prompt(prompt_name)

    def add_resource(resource: Any) -> None:
        uri = str(resource.uri)
        label = f"resource:{uri}"
        permission = _permission(label, "resource", uri)
        if not principal.can(permission):
            return
        needed = _approval_for(label, "resource", uri)
        to_add = resource
        if needed is not None and getattr(resource, "fn", None) is not None:
            wrapped_fn = _guard(
                resource.fn, kind="resource", name=uri, permission=permission, needed=needed
            )
            to_add = resource.model_copy(update={"fn": wrapped_fn})
        original_add_resource(to_add)

    def resource(uri: str, **options: Any) -> Callable[[_CallableT], _CallableT]:
        """Price the URI before the SDK registers (templates bypass ``add_resource``)."""

        label = f"resource:{uri}"
        permission = _permission(label, "resource", uri)
        if not principal.can(permission):

            def skip(function: _CallableT) -> _CallableT:
                return function

            return skip

        needed = _approval_for(label, "resource", uri)

        def decorate(function: _CallableT) -> _CallableT:
            to_register = (
                _guard(function, kind="resource", name=uri, permission=permission, needed=needed)
                if needed is not None
                else function
            )
            # Static resources call self.add_resource; use the original so we
            # do not price or wrap the handler a second time.
            object.__setattr__(server, "add_resource", original_add_resource)
            try:
                return cast(_CallableT, original_resource(uri, **options)(to_register))
            finally:
                object.__setattr__(server, "add_resource", add_resource)

        return decorate

    # The tool and prompt decorators register through self.add_*, so patching
    # add_tool and add_prompt catches them too. Only `resource` needs its own.
    object.__setattr__(server, "add_tool", add_tool)
    object.__setattr__(server, "add_prompt", add_prompt)
    object.__setattr__(server, "add_resource", add_resource)
    object.__setattr__(server, "resource", resource)
    return server

