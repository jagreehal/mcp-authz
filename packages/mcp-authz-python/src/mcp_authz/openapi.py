"""The same bet as the MCP side, on the other catalogue an agent reads.

``gate`` earns its keep because a tool that is never registered is a tool the
model never sees, so it never tries. An HTTP API has one thing shaped like that
list: its OpenAPI document. Filtering the served document per caller is the same
move — a smaller prompt, and no confident calls into a 403.

For a hand-written client it changes nothing, because that client was coded
against the spec months ago. Hiding an operation is not the boundary; the check
on the request is, and it runs here whether or not the caller ever read the
document.

This is ASGI middleware rather than a framework plugin: FastAPI, Starlette,
Litestar and Django all speak it, and the API underneath keeps whatever it
already uses.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.shared.exceptions import MCPError

from ._asgi import (
    ASGIApp,
    Receive,
    Scope,
    Send,
    denied,
    header,
    json_response,
    path_of,
    text_response,
)
from .audit import (
    AuditErrorSink,
    AuditEvent,
    AuditSink,
    AuthorizationDecisionSink,
    deliver_terminal_audit,
    emit_decision,
    new_call_id,
    now,
    principal_label,
)
from .policy import Policy, Principal
from .server import identity_from_access_token

#: The methods OpenAPI defines on a path item. Anything else there is not an operation.
METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")

UNASSIGNED = "TODO:unassigned"


@dataclass(frozen=True, slots=True)
class Operation:
    """One operation, as the document describes it."""

    operation_id: str
    method: str
    path: str


@dataclass(frozen=True, slots=True)
class OperationRecord:
    """What the document says this API can do."""

    names: list[str] = field(default_factory=list)
    operations: list[Operation] = field(default_factory=list)


def record_operations(spec: Mapping[str, Any]) -> OperationRecord:
    """Read the catalogue off the document.

    The mirror of the TypeScript ``recordOperations``, and it needs no running
    server: an OpenAPI file is the catalogue, already sitting in your
    repository. Feed the result to ``to_permissions_module`` for a map priced
    ``TODO:unassigned``, which no role grants and the boot refuses until
    somebody decides what each operation costs.
    """

    operations: list[Operation] = []
    seen: dict[str, str] = {}
    paths = spec.get("paths") or {}
    for path, item in paths.items():
        if not isinstance(item, Mapping):
            continue
        for method in METHODS:
            operation = item.get(method)
            if not isinstance(operation, Mapping):
                continue
            operation_id = operation.get("operationId")
            if not isinstance(operation_id, str) or not operation_id:
                # Refused rather than named `get /cases/{id}` for you. A
                # generated fallback is a second naming scheme that only some
                # operations use, and it changes under a path rename — so the
                # map silently stops matching the route it was written for.
                raise ValueError(
                    f"{method.upper()} {path} has no operationId, and the permission map is keyed by it. "
                    "Give the operation an operationId in the document."
                )
            duplicate = seen.get(operation_id)
            if duplicate:
                raise ValueError(
                    f"operationId '{operation_id}' is used by both {duplicate} and {method.upper()} {path}. "
                    "One id would price two routes, so the map could not say which."
                )
            seen[operation_id] = f"{method.upper()} {path}"
            operations.append(Operation(operation_id=operation_id, method=method, path=str(path)))
    return OperationRecord(names=sorted(seen), operations=operations)


def to_permissions_module(record: OperationRecord) -> str:
    """A permission map to start from, priced so it cannot be forgotten.

    Every operation gets a placeholder no role grants, so the boot refuses until
    a person has decided what each one costs. That decision is the whole point
    of the file, and a default would quietly make it for them.
    """

    lines = [
        "# Generated from a recorded catalogue. Replace every TODO with a real permission.",
        "",
        "PERMISSIONS = {",
        *(f"    {json.dumps(name)}: {json.dumps(UNASSIGNED)}," for name in record.names),
        "}",
        "",
    ]
    return "\n".join(lines)


def filter_spec(
    spec: Mapping[str, Any],
    principal: Principal,
    permissions: Mapping[str, str],
) -> dict[str, Any]:
    """The document as this caller should see it: their operations, and nothing else.

    A path item left with no operations is dropped, so the reader is not offered
    a route with no verbs. ``components`` is deliberately left whole — pruning it
    means walking the ``$ref`` graph, and a schema nobody references costs a few
    hundred tokens where a wrongly-pruned one breaks the document.
    """

    paths: dict[str, Any] = {}
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, Mapping):
            continue
        kept: dict[str, Any] = {}
        any_operation = False
        for key, value in item.items():
            if key not in METHODS:
                # `parameters`, `summary`, `$ref`, extensions: path-level things
                # that describe whatever operations survive.
                kept[key] = value
                continue
            operation_id = value.get("operationId") if isinstance(value, Mapping) else None
            permission = permissions.get(operation_id) if isinstance(operation_id, str) else None
            if permission is not None and principal.can(permission):
                kept[key] = value
                any_operation = True
        if any_operation:
            paths[path] = kept
    return {**spec, "paths": paths}


class OpenApiAuthorizationMiddleware:
    """An OAuth 2.1 resource server in front of an API you already have.

    Anything the document does not describe is refused. That is the same rule as
    ``gate`` — a capability nobody priced is reachable by everyone or by nobody,
    with no error to read — and it means routes you deliberately leave out of the
    spec (a health check, static files) belong outside this wrapper rather than
    behind it.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        spec: Mapping[str, Any],
        permissions: Mapping[str, str],
        policy: Policy,
        token_verifier: TokenVerifier,
        resource_server_url: str,
        authorization_servers: Sequence[str] = (),
        required_scopes: Sequence[str] = ("api",),
        supported_scopes: Sequence[str] = (),
        spec_path: str = "/openapi.json",
        emitter: str | None = None,
        on_audit: AuditSink | None = None,
        on_audit_error: AuditErrorSink | None = None,
        on_decision: AuthorizationDecisionSink | None = None,
    ) -> None:
        self.app = app
        self.spec = spec
        self.permissions = dict(permissions)
        self.policy = policy
        self.token_verifier = token_verifier
        self.resource_server_url = resource_server_url.rstrip("/")
        self.authorization_servers = list(authorization_servers)
        self.required_scopes = list(required_scopes)
        self.supported_scopes = sorted({*required_scopes, *supported_scopes})
        self.spec_path = spec_path
        self.emitter = emitter
        self.on_audit = on_audit
        self.on_audit_error = on_audit_error
        self.on_decision = on_decision

        record = record_operations(spec)
        for name in record.names:
            if name not in self.permissions:
                # The boot, not the first call. An operation with no price is
                # either reachable by everyone or by nobody, and both are found
                # late.
                raise ValueError(
                    f"The permission map puts no price on '{name}'. Every operation in the document "
                    "needs an entry; record_operations() and to_permissions_module() generate the "
                    "starting map."
                )
        for name in self.permissions:
            if name not in record.names:
                raise ValueError(
                    f"The permission map prices '{name}', which the document describes no operation for. "
                    "A renamed operationId leaves an entry behind that stops gating anything."
                )
        granted = {permission for permissions in policy.roles.values() for permission in permissions}
        if "*" not in granted:
            unreachable = sorted(
                {permission for permission in self.permissions.values() if permission not in granted}
            )
            if unreachable:
                raise ValueError(
                    "Unreachable operation: no policy role grants " + ", ".join(unreachable)
                )

        # Concrete segments beat templated ones, so `/cases/search` is not
        # swallowed by `/cases/{id}`, whichever order the document lists them in.
        self._routes = sorted(
            ((operation, _matcher(operation.path)) for operation in record.operations),
            key=lambda entry: (entry[0].path.count("{"), -len(entry[0].path)),
        )
        self._base_path = path_of(self.resource_server_url)
        self._metadata_path = "/.well-known/oauth-protected-resource" + self._base_path

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path", "/"))
        if path == self._metadata_path:
            # Unauthenticated on purpose: this is how a client discovers which
            # authorization server to go to, which it needs before it has a token.
            await json_response(
                send,
                200,
                {
                    "resource": self.resource_server_url,
                    "authorization_servers": self.authorization_servers,
                    "scopes_supported": self.supported_scopes,
                    "bearer_methods_supported": ["header"],
                },
            )
            return

        if not path.startswith(self._base_path):
            await text_response(
                send,
                404,
                f"No API at {path}. This server answers under {self._base_path or '/'}, "
                "which is also the audience its tokens must carry.\n",
            )
            return
        route = path[len(self._base_path) :] or "/"

        token = await self._token(scope)
        if token is None:
            await self._challenge(send, "invalid_token", "A valid bearer token is required.")
            return
        if not set(self.required_scopes).issubset(set(token.scopes)):
            await self._challenge(
                send,
                "insufficient_scope",
                "The token is missing " + " ".join(sorted(set(self.required_scopes) - set(token.scopes))),
                status=403,
            )
            return

        try:
            principal = self.policy(identity_from_access_token(token))
        except MCPError as error:
            await self._challenge(send, "invalid_token", error.message)
            return
        if not principal.permissions:
            await emit_decision(self.on_decision, principal, "deny", "not_permitted", self.emitter)
            await denied(
                send,
                f"{principal_label(principal)} matches no rule in the access policy, so they hold no "
                "permissions. Ask an administrator to grant them a role.",
            )
            return

        if route == self.spec_path:
            # The catalogue, cut to this caller. Authenticated on purpose: it is
            # a different document per person, and an anonymous one would have to
            # be the whole thing.
            await emit_decision(self.on_decision, principal, "allow", None, self.emitter)
            await json_response(send, 200, filter_spec(self.spec, principal, self.permissions))
            return

        method = str(scope.get("method", "GET")).lower()
        matched = next(
            (operation for operation, pattern in self._routes if operation.method == method and pattern.match(route)),
            None,
        )
        if matched is None:
            await emit_decision(self.on_decision, principal, "deny", "no_such_operation", self.emitter)
            await json_response(
                send,
                404,
                {
                    "error": "not_found",
                    "error_description": (
                        f"{method.upper()} {route} is not in the document this server gates, so it is "
                        "refused. Describe it in the OpenAPI document, or serve it outside this wrapper."
                    ),
                },
            )
            return

        permission = self.permissions[matched.operation_id]
        if not principal.can(permission):
            await emit_decision(self.on_decision, principal, "deny", "not_permitted", self.emitter)
            await denied(
                send,
                f"{principal_label(principal)} matches no rule in the access policy granting "
                f"'{permission}', so they hold no permissions. Ask an administrator to grant them a role.",
            )
            return
        await emit_decision(self.on_decision, principal, "allow", None, self.emitter)

        if self.on_audit is None:
            await self.app(scope, receive, send)
            return
        await self._audited(scope, receive, send, matched, permission, principal)

    async def _audited(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        operation: Operation,
        permission: str,
        principal: Principal,
    ) -> None:
        route = str(scope.get("path", "/"))[len(self._base_path) :] or "/"
        call_id = new_call_id()

        def event(phase: str, started: float | None = None, error: str | None = None) -> AuditEvent:
            return AuditEvent(
                call_id=call_id,
                issuer=principal.issuer,
                sub=principal.sub,
                email=principal.email,
                domain=principal.domain,
                emitter=self.emitter,
                kind="operation",
                name=operation.operation_id,
                permission=permission,
                # The concrete path, which is what the call actually touched. The
                # query string is left out: it carries values a log store should
                # not be the first place to hold.
                resource=route,
                decision="allow",
                phase=phase,
                at=now(),
                duration_ms=None if started is None else (time.perf_counter() - started) * 1000,
                error=error,
            )

        assert self.on_audit is not None
        try:
            result = self.on_audit(event("attempt"))
            if hasattr(result, "__await__"):
                await result  # type: ignore[misc]
        except Exception:  # noqa: BLE001 - fail closed, as the MCP side does
            await json_response(
                send,
                503,
                {
                    "error": "unavailable",
                    "error_description": "The audit log refused the write, so the call did not run.",
                },
            )
            return

        started = time.perf_counter()
        status = 500

        async def watched(message: MutableMapping[str, Any]) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
            await send(message)

        try:
            await self.app(scope, receive, watched)
        except Exception as error:
            await deliver_terminal_audit(
                self.on_audit, self.on_audit_error, event("failure", started, str(error))
            )
            raise
        # What an auditor is asking is whether the action happened, and over HTTP
        # that is the status rather than whether a coroutine raised.
        succeeded = status < 400
        await deliver_terminal_audit(
            self.on_audit,
            self.on_audit_error,
            event("success" if succeeded else "failure", started, None if succeeded else f"HTTP {status}"),
        )

    async def _token(self, scope: Scope) -> AccessToken | None:
        authorization = header(scope.get("headers", ()), b"authorization")
        if authorization is None or not authorization.lower().startswith("bearer "):
            return None
        return await self.token_verifier.verify_token(authorization[7:].strip())

    async def _challenge(self, send: Send, code: str, description: str, status: int = 401) -> None:
        challenge = (
            f'Bearer error="{code}", error_description="{description}", '
            f'resource_metadata="{self.resource_server_url}{self._metadata_path}"'
        )
        await json_response(
            send,
            status,
            {"error": code, "error_description": description},
            [(b"www-authenticate", challenge.encode())],
        )


def _matcher(template: str) -> re.Pattern[str]:
    """A path template as a matcher.

    ``{id}`` matches one segment and never a ``/``, so ``/cases/{id}`` does not
    answer for ``/cases/C1/notes`` — which would hand a caller a route nobody
    priced.
    """

    parts = [
        "[^/]+" if re.fullmatch(r"\{[^{}]+\}", segment) else re.escape(segment)
        for segment in template.split("/")
    ]
    return re.compile("^" + "/".join(parts) + "$")
