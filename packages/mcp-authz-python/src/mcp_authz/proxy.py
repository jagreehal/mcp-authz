"""Gate an MCP server you can only reach by URL.

``AuthorizedMCPServer`` needs the tools; ``gate`` needs the builder that makes
them. When all you have is an address, there is no in-process seam left to use,
and enforcement has to happen at the edge.

Nothing downstream re-checks anything here. The upstream is reached with one
service credential that outranks every caller, so a request this cannot classify
is refused rather than forwarded, a capability nobody priced fails closed rather
than inheriting that credential, and a catalogue this cannot read is withheld
rather than served whole.
"""

from __future__ import annotations

import codecs
import json
import re
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from typing import Any

import httpx2
from mcp import UriTemplate
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.shared.exceptions import MCPError
from mcp.shared.inbound import NAME_BEARING_METHODS

from ._asgi import Receive, Scope, Send, denied, header, json_response, lifespan, path_of, read_body, text_response
from .audit import AuthorizationDecisionSink, emit_decision, principal_label
from .policy import Policy, Principal
from .routing import classify_scoped_request
from .server import identity_from_access_token

LISTING_FIELDS = {
    "tools/list": "tools",
    "prompts/list": "prompts",
    "resources/list": "resources",
    "resources/templates/list": "resourceTemplates",
}
INVOCATION_METHODS = ("tools/call", "prompts/get", "resources/read")

#: Headers that must not survive a hop.
#:
#: ``authorization`` and ``cookie`` are the caller's credentials for *this*
#: proxy; forwarding either would hand a third-party upstream a token it was
#: never the audience for. The rest are hop-by-hop per RFC 9110 section 7.6.1 —
#: they describe the connection that just ended, not the one about to be opened
#: — plus ``host``, which the new URL decides.
DROPPED_ON_FORWARD = frozenset(
    {
        "authorization",
        "cookie",
        "host",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",
    }
)

#: Two line terminators, which is what ends a server-sent event.
#:
#: Each may independently be CRLF, LF or a bare CR, so the nine combinations all
#: count — an upstream is under no obligation to be consistent between the two.
#: A lone CR only counts when no LF follows, or a single CRLF would decompose
#: into two terminators and every line would look like the end of an event.
_LINE_END = r"(?:\r\n|\r(?!\n)|\n)"
EVENT_END = re.compile(_LINE_END + _LINE_END)

#: The longest terminator is CRLF twice, so a boundary can straddle a chunk edge
#: by at most three characters. The scan steps back that far and no more.
_OVERLAP = 3

Bearer = str | Callable[[], str | Awaitable[str]]


class _ResourceEntry:
    """One priced ``resource:`` label and the URIs it covers."""

    def __init__(self, label: str, permission: str, uri: str) -> None:
        self.label = label
        self.permission = permission
        self._uri = uri
        self._template = UriTemplate.parse(uri) if UriTemplate.is_template(uri) else None

    @property
    def templated(self) -> bool:
        return self._template is not None

    def matches(self, uri: str) -> bool:
        if self._template is None:
            return uri == self._uri
        return self._template.match(uri) is not None


class McpProxy:
    """An OAuth 2.1 resource server in front of an MCP server reached by URL."""

    def __init__(
        self,
        *,
        resource_server_url: str,
        upstream_url: str,
        upstream_bearer: Bearer,
        policy: Policy,
        token_verifier: TokenVerifier,
        permissions: Mapping[str, str],
        resource_uris: Mapping[str, str] | None = None,
        authorization_servers: Sequence[str] = (),
        required_scopes: Sequence[str] = ("mcp",),
        supported_scopes: Sequence[str] = (),
        on_decision: AuthorizationDecisionSink | None = None,
        emitter: str | None = None,
        health_path: str = "/health",
        max_request_bytes: int = 1_048_576,
        http_client: httpx2.AsyncClient | None = None,
    ) -> None:
        self.resource_server_url = resource_server_url.rstrip("/")
        self.upstream_url = upstream_url
        self.upstream_bearer = upstream_bearer
        self.policy = policy
        self.token_verifier = token_verifier
        self.permissions = dict(permissions)
        self.authorization_servers = list(authorization_servers)
        self.required_scopes = list(required_scopes)
        self.supported_scopes = sorted({*required_scopes, *supported_scopes})
        self.on_decision = on_decision
        self.emitter = emitter
        self.health_path = health_path
        self.max_request_bytes = max_request_bytes
        self._http_client = http_client

        for label, permission in self.permissions.items():
            if not label or not permission:
                raise ValueError("Permission map keys and values must be non-empty strings.")
        self._resources = _resource_index(self.permissions, resource_uris)

        granted = {permission for permissions_ in policy.roles.values() for permission in permissions_}
        if "*" not in granted:
            unreachable = sorted({p for p in self.permissions.values() if p not in granted})
            if unreachable:
                raise ValueError("Unreachable capability: no policy role grants " + ", ".join(unreachable))

        self._base_path = path_of(self.resource_server_url)
        self._metadata_path = "/.well-known/oauth-protected-resource" + self._base_path

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await lifespan(receive, send)
            return
        if scope["type"] != "http":
            return

        path = str(scope.get("path", "/"))
        if path == self._metadata_path:
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
        if path == self.health_path:
            # Counts, not names, and never the upstream's address. This answers
            # the operator's question — did my policy load, and does it match the
            # capabilities — without handing an unauthenticated scanner a map of
            # what sits behind.
            await json_response(
                send,
                200,
                {
                    "ok": True,
                    "mode": "proxy",
                    "resource": self.resource_server_url,
                    "authorization": {"mode": "policy", "roles": len(self.policy.roles)},
                    "capabilities": len(self.permissions),
                },
            )
            return
        if path != (self._base_path or "/"):
            await text_response(
                send,
                404,
                f"No MCP endpoint at {path}. This proxy answers on {self._base_path or '/'}, "
                "which is also the audience its tokens must carry.\n",
            )
            return

        token = await self._token(scope)
        if token is None:
            await self._challenge(send, "invalid_token", "A valid bearer token is required.")
            return
        if not set(self.required_scopes).issubset(set(token.scopes)):
            missing = " ".join(sorted(set(self.required_scopes) - set(token.scopes)))
            await self._challenge(send, "insufficient_scope", f"The token is missing {missing}", status=403)
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

        body = await read_body(receive, self.max_request_bytes)
        if body is None:
            await _protocol_error(
                send, 413, -32000, f"Request body exceeds the {self.max_request_bytes} byte limit."
            )
            return

        route = await self._classify(scope, send, body)
        if route is None:
            return
        method, name = route

        if not await self._price(send, principal, method, name):
            return
        await emit_decision(self.on_decision, principal, "allow", None, self.emitter)
        await self._forward(scope, send, body, principal, method)

    async def _classify(
        self, scope: Scope, send: Send, body: bytes
    ) -> tuple[str | None, str | None] | None:
        """The method and capability name, or ``None`` once a refusal was sent.

        The capability is named in the body, not trustworthily in a header, so
        deciding its permission means reading it. The bearer gate has already
        run by the time this does, so the cap bounds an authenticated caller
        rather than anyone who can reach the port.
        """

        headers = {key.decode("latin-1"): value.decode("latin-1") for key, value in scope.get("headers", ())}
        content_type = headers.get("content-type", "")
        if "application/json" not in content_type and "+json" not in content_type:
            await _protocol_error(send, 415, -32000, "This proxy authorizes an application/json body.")
            return None
        try:
            payload = json.loads(body or b"null")
        except json.JSONDecodeError:
            await _protocol_error(send, 400, -32700, "Parse error: the request body is not valid JSON")
            return None

        classified = classify_scoped_request(headers, payload, http_method=str(scope.get("method", "POST")))
        if classified.kind == "reject":
            # The headers and the body disagree. That is never a request to
            # reason about further — one of the two is lying about what it does,
            # and neither answer can be trusted over the other.
            await _protocol_error(
                send,
                400,
                classified.code or -32020,
                "MCP routing headers disagree with the body.",
                _request_id(payload),
            )
            return None
        if classified.kind == "modern":
            return classified.method, classified.name

        # No routing headers: the body alone still says what the server will act
        # on, which is enough to price a capability.
        derived = _route_from_body(payload)
        if derived is None:
            await _protocol_error(
                send, 400, -32600, "Invalid Request: no JSON-RPC method to route on.", _request_id(payload)
            )
            return None
        return derived

    async def _price(self, send: Send, principal: Principal, method: str | None, name: str | None) -> bool:
        """Refuse an invocation nobody priced, so a new upstream tool inherits nothing."""

        if method not in INVOCATION_METHODS:
            return True

        async def refuse(because: str) -> bool:
            await emit_decision(self.on_decision, principal, "deny", "policy_denied", self.emitter)
            await denied(
                send,
                f"{principal_label(principal)} matches no rule in the access policy granting {because}. "
                "Ask an administrator to grant them a role.",
            )
            return False

        if not name:
            return await refuse(f"a {method} that names no capability")
        permission = self._permission_for(method, name, principal)
        if permission is None:
            return await refuse(f"the capability '{name}', which is not priced in the permission map")
        if not principal.can(permission):
            return await refuse(f"the permission '{permission}'")
        return True

    def _permission_for(self, method: str | None, name: str, principal: Principal) -> str | None:
        if method == "tools/call":
            return self.permissions.get(name) or self.permissions.get(f"tool:{name}")
        if method == "prompts/get":
            return self.permissions.get(f"prompt:{name}")
        if method != "resources/read":
            return None
        # Patterns can overlap, and which registration an upstream routes a URI
        # to is its business, not something to guess from the order of a
        # permission map. So every pattern that covers this URI has to be
        # satisfied: report the first one the caller fails, and only then the
        # first one at all.
        matches = [entry for entry in self._resources if entry.matches(name)]
        if not matches:
            return None
        failed = next((entry for entry in matches if not principal.can(entry.permission)), None)
        return (failed or matches[0]).permission

    async def _forward(
        self, scope: Scope, send: Send, body: bytes, principal: Principal, method: str | None
    ) -> None:
        """Swap the caller's credential for the service one, forward, then filter."""

        bearer = self.upstream_bearer() if callable(self.upstream_bearer) else self.upstream_bearer
        if not isinstance(bearer, str):
            bearer = await bearer

        dropped = set(DROPPED_ON_FORWARD)
        # RFC 9110 section 7.6.1: `Connection` names further fields that belong
        # to this hop only. They are named at run time, so a fixed list cannot
        # know them, and forwarding one sends the previous hop's private state to
        # the next.
        connection = header(scope.get("headers", ()), b"connection") or ""
        dropped.update(field.strip().lower() for field in connection.split(",") if field.strip())
        headers = {
            key.decode("latin-1"): value.decode("latin-1")
            for key, value in scope.get("headers", ())
            if key.decode("latin-1").lower() not in dropped
        }
        headers["authorization"] = f"Bearer {bearer}"

        client = self._http_client or httpx2.AsyncClient()
        owned = self._http_client is None
        try:
            request = client.build_request(
                str(scope.get("method", "POST")), self.upstream_url, headers=headers, content=body
            )
            response = await client.send(request, stream=True)
            try:
                await self._answer(send, response, principal, method, _request_id_from(body))
            finally:
                await response.aclose()
        finally:
            if owned:
                await client.aclose()

    async def _answer(
        self,
        send: Send,
        response: httpx2.Response,
        principal: Principal,
        method: str | None,
        request_id: str | int | None,
    ) -> None:
        content_type = response.headers.get("content-type", "")
        if method not in LISTING_FIELDS:
            await _stream_through(send, response)
            return

        if "text/event-stream" in content_type:
            await _stream_events(
                send,
                response,
                lambda payload: _filter_message(payload, method, principal, self.permissions),
                self.max_request_bytes,
                method,
                request_id,
            )
            return
        if "application/json" not in content_type and "+json" not in content_type:
            # A catalogue this cannot read is one it cannot hide anything from.
            # Passing it through would serve the full catalogue to everyone the
            # day an upstream changes its content type.
            await _unfilterable(
                send, f"{method} came back as '{content_type or 'no content type'}'", request_id
            )
            return

        raw = bytearray()
        async for chunk in response.aiter_bytes():
            raw.extend(chunk)
            if len(raw) > self.max_request_bytes:
                await _unfilterable(
                    send, f"{method} was over {self.max_request_bytes} bytes or not readable as JSON-RPC", request_id
                )
                return
        try:
            payload = json.loads(bytes(raw))
        except json.JSONDecodeError:
            await _unfilterable(
                send, f"{method} was over {self.max_request_bytes} bytes or not readable as JSON-RPC", request_id
            )
            return
        filtered = _filter_message(payload, method, principal, self.permissions)
        if filtered is None:
            await _unfilterable(
                send, f"{method} was over {self.max_request_bytes} bytes or not readable as JSON-RPC", request_id
            )
            return
        # The upstream's own headers survive — a session id belongs to the
        # client, not to us — minus the framing that described the body we
        # just replaced.
        body = json.dumps(filtered).encode()
        headers = [
            (key, value) for key, value in _response_headers(response) if key.lower() != b"content-type"
        ]
        await send(
            {
                "type": "http.response.start",
                "status": response.status_code,
                "headers": [(b"content-type", b"application/json"), *headers],
            }
        )
        await send({"type": "http.response.body", "body": body})

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


def _resource_index(
    permissions: Mapping[str, str], resource_uris: Mapping[str, str] | None
) -> list[_ResourceEntry]:
    """Match each priced ``resource:`` label to the URIs it covers.

    Exact URIs are tried before templates, so a resource registered at its own
    address is never answered by a template that happens to span it.
    """

    entries: list[_ResourceEntry] = []
    unpriced: list[str] = []
    for label, permission in permissions.items():
        if not label.startswith("resource:"):
            continue
        uri = (resource_uris or {}).get(label)
        if uri is None:
            unpriced.append(label)
            continue
        entries.append(_ResourceEntry(label, permission, uri))

    if unpriced:
        raise ValueError(
            "A proxy authorizes resources/read by URI, and these priced resources carry none:\n"
            + "\n".join(f"  {label}" for label in unpriced)
            + "\n\nPass `resource_uris` mapping each label to its uri or uriTemplate. List the "
            "upstream once with mcp.client.Client to read them off it."
        )
    for label in (resource_uris or {}):
        if label not in permissions:
            raise ValueError(f"resource_uris key '{label}' names no priced capability.")
    return sorted(entries, key=lambda entry: entry.templated)


def _route_from_body(payload: Any) -> tuple[str | None, str | None] | None:
    if not isinstance(payload, Mapping):
        return None
    method = payload.get("method")
    if not isinstance(method, str):
        return None
    source = NAME_BEARING_METHODS.get(method)
    params = payload.get("params")
    name = params.get(source) if source is not None and isinstance(params, Mapping) else None
    return method, name if isinstance(name, str) else None


def _filter_message(
    payload: Any, method: str | None, principal: Principal, permissions: Mapping[str, str]
) -> dict[str, Any] | None:
    """One JSON-RPC message with its listing filtered.

    ``None`` means this cannot tell what the message carries. An error reply and
    a progress notification carry no catalogue and pass through untouched;
    anything unrecognisable does not, because the whole point of reading the body
    is to know whether a capability is hiding in it.
    """

    if not isinstance(payload, Mapping):
        return None
    if "result" not in payload:
        return dict(payload) if "error" in payload or "method" in payload else None
    result = payload["result"]
    if not isinstance(result, Mapping):
        return None
    field = LISTING_FIELDS.get(method or "")
    if field is None:
        return dict(payload)
    items = result.get(field)
    if not isinstance(items, list):
        return dict(payload)
    kind = "tool" if field == "tools" else "prompt" if field == "prompts" else "resource"
    visible = [item for item in items if _visible(item, kind, principal, permissions)]
    return {**payload, "result": {**result, field: visible}}


def _visible(item: Any, kind: str, principal: Principal, permissions: Mapping[str, str]) -> bool:
    name = item.get("name") if isinstance(item, Mapping) else None
    if not isinstance(name, str):
        return False
    label = name if kind == "tool" else f"{kind}:{name}"
    permission = permissions.get(label)
    return permission is not None and principal.can(permission)


async def _stream_through(send: Send, response: httpx2.Response) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": response.status_code,
            "headers": _response_headers(response),
        }
    )
    async for chunk in response.aiter_bytes():
        await send({"type": "http.response.body", "body": chunk, "more_body": True})
    await send({"type": "http.response.body", "body": b""})


async def _stream_events(
    send: Send,
    response: httpx2.Response,
    filter_payload: Callable[[Any], dict[str, Any] | None],
    max_event_bytes: int,
    method: str | None,
    request_id: str | int | None,
) -> None:
    """Filter a listing carried over SSE, event by event as it arrives.

    Streamed rather than buffered: the body is an upstream's to size, and reading
    it to the end before answering would both hold a catalogue hostage to a slow
    server and let that server decide how much memory this process spends.
    """

    await send(
        {
            "type": "http.response.start",
            "status": response.status_code,
            "headers": _response_headers(response),
        }
    )
    async for piece in _filtered_events(
        response.aiter_bytes(), filter_payload, max_event_bytes, method, request_id
    ):
        await send({"type": "http.response.body", "body": piece, "more_body": True})
    await send({"type": "http.response.body", "body": b""})


async def _filtered_events(
    chunks: AsyncIterator[bytes],
    filter_payload: Callable[[Any], dict[str, Any] | None],
    max_event_bytes: int,
    method: str | None,
    request_id: str | int | None,
) -> AsyncIterator[bytes]:
    decoder = codecs.getincrementaldecoder("utf-8")()
    buffered = ""
    buffered_bytes = 0
    # Where the search for a terminator has already looked, and how many bytes
    # the pending event holds. Both are carried rather than recomputed:
    # rescanning the whole buffer on every chunk is quadratic in the number of
    # chunks, and an upstream chooses the chunk size. Bytes rather than
    # `len(str)`, which for anything outside ASCII reads a byte cap as larger
    # than it is.
    scanned = 0
    started = False

    def refusal(because: str) -> bytes:
        return f"event: message\ndata: {json.dumps(_unfilterable_body(because, request_id))}\n\n".encode()

    def filter_event(block: str) -> str:
        # Any of CRLF, LF or a bare CR ends a line (WHATWG server-sent events).
        data: list[str] = []
        rest: list[str] = []
        for line in re.split(r"\r\n|\n|\r", block):
            if line.startswith(":"):
                continue
            separator = line.find(":")
            field = line if separator == -1 else line[:separator]
            if field != "data":
                if line:
                    rest.append(line)
                continue
            value = "" if separator == -1 else line[separator + 1 :]
            data.append(value[1:] if value.startswith(" ") else value)
        if not data:
            return block
        try:
            payload = json.loads("\n".join(data))
        except json.JSONDecodeError:
            body = _unfilterable_body(f"{method} carried an unreadable event", request_id)
            return f"event: message\ndata: {json.dumps(body)}"
        filtered = filter_payload(payload)
        body = filtered if filtered is not None else _unfilterable_body(
            f"{method} carried an unrecognisable event", request_id
        )
        return "\n".join([*rest, f"data: {json.dumps(body)}"])

    async for chunk in chunks:
        text = decoder.decode(chunk)
        if not started:
            started = True
            # A stream may open with a byte-order mark. Left in place it becomes
            # part of the first field name, so `data:` stops looking like `data:`
            # and the event is passed through unread.
            text = text.removeprefix("﻿")
        buffered += text
        buffered_bytes += len(text.encode())

        while True:
            start = max(0, scanned - _OVERLAP)
            found = EVENT_END.search(buffered, start)
            # A trailing lone CR may be the first half of a CRLF still in flight,
            # so it waits for the next chunk rather than being read as an end.
            if found is None or (buffered.endswith("\r") and found.end() == len(buffered)):
                scanned = len(buffered)
                break
            block = buffered[: found.start()]
            # Measured before the event is filtered, not after it is emitted.
            # Checking only the unterminated case makes the cap a question of how
            # the transport happened to split the stream, which is the upstream's
            # choice to make.
            if len(block.encode()) > max_event_bytes:
                yield refusal(f"{method} sent an event over {max_event_bytes} bytes")
                return
            consumed = len(buffered[: found.end()].encode())
            buffered = buffered[found.end() :]
            buffered_bytes -= consumed
            scanned = 0
            yield (filter_event(block) + found.group(0)).encode()

        if buffered_bytes > max_event_bytes:
            # An event with no end is an event this would have to hold entirely
            # to read. Refusing bounds what a broken or hostile upstream can
            # spend here.
            yield refusal(f"{method} sent an event over {max_event_bytes} bytes")
            return

    buffered += decoder.decode(b"", True)
    if buffered.strip():
        if buffered_bytes > max_event_bytes:
            yield refusal(f"{method} sent an event over {max_event_bytes} bytes")
        else:
            yield filter_event(buffered).encode()


def _response_headers(response: httpx2.Response) -> list[tuple[bytes, bytes]]:
    """The upstream's headers minus the framing that described a body we replaced.

    A filtered listing is shorter than what arrived, and the client already
    decoded any `content-encoding`, so copying either header across would
    describe the old body: a caller would read a truncated response, or try to
    gunzip plain JSON. The hop-by-hop headers go for the same reason they do on
    the way out — they describe a connection that has ended.
    """

    return [
        (key.encode("latin-1"), value.encode("latin-1"))
        for key, value in response.headers.items()
        if key.lower() not in DROPPED_ON_FORWARD and key.lower() != "content-encoding"
    ]


def _request_id(payload: Any) -> str | int | None:
    if not isinstance(payload, Mapping):
        return None
    value = payload.get("id")
    return value if isinstance(value, (str, int)) else None


def _request_id_from(body: bytes) -> str | int | None:
    try:
        return _request_id(json.loads(body or b"null"))
    except json.JSONDecodeError:  # pragma: no cover - the body already parsed once
        return None


def _unfilterable_body(because: str, request_id: str | int | None) -> dict[str, Any]:
    """A refusal the client can match to what it asked.

    An error carrying ``id: null`` answers no pending request, so a client is
    entitled to ignore it — and then waits on a listing that will never arrive
    for as long as the stream stays open. The id comes from the request body
    this already validated.
    """

    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32010,
            "message": f"Bad Gateway: this catalogue could not be filtered — {because}.",
        },
    }


async def _unfilterable(send: Send, because: str, request_id: str | int | None) -> None:
    """A catalogue withheld.

    Absence from a listing is not the security boundary — naming a hidden
    capability is still refused — but a listing served unfiltered hands every
    caller the map, so an unreadable one fails closed rather than through.
    """

    await json_response(send, 502, _unfilterable_body(because, request_id))


async def _protocol_error(
    send: Send, status: int, code: int, message: str, request_id: str | int | None = None
) -> None:
    await json_response(
        send, status, {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
    )
