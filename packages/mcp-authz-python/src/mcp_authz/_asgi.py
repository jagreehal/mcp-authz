"""The small ASGI plumbing both HTTP entry points need.

Neither of them is a framework: an API keeps whatever it already uses, and a
proxy sits in front of a URL. What is left is reading a capped body and writing
a JSON answer, which is written once here rather than twice slightly differently.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Iterable, Mapping, MutableMapping, Sequence
from typing import Any

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


def path_of(url: str) -> str:
    """The path a public URL answers on, without its trailing slash."""

    without_scheme = url.split("://", maxsplit=1)[-1]
    slash = without_scheme.find("/")
    return "" if slash == -1 else without_scheme[slash:].rstrip("/")


def header(headers: Iterable[tuple[bytes, bytes]], name: bytes) -> str | None:
    for key, value in headers:
        if key.lower() == name:
            return value.decode("latin-1")
    return None


async def read_body(receive: Receive, max_bytes: int) -> bytes | None:
    """The request body, or ``None`` when it is over the cap.

    Stops at the limit rather than buffering first and measuring after, because
    measuring after is how a caller decides how much memory this process spends.
    """

    body = bytearray()
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        body.extend(message.get("body", b""))
        if len(body) > max_bytes:
            return None
        if not message.get("more_body", False):
            break
    return bytes(body)


async def json_response(
    send: Send,
    status: int,
    payload: Mapping[str, Any],
    headers: Sequence[tuple[bytes, bytes]] = (),
) -> None:
    body = json.dumps(payload).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), *headers],
        }
    )
    await send({"type": "http.response.body", "body": body})


async def text_response(send: Send, status: int, text: str) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"text/plain; charset=utf-8")],
        }
    )
    await send({"type": "http.response.body", "body": text.encode()})


async def denied(send: Send, description: str) -> None:
    await json_response(
        send,
        403,
        {"error": "forbidden", "reason": "policy_denied", "error_description": description},
    )


async def lifespan(receive: Receive, send: Send) -> None:
    """Answer the server's startup and shutdown so a bare mount can be run."""

    while True:
        message = await receive()
        if message["type"] == "lifespan.startup":
            await send({"type": "lifespan.startup.complete"})
        elif message["type"] == "lifespan.shutdown":
            await send({"type": "lifespan.shutdown.complete"})
            return
