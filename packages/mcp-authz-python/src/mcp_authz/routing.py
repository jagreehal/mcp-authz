"""Validate MCP routing headers before using them for OAuth scope selection."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from mcp.shared.inbound import NAME_BEARING_METHODS, InboundLadderRejection, classify_inbound_request


@dataclass(frozen=True, slots=True)
class ScopedRoute:
    kind: Literal["modern", "legacy", "reject"]
    method: str | None = None
    name: str | None = None
    code: int | None = None


def classify_scoped_request(headers: Mapping[str, str], body: Any, *, http_method: str = "POST") -> ScopedRoute:
    """Return only route information that is safe to influence authorization."""

    if http_method.upper() != "POST":
        return ScopedRoute("legacy")
    folded = {key.casefold(): value for key, value in headers.items()}
    if "mcp-protocol-version" not in folded:
        return ScopedRoute("legacy")
    if not isinstance(body, Mapping):
        return ScopedRoute("reject", code=-32020)

    outcome = classify_inbound_request(body, headers=folded)
    if isinstance(outcome, InboundLadderRejection):
        return ScopedRoute("reject", code=outcome.code)
    method = body.get("method")
    if not isinstance(method, str):
        return ScopedRoute("reject", code=-32020)
    source = NAME_BEARING_METHODS.get(method)
    params = body.get("params")
    body_name = params.get(source) if source is not None and isinstance(params, Mapping) else None
    return ScopedRoute("modern", method=method, name=body_name if isinstance(body_name, str) else None)
