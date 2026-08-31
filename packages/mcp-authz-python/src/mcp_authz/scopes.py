"""OAuth scope selection for MCP capability headers (SEP-2243)."""

from collections.abc import Mapping, Sequence

from mcp.shared.inbound import decode_header_value

ScopeRequirement = str | Sequence[str]
CapabilityScopeMap = Mapping[str, ScopeRequirement]


def decode_mcp_name_header(value: str) -> str | None:
    """Decode through the official SDK's canonical MCP header codec."""

    return decode_header_value(value.strip())


def scopes_for_capability(
    method: str | None,
    name: str | None,
    capability_scopes: CapabilityScopeMap,
    baseline: str = "mcp",
) -> list[str]:
    if not name:
        return [baseline]
    key: str | None = None
    if method == "tools/call":
        key = name if name in capability_scopes else f"tool:{name}"
    elif method == "prompts/get":
        key = f"prompt:{name}"
    elif method == "resources/read":
        key = f"resource:{name}"
    required = capability_scopes.get(key, baseline) if key else baseline
    return [required] if isinstance(required, str) else list(required)
