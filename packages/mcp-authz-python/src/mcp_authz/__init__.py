"""Authorization for servers built with the official MCP Python SDK."""

from .gate import gate
from .identity import Identity
from .policy import Explanation, MatchedRule, Policy, Principal, define_policy
from .routing import ScopedRoute, classify_scoped_request
from .scopes import decode_mcp_name_header, scopes_for_capability
from .server import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalSink,
    AuthorizationMiddleware,
    AuthorizedMCPServer,
    current_principal,
    identity_from_access_token,
)
from .verifier import JwtVerifier

__version__ = "0.2.0"

__all__ = [
    "ApprovalDecision",
    "ApprovalRequest",
    "ApprovalSink",
    "AuthorizedMCPServer",
    "AuthorizationMiddleware",
    "Explanation",
    "Identity",
    "JwtVerifier",
    "MatchedRule",
    "Policy",
    "Principal",
    "ScopedRoute",
    "classify_scoped_request",
    "current_principal",
    "decode_mcp_name_header",
    "define_policy",
    "gate",
    "identity_from_access_token",
    "scopes_for_capability",
]
