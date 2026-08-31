"""Verified identities shared by token verification and authorization policy."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Identity:
    """Facts proved by the access-token verifier, never by client headers."""

    issuer: str
    sub: str
    email: str | None = None
    email_verified: bool = False
    domain: str | None = None
    claims: Mapping[str, Any] = field(default_factory=dict)
