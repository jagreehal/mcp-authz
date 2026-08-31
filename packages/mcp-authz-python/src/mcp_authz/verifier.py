"""JWKS-backed verification using the official MCP TokenVerifier interface."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import Any

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWTError
from mcp.server.auth.provider import AccessToken


class JwtVerifier:
    """Verify signed JWT access tokens into official MCP ``AccessToken`` values."""

    def __init__(
        self,
        *,
        issuer: str,
        jwks_uri: str,
        resource: str,
        allowed_domain: str | None = None,
        email_claim: str = "email",
        email_verified_claim: str = "email_verified",
        require_email_verified: bool = True,
        algorithms: Sequence[str] = ("RS256", "ES256"),
    ) -> None:
        self.issuer = issuer
        self.resource = resource.split("#", maxsplit=1)[0]
        self.allowed_domain = allowed_domain
        self.email_claim = email_claim
        self.email_verified_claim = email_verified_claim
        self.require_email_verified = require_email_verified
        self.algorithms = tuple(algorithms)
        if not self.algorithms or any(algorithm.startswith("HS") for algorithm in self.algorithms):
            raise ValueError("JwtVerifier requires at least one asymmetric signing algorithm.")
        self._jwks = PyJWKClient(jwks_uri, cache_keys=True)

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return ``None`` for every invalid credential, as the MCP SDK expects."""

        return await asyncio.to_thread(self._verify_token, token)

    def _verify_token(self, token: str) -> AccessToken | None:
        try:
            key = self._jwks.get_signing_key_from_jwt(token)
            payload = jwt.decode(
                token,
                key.key,
                algorithms=list(self.algorithms),
                audience=self.resource,
                issuer=self.issuer,
                options={"require": ["exp", "iss", "aud", "sub"]},
            )
        except (PyJWTError, ValueError):
            return None

        sub = payload.get("sub")
        email = payload.get(self.email_claim)
        if not isinstance(sub, str) or not sub or not isinstance(email, str) or not email:
            return None
        if self.require_email_verified and payload.get(self.email_verified_claim) is not True:
            return None
        domain = payload.get("hd")
        if self.allowed_domain and (not isinstance(domain, str) or domain.casefold() != self.allowed_domain.casefold()):
            return None

        normalized_claims = dict(payload)
        normalized_claims["email"] = email
        normalized_claims["email_verified"] = (
            not self.require_email_verified or payload.get(self.email_verified_claim) is True
        )
        if isinstance(domain, str):
            normalized_claims["hd"] = domain
        return AccessToken(
            token=token,
            client_id=_client_id(payload, sub),
            scopes=_scopes(payload.get("scope")),
            expires_at=int(payload["exp"]),
            resource=self.resource,
            subject=sub,
            claims=normalized_claims,
        )


def _client_id(payload: dict[str, Any], fallback: str) -> str:
    for claim in ("client_id", "azp"):
        value = payload.get(claim)
        if isinstance(value, str) and value:
            return value
    return fallback


def _scopes(value: Any) -> list[str]:
    if isinstance(value, str):
        return value.split()
    if isinstance(value, list):
        return [scope for scope in value if isinstance(scope, str) and scope]
    return []
