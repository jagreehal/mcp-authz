import time
from types import SimpleNamespace
from typing import Any, cast

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_authz import JwtVerifier


@pytest.fixture
def verifier_and_key() -> tuple[JwtVerifier, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = JwtVerifier(
        issuer="https://auth.example.com",
        jwks_uri="https://auth.example.com/.well-known/jwks.json",
        resource="https://mcp.example.com/mcp",
        allowed_domain="acme.com",
        algorithms=("RS256",),
    )
    verifier._jwks = cast(
        Any, SimpleNamespace(get_signing_key_from_jwt=lambda _token: SimpleNamespace(key=key.public_key()))
    )
    return verifier, key


def make_token(key: rsa.RSAPrivateKey, **overrides: object) -> str:
    claims = {
        "iss": "https://auth.example.com",
        "aud": "https://mcp.example.com/mcp",
        "sub": "user-1",
        "email": "person@acme.com",
        "email_verified": True,
        "hd": "acme.com",
        "scope": "mcp cases:read",
        "exp": int(time.time()) + 300,
        **overrides,
    }
    return jwt.encode(claims, key, algorithm="RS256")


async def test_returns_official_access_token(verifier_and_key: tuple[JwtVerifier, rsa.RSAPrivateKey]) -> None:
    verifier, key = verifier_and_key
    token = make_token(key)
    verified = await verifier.verify_token(token)
    assert verified is not None
    assert verified.subject == "user-1"
    assert verified.scopes == ["mcp", "cases:read"]
    assert verified.claims is not None and verified.claims["email"] == "person@acme.com"


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "https://another.example.com/mcp"},
        {"email_verified": False},
        {"hd": "other.com"},
        {"exp": 1},
    ],
)
async def test_rejects_invalid_identity_or_token(
    verifier_and_key: tuple[JwtVerifier, rsa.RSAPrivateKey], overrides: dict[str, object]
) -> None:
    verifier, key = verifier_and_key
    assert await verifier.verify_token(make_token(key, **overrides)) is None
