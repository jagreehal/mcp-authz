"""A minimal protected MCP server built on the official Python SDK."""

import os

import uvicorn
from mcp.server.auth.settings import AuthSettings
from mcp_authz import AuthorizedMCPServer, JwtVerifier, define_policy

PUBLIC_URL = os.environ.get("MCP_PUBLIC_URL", "http://127.0.0.1:8300/mcp")
ISSUER = os.environ.get("OAUTH_ISSUER", "https://auth.example.com")
JWKS_URI = os.environ.get("OAUTH_JWKS_URI", f"{ISSUER}/.well-known/jwks.json")

policy = define_policy(
    {
        "permissions": ["cases:read", "cases:write"],
        "roles": {
            "reader": ["cases:read"],
            "editor": ["cases:read", "cases:write"],
        },
        "rules": [
            {"match": {"domain": "acme.com"}, "role": "reader"},
            {"match": {"email": "alice@acme.com"}, "role": "editor"},
            {"match": {"sub": "departed-contractor"}, "deny": True},
        ],
    }
)

server = AuthorizedMCPServer(
    "acme-cases",
    policy=policy,
    token_verifier=JwtVerifier(
        issuer=ISSUER,
        jwks_uri=JWKS_URI,
        resource=PUBLIC_URL,
        allowed_domain="acme.com",
    ),
    auth=AuthSettings(
        issuer_url=ISSUER,
        resource_server_url=PUBLIC_URL,
        required_scopes=["mcp"],
    ),
)


@server.tool(permission="cases:read")
def get_case(case_id: str) -> dict[str, str]:
    """Read a case."""

    return {"id": case_id, "title": "Example case"}


@server.tool(permission="cases:write")
def update_case(case_id: str, title: str) -> dict[str, str]:
    """Rename a case."""

    return {"id": case_id, "title": title}


app = server.streamable_http_app(stateless_http=True, json_response=True)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8300)

