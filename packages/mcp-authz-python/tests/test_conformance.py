import json
from pathlib import Path
from typing import Any, cast

import pytest

from mcp_authz import (
    Identity,
    classify_scoped_request,
    decode_mcp_name_header,
    define_policy,
    scopes_for_capability,
)

CONFORMANCE = Path(__file__).parents[3] / "conformance" / "v1"


def fixture(path: str) -> dict[str, Any]:
    document = cast(dict[str, Any], json.loads((CONFORMANCE / path).read_text()))
    # A file that stopped being found, or stopped having cases, would otherwise
    # pass every loop below by never entering one.
    assert document.get("cases"), f"{path} has no cases"
    return document


def test_policy_decisions() -> None:
    document = fixture("policy/decisions.json")
    policy = define_policy(document["policy"])

    for case in document["cases"]:
        raw_identity = case["identity"]
        identity = Identity(
            issuer=raw_identity["issuer"],
            sub=raw_identity["sub"],
            email=raw_identity.get("email"),
            email_verified=raw_identity.get("emailVerified", False),
            domain=raw_identity.get("domain"),
            claims=raw_identity.get("claims", {}),
        )
        principal = policy(identity)
        assert list(principal.roles) == case["expected"]["roles"], case["name"]
        assert list(principal.permissions) == case["expected"]["permissions"], case["name"]
        assert all(principal.can(permission) for permission in case["expected"]["can"]), case["name"]
        assert all(not principal.can(permission) for permission in case["expected"]["cannot"]), case["name"]


def test_policy_explanations() -> None:
    document = fixture("policy/explanations.json")
    policy = define_policy(document["policy"])

    for case in document["cases"]:
        raw_identity = case["identity"]
        identity = Identity(
            issuer=raw_identity["issuer"],
            sub=raw_identity["sub"],
            email=raw_identity.get("email"),
            email_verified=raw_identity.get("emailVerified", False),
            domain=raw_identity.get("domain"),
            claims=raw_identity.get("claims", {}),
        )
        explanation = policy.explain(identity)
        expected = case["expected"]

        assert [
            {"index": rule.index, "roles": list(rule.roles), "deny": rule.deny} for rule in explanation.matched
        ] == expected["matched"], case["name"]

        denied = explanation.denied_by.index if explanation.denied_by else None
        assert denied == expected["deniedBy"], case["name"]

        # An index that does not point at the rule it claims is worse than no index.
        for rule in explanation.matched:
            assert dict(rule.match) == document["policy"]["rules"][rule.index].get("match", {}), case["name"]

        # The explanation and the decision are the same answer, reached twice.
        assert list(explanation.principal.roles) == expected["roles"], case["name"]
        assert list(explanation.principal.permissions) == expected["permissions"], case["name"]
        assert policy(identity).permissions == explanation.principal.permissions, case["name"]


def test_policy_validation() -> None:
    for case in fixture("policy/validation.json")["cases"]:
        with pytest.raises(ValueError) as error:
            define_policy(case["policy"])
        assert case["errorIncludes"] in str(error.value), case["name"]


def test_stable_subject_includes_issuer() -> None:
    policy = define_policy(
        {
            "roles": {"member": ["cases:read"]},
            "rules": [
                {
                    "match": {"issuer": "https://trusted.example", "sub": "shared-subject"},
                    "role": "member",
                }
            ],
        }
    )
    trusted = Identity(issuer="https://trusted.example", sub="shared-subject")
    other = Identity(issuer="https://other.example", sub="shared-subject")
    assert policy(trusted).can("cases:read")
    assert not policy(other).can("cases:read")


def test_scope_selection() -> None:
    document = fixture("protocol/scopes.json")
    for case in document["cases"]:
        name = case.get("capabilityName")
        if "headerName" in case:
            name = decode_mcp_name_header(case["headerName"])
        actual = scopes_for_capability(case["method"], name, document["map"], document["baseline"])
        assert actual == case["expected"], case["name"]


def test_routing() -> None:
    for case in fixture("protocol/routing.json")["cases"]:
        route = classify_scoped_request(case["headers"], case["body"])
        expected = case["expected"]
        assert route.kind == expected["kind"], case["name"]
        if route.kind == "modern":
            assert route.method == expected["method"], case["name"]
            assert route.name == expected.get("name"), case["name"]
        if route.kind == "reject":
            assert route.code == expected["code"], case["name"]


def test_non_post_routing_headers_stay_untrusted() -> None:
    route = classify_scoped_request(
        {"Mcp-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "delete_case"},
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "delete_case"}},
        http_method="GET",
    )

    assert route.kind == "legacy"
    assert route.method is None
    assert route.name is None
