"""Small deny-by-default, permission-based authorization policies."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .identity import Identity


@dataclass(frozen=True, slots=True)
class Principal:
    issuer: str
    sub: str
    email: str | None
    domain: str | None
    roles: tuple[str, ...]
    permissions: tuple[str, ...]

    def can(self, permission: str) -> bool:
        return "*" in self.permissions or permission in self.permissions


@dataclass(frozen=True, slots=True)
class MatchedRule:
    """One rule that matched, pointed back at the line an administrator edits."""

    index: int
    match: Mapping[str, Any]
    roles: tuple[str, ...]
    deny: bool


@dataclass(frozen=True, slots=True)
class Explanation:
    """Why a principal came out the way it did."""

    principal: Principal
    matched: tuple[MatchedRule, ...]
    denied_by: MatchedRule | None


class Policy:
    """A validated policy callable."""

    def __init__(
        self,
        roles: Mapping[str, tuple[str, ...]],
        rules: tuple[_Rule, ...],
        permissions: tuple[str, ...],
    ) -> None:
        self.roles = dict(roles)
        self.rules = rules
        self.permissions = permissions

    def __call__(self, identity: Identity) -> Principal:
        return self.explain(identity).principal

    def explain(self, identity: Identity) -> Explanation:
        """The same decision, plus the rules that produced it.

        Nothing on the request path calls this. It answers "why can Alice do
        this", which the principal alone cannot, and it shares the one matcher
        so the answer can never disagree with the decision.
        """

        matched = tuple(rule for rule in self.rules if _matches(rule.match, identity))
        denied_by = next((rule for rule in matched if rule.deny), None)
        held_roles = () if denied_by else _unique(role for rule in matched for role in rule.roles)
        held_permissions = (
            ()
            if denied_by
            else _unique(permission for role in held_roles for permission in self.roles[role])
        )
        principal = Principal(
            issuer=identity.issuer,
            sub=identity.sub,
            email=identity.email,
            domain=identity.domain,
            roles=held_roles,
            permissions=held_permissions,
        )
        return Explanation(
            principal=principal,
            matched=tuple(_matched_rule(rule) for rule in matched),
            denied_by=_matched_rule(denied_by) if denied_by else None,
        )


@dataclass(frozen=True, slots=True)
class _Rule:
    index: int
    match: Mapping[str, Any]
    roles: tuple[str, ...]
    deny: bool


def _matched_rule(rule: _Rule) -> MatchedRule:
    return MatchedRule(index=rule.index, match=rule.match, roles=rule.roles, deny=rule.deny)


def define_policy(spec: Mapping[str, Any]) -> Policy:
    """Validate and compile a plain JSON/YAML-shaped policy."""

    if not isinstance(spec, Mapping):
        raise ValueError("Policy must be an object.")
    _known_fields(spec, {"permissions", "roles", "rules"}, "Policy")

    raw_roles = spec.get("roles")
    raw_rules = spec.get("rules")
    if not isinstance(raw_roles, Mapping):
        raise ValueError("Policy 'roles' must be an object.")
    if not isinstance(raw_rules, list):
        raise ValueError("Policy 'rules' must be an array.")

    catalogue = None
    if "permissions" in spec:
        catalogue = _string_list(spec["permissions"], "Policy 'permissions'")
        if "*" in catalogue:
            raise ValueError("Policy 'permissions' must name concrete permissions, not '*'.")
    known_permissions = set(catalogue) if catalogue is not None else None

    roles: dict[str, tuple[str, ...]] = {}
    for role, raw_permissions in raw_roles.items():
        if not isinstance(role, str) or not role:
            raise ValueError("Policy role names must not be empty.")
        permissions = _string_list(raw_permissions, f"Policy role '{role}'")
        if "*" in permissions and len(permissions) > 1:
            raise ValueError(f"Policy role '{role}' grants '*' and must not list redundant permissions.")
        for permission in permissions:
            if permission != "*" and known_permissions is not None and permission not in known_permissions:
                raise ValueError(
                    f"Policy role '{role}' grants '{permission}', which is absent from the permission catalogue."
                )
        roles[role] = permissions

    rules: list[_Rule] = []
    for index, raw_rule in enumerate(raw_rules):
        at = f"Policy rule {index}"
        if not isinstance(raw_rule, Mapping):
            raise ValueError(f"{at} must be an object.")
        _known_fields(raw_rule, {"match", "role", "deny"}, at)
        deny = raw_rule.get("deny", False)
        if not isinstance(deny, bool):
            raise ValueError(f"{at} 'deny' must be a boolean.")
        if not deny and "role" not in raw_rule:
            raise ValueError(f"{at} grants nothing: it needs a 'role' or 'deny: true'.")
        named_roles = _role_names(raw_rule.get("role"), at)
        for role in named_roles:
            if role not in roles:
                raise ValueError(f"{at} names role '{role}', which is not defined.")
        rules.append(_Rule(index, _validate_match(raw_rule.get("match"), at), named_roles, deny))

    concrete = catalogue or _unique(
        permission for granted in roles.values() for permission in granted if permission != "*"
    )
    return Policy(roles, tuple(rules), concrete)


def _known_fields(value: Mapping[str, Any], allowed: set[str], at: str) -> None:
    for key in value:
        if key not in allowed:
            raise ValueError(f"{at} has unknown field '{key}'.")


def _string_list(value: Any, at: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{at} must be an array of permission strings.")
    if any(not isinstance(entry, str) or not entry for entry in value):
        raise ValueError(f"{at} must be an array of non-empty permission strings.")
    return _unique(value)


def _role_names(value: Any, at: str) -> tuple[str, ...]:
    if value is None:
        return ()
    values = value if isinstance(value, list) else [value]
    if not values or any(not isinstance(role, str) or not role for role in values):
        raise ValueError(f"{at} 'role' must be a non-empty role name or array of role names.")
    return _unique(values)


def _validate_match(value: Any, at: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"{at} 'match' must be an object.")
    _known_fields(value, {"issuer", "sub", "email", "domain", "claim"}, f"{at} match")
    for key in ("issuer", "sub", "email", "domain"):
        field = value.get(key)
        if field is not None and (not isinstance(field, str) or not field):
            raise ValueError(f"{at} match '{key}' must be a non-empty string.")
    claims = value.get("claim")
    if claims is not None:
        if not isinstance(claims, Mapping):
            raise ValueError(f"{at} match 'claim' must be an object.")
        if any(
            not isinstance(path, str) or not path or not isinstance(expected, str) or not expected
            for path, expected in claims.items()
        ):
            raise ValueError(f"{at} match claim entries must have non-empty string names and values.")
    return dict(value)


def _matches(match: Mapping[str, Any], identity: Identity) -> bool:
    if "issuer" in match and match["issuer"] != identity.issuer:
        return False
    if "sub" in match and match["sub"] != identity.sub:
        return False
    if "email" in match and (
        not identity.email_verified
        or identity.email is None
        or str(match["email"]).casefold() != identity.email.casefold()
    ):
        return False
    domain = None
    if identity.email_verified and identity.email:
        domain = identity.domain or identity.email.rpartition("@")[2] or None
    if "domain" in match and (domain is None or str(match["domain"]).casefold() != domain.casefold()):
        return False
    for path, expected in match.get("claim", {}).items():
        actual = _claim_at(identity.claims, path)
        if isinstance(actual, list):
            if expected not in actual:
                return False
        elif actual != expected:
            return False
    return True


def _claim_at(claims: Mapping[str, Any], path: str) -> Any:
    if path in claims:
        return claims[path]
    value: Any = claims
    for key in path.split("."):
        if not isinstance(value, Mapping) or key not in value:
            return None
        value = value[key]
    return value


def _unique(values: Sequence[str] | Any) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))
