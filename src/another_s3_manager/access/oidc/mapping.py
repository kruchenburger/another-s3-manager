"""The sole claim-to-access policy. No provider-specific grant rewriting."""

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


def claim_at(claims, path):
    value = claims
    for component in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(component)
    return value


@dataclass(frozen=True)
class MappingResult:
    roles: tuple[str, ...]
    admin: bool
    matched_rules: int

    @property
    def eligible(self):
        return self.admin or bool(self.roles)


def evaluate_mapping(claims, config):
    settings = config.get("auth", {}).get("oidc", {})
    rules = settings.get("role_mapping", {}).get("rules", [])
    names = {role["name"] for role in config.get("roles", []) if role.get("name")}
    overage = isinstance(claims.get("_claim_names"), dict) and "groups" in claims["_claim_names"]
    if overage:
        logger.warning("OIDC group overage; use filtered groups or app roles")
    roles, admin, count, unknown = set(), False, 0, False
    for rule in rules:
        if overage and rule["claim"] == settings.get("groups_claim", "groups"):
            continue
        value = claim_at(claims, rule["claim"])
        matches = (
            value == rule["value"]
            if isinstance(value, str)
            else (isinstance(value, list) and all(isinstance(item, str) for item in value) and rule["value"] in value)
        )
        if rule["claim"] == "hd" and claims.get("email_verified") is not True:
            matches = False
        if matches:
            count += 1
            admin |= rule.get("admin", False)
            roles.update(name for name in rule.get("roles", []) if name in names)
            unknown |= any(name not in names for name in rule.get("roles", []))
    if unknown:
        logger.warning("OIDC mapping references unavailable roles")
    return MappingResult(tuple(sorted(roles)), admin, count)
