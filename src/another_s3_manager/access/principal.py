"""Current account data and compatibility identity normalization."""

from dataclasses import dataclass
from typing import Any


def account_identity(user: dict) -> tuple:
    """The single account identity rule shared by all authentication and jobs."""
    generation = user.get("auth_generation")
    if not isinstance(generation, str) or not generation:
        raise ValueError("Account generation is required")
    return (user["id"], generation)


@dataclass(frozen=True)
class Principal:
    """Keep stored grants; role expansion belongs to the application service."""

    user: dict[str, Any]

    def __post_init__(self):
        account_identity(self.user)

    @property
    def id(self) -> int:
        return self.user["id"]

    @property
    def username(self) -> str:
        return self.user["username"]

    @property
    def granted_roles(self) -> list[str]:
        return list(self.user.get("allowed_roles", []))

    def to_user_dict(self) -> dict[str, Any]:
        return {**self.user, **({"allowed_roles": self.granted_roles} if "allowed_roles" in self.user else {})}


@dataclass(frozen=True)
class BearerAuthentication:
    token: Any
    principal: Principal
    projected_roles: list[str]
