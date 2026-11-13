"""Current account data and compatibility identity normalization."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


def account_identity(user: dict) -> tuple:
    """Normalize account generation consistently with SQLite's naive UTC reads."""
    created_at = user.get("created_at")
    if created_at is not None:
        timestamp = datetime.fromisoformat(created_at)
        created_at = timestamp.replace(tzinfo=timestamp.tzinfo or UTC).astimezone(UTC).isoformat()
    return (user.get("id"), user.get("username"), created_at)


@dataclass(frozen=True)
class Principal:
    """Keep stored grants; role expansion belongs to the application service."""

    user: dict[str, Any]

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
