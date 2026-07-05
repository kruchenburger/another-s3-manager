"""ORM models for users, user_roles, and bans."""

from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    theme: Mapped[str] = mapped_column(String, nullable=False, default="auto")
    default_role: Mapped[str | None] = mapped_column(String, nullable=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="0")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )

    roles: Mapped[list["UserRole"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )
    bans: Mapped[list["Ban"]] = relationship(back_populates="user", cascade="all, delete-orphan", passive_deletes=True)
    api_tokens: Mapped[list["ApiToken"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )


class UserRole(Base):
    __tablename__ = "user_roles"
    __table_args__ = (UniqueConstraint("user_id", "role_name", name="uq_user_role"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role_name: Mapped[str] = mapped_column(String, nullable=False)

    user: Mapped["User"] = relationship(back_populates="roles")


class Ban(Base):
    __tablename__ = "bans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    banned_until: Mapped[float] = mapped_column(Float, nullable=False)
    banned_at: Mapped[float] = mapped_column(Float, nullable=False)
    reason: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    user: Mapped["User"] = relationship(back_populates="bans")


class ApiToken(Base):
    __tablename__ = "api_tokens"
    __table_args__ = (
        # Uniqueness among ACTIVE tokens only. Revoke is a soft delete
        # (revoked_at set) and revoked tokens are hidden from every listing,
        # so an absolute UNIQUE(user_id, name) made a revoked token block its
        # own name forever — a 409 for a token the user can't see. The
        # partial index allows any number of revoked namesakes but at most
        # one active token per (user, name).
        Index(
            "uq_api_token_user_name_active",
            "user_id",
            "name",
            unique=True,
            sqlite_where=text("revoked_at IS NULL"),
        ),
        CheckConstraint(
            "max_read_bytes > 0 AND max_read_bytes <= 10485760",
            name="ck_api_token_max_read_bytes_range",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_read_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="1")
    max_read_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=1048576, server_default="1048576")

    user: Mapped["User"] = relationship(back_populates="api_tokens")
