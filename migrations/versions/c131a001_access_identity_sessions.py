"""Expand Access identity and session storage.

Generation storage is nullable so N-1-shaped inserts remain valid. Each existing
row receives its own random generation. Downgrade is test/dev-only: it loses
identities, login ledger and all new security fields. Re-upgrade generates new
identities for the preserved accounts and invalidates earlier cookies.
Old-image startup cannot resolve this revision; recovery requires a forward fix
or a consistent pre-release backup, losing all subsequent changes.
"""

import secrets

import sqlalchemy as sa
from alembic import op

revision = "c131a001"
down_revision = "35173f08b83b"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("auth_source", sa.String(), nullable=False, server_default="local"))
        batch.add_column(sa.Column("is_disabled", sa.Boolean(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("auth_generation", sa.String(), nullable=True))
        batch.add_column(sa.Column("session_epoch", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("sso_authz_valid_until", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("mapping_mode_applied", sa.String(), nullable=True))
        batch.create_check_constraint("ck_users_mapping_mode", "mapping_mode_applied IN ('sync', 'initial')")
    connection = op.get_bind()
    for user_id in connection.execute(sa.text("SELECT id FROM users")).scalars().all():
        connection.execute(
            sa.text("UPDATE users SET auth_generation=:generation WHERE id=:id"),
            {"id": user_id, "generation": secrets.token_urlsafe(32)},
        )
    op.create_table(
        "user_identities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("issuer", sa.String(), nullable=False),
        sa.Column("subject", sa.String(), nullable=False),
        sa.Column("email_at_link", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("issuer", "subject", name="uq_identity_issuer_subject"),
        sa.UniqueConstraint("user_id", "issuer", name="uq_identity_user_issuer"),
    )
    op.create_table(
        "oidc_login_transactions",
        sa.Column("state_hash", sa.String(64), primary_key=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_oidc_login_transactions_expires_at", "oidc_login_transactions", ["expires_at"])


def downgrade():
    op.drop_table("oidc_login_transactions")
    op.drop_table("user_identities")
    with op.batch_alter_table("users") as batch:
        batch.drop_constraint("ck_users_mapping_mode", type_="check")
        for name in (
            "mapping_mode_applied",
            "sso_authz_valid_until",
            "session_epoch",
            "auth_generation",
            "is_disabled",
            "auth_source",
        ):
            batch.drop_column(name)
