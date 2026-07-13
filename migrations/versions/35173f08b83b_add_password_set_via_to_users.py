"""add password_set_via to users

Revision ID: 35173f08b83b
Revises: 63c8a9adb455
Create Date: 2026-07-13 18:22:12.207427

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "35173f08b83b"
down_revision: Union[str, Sequence[str], None] = "63c8a9adb455"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add password provenance, backfilling EXISTING rows fail-safe.

    Deliberately dumb and deterministic: no env reads, no password hashing.
      - Every existing row gets server_default 'unknown'.
      - Every non-admin row is then marked 'ui' — the startup env sync only ever
        looks at 'admin', and 'ui' is the do-not-touch value.
      - The 'admin' row stays 'unknown' and is classified ONCE at startup by
        users.sync_admin_password_from_env(), which can bcrypt-prove whether the
        stored hash is still the built-in default (or the current ADMIN_PASSWORD).

    Backfilling 'env' here would be a security bug: on the next boot a stale
    ADMIN_PASSWORD would silently overwrite a password the operator set in the UI.
    Nothing in this migration can produce 'env'.
    """
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(sa.Column("password_set_via", sa.String(), server_default="unknown", nullable=False))
    op.execute("UPDATE users SET password_set_via = 'ui' WHERE username <> 'admin'")


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_column("password_set_via")
