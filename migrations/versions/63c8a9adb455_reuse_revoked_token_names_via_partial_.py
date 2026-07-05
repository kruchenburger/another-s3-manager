"""reuse revoked token names via partial unique index

Revoke is a soft delete (revoked_at set) and revoked tokens are hidden from
every listing, so the absolute UNIQUE(user_id, name) constraint made a
revoked token block its own name forever — the API returned 409 for a token
the user can't see. Replace it with a partial unique index that enforces
uniqueness among ACTIVE tokens only.

Revision ID: 63c8a9adb455
Revises: 7cd668620249
Create Date: 2026-07-03 14:26:44.033111

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "63c8a9adb455"
down_revision: Union[str, Sequence[str], None] = "7cd668620249"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # batch mode: SQLite can't ALTER-drop a constraint in place, so the table
    # is rebuilt without it.
    with op.batch_alter_table("api_tokens", schema=None) as batch_op:
        batch_op.drop_constraint("uq_api_token_user_name", type_="unique")
    op.create_index(
        "uq_api_token_user_name_active",
        "api_tokens",
        ["user_id", "name"],
        unique=True,
        sqlite_where=sa.text("revoked_at IS NULL"),
    )


def downgrade() -> None:
    """Downgrade schema.

    NOTE: fails if a user has already reused a revoked token's name (the
    absolute constraint can't hold with revoked namesakes present). Delete
    the revoked duplicates first if you really need to downgrade.
    """
    op.drop_index("uq_api_token_user_name_active", table_name="api_tokens")
    with op.batch_alter_table("api_tokens", schema=None) as batch_op:
        batch_op.create_unique_constraint("uq_api_token_user_name", ["user_id", "name"])
