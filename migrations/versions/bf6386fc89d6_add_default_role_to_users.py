"""add default_role to users

Revision ID: bf6386fc89d6
Revises: 6e601cabdb60
Create Date: 2026-05-13 22:35:14.342495

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "bf6386fc89d6"
down_revision: Union[str, Sequence[str], None] = "6e601cabdb60"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("default_role", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "default_role")
