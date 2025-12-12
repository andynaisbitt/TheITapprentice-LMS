"""add_favicon_fields_to_site_settings

Revision ID: 51798c8df2ec
Revises: 7218a929a053
Create Date: 2025-12-11 05:01:49.614834

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "51798c8df2ec"
down_revision: Union[str, None] = "7218a929a053"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add favicon_url and favicon_dark_url columns to site_settings table
    op.add_column("site_settings", sa.Column("favicon_url", sa.String(255), nullable=True))
    op.add_column("site_settings", sa.Column("favicon_dark_url", sa.String(255), nullable=True))


def downgrade() -> None:
    # Remove favicon columns
    op.drop_column("site_settings", "favicon_dark_url")
    op.drop_column("site_settings", "favicon_url")
