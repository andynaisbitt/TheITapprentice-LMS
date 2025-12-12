"""add logo fields to site_settings

Revision ID: 3878f4518d04
Revises: fc2614afbe3c
Create Date: 2025-12-07 19:28:07.684486

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "3878f4518d04"
down_revision: Union[str, None] = "fc2614afbe3c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add logo URL columns to site_settings
    op.add_column('site_settings', sa.Column('logo_url', sa.String(length=255), nullable=True))
    op.add_column('site_settings', sa.Column('logo_dark_url', sa.String(length=255), nullable=True))


def downgrade() -> None:
    # Remove logo URL columns
    op.drop_column('site_settings', 'logo_dark_url')
    op.drop_column('site_settings', 'logo_url')
