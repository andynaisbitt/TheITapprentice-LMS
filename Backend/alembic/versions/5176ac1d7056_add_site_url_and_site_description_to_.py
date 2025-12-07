"""add site_url and site_description to theme_settings

Revision ID: 5176ac1d7056
Revises: 9e92e2da7909
Create Date: 2025-12-07 18:52:53.082439

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "5176ac1d7056"
down_revision: Union[str, None] = "9e92e2da7909"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add site_url and site_description columns to theme_settings
    op.add_column('theme_settings', sa.Column('site_url', sa.String(length=255), nullable=True))
    op.add_column('theme_settings', sa.Column('site_description', sa.String(length=500), nullable=True))

    # Set default values for existing row
    op.execute("UPDATE theme_settings SET site_url = 'https://yourdomain.com' WHERE site_url IS NULL")
    op.execute("UPDATE theme_settings SET site_description = 'Latest blog posts' WHERE site_description IS NULL")


def downgrade() -> None:
    # Remove site_url and site_description columns
    op.drop_column('theme_settings', 'site_description')
    op.drop_column('theme_settings', 'site_url')
