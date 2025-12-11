"""add_og_image_to_site_settings

Revision ID: 20d26c1dd256
Revises: 5f6e55b7e175
Create Date: 2025-12-11 02:14:14.905729

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "20d26c1dd256"
down_revision: Union[str, None] = "5f6e55b7e175"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add og_image column to site_settings table
    op.add_column('site_settings', sa.Column('og_image', sa.String(length=255), nullable=True))


def downgrade() -> None:
    # Remove og_image column from site_settings table
    op.drop_column('site_settings', 'og_image')
