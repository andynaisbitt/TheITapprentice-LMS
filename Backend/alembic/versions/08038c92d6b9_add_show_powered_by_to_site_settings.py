"""add_show_powered_by_to_site_settings

Revision ID: 08038c92d6b9
Revises: 3878f4518d04
Create Date: 2025-12-08 00:11:13.341036

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "08038c92d6b9"
down_revision: Union[str, None] = "3878f4518d04"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add show_powered_by field with default True (show by default)
    op.add_column('site_settings', sa.Column('show_powered_by', sa.Boolean(), nullable=True, server_default='true'))


def downgrade() -> None:
    op.drop_column('site_settings', 'show_powered_by')
