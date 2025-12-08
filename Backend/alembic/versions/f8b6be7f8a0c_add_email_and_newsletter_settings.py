"""add_email_and_newsletter_settings

Revision ID: f8b6be7f8a0c
Revises: 671355394ee5
Create Date: 2025-12-08 02:12:47.000050

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "f8b6be7f8a0c"
down_revision: Union[str, None] = "671355394ee5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add newsletter enable/disable and SMTP settings to site_settings
    op.add_column('site_settings', sa.Column('newsletter_enabled', sa.Boolean(), nullable=True, server_default='true'))
    op.add_column('site_settings', sa.Column('smtp_host', sa.String(length=255), nullable=True))
    op.add_column('site_settings', sa.Column('smtp_port', sa.Integer(), nullable=True, server_default='587'))
    op.add_column('site_settings', sa.Column('smtp_username', sa.String(length=255), nullable=True))
    op.add_column('site_settings', sa.Column('smtp_password', sa.String(length=255), nullable=True))
    op.add_column('site_settings', sa.Column('smtp_use_tls', sa.Boolean(), nullable=True, server_default='true'))
    op.add_column('site_settings', sa.Column('smtp_from_email', sa.String(length=255), nullable=True))
    op.add_column('site_settings', sa.Column('smtp_from_name', sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column('site_settings', 'smtp_from_name')
    op.drop_column('site_settings', 'smtp_from_email')
    op.drop_column('site_settings', 'smtp_use_tls')
    op.drop_column('site_settings', 'smtp_password')
    op.drop_column('site_settings', 'smtp_username')
    op.drop_column('site_settings', 'smtp_port')
    op.drop_column('site_settings', 'smtp_host')
    op.drop_column('site_settings', 'newsletter_enabled')
