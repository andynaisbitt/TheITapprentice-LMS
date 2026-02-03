"""add registration control to site settings

Revision ID: v2_11_registration_control
Revises: 116a2592ee5f
Create Date: 2025-12-12

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'v2_11_registration_control'
down_revision = '116a2592ee5f'
branch_labels = None
depends_on = None


def upgrade():
    """Add registration control columns to site_settings table"""

    # Add registration_enabled column (default True - registration is enabled by default)
    op.add_column('site_settings',
        sa.Column('registration_enabled', sa.Boolean(), nullable=False, server_default='true')
    )

    # Add registration_disabled_message column (nullable - optional custom message)
    op.add_column('site_settings',
        sa.Column('registration_disabled_message', sa.String(length=500), nullable=True)
    )


def downgrade():
    """Remove registration control columns"""

    op.drop_column('site_settings', 'registration_disabled_message')
    op.drop_column('site_settings', 'registration_enabled')
