"""add_homepage_controls

Revision ID: 7218a929a053
Revises: 20d26c1dd256
Create Date: 2025-12-11 02:50:48.011283

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "7218a929a053"
down_revision: Union[str, None] = "20d26c1dd256"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Section Visibility Toggles (4 columns)
    op.add_column('site_settings', sa.Column('show_hero', sa.Boolean(), server_default='true', nullable=False))
    op.add_column('site_settings', sa.Column('show_carousel', sa.Boolean(), server_default='true', nullable=False))
    op.add_column('site_settings', sa.Column('show_categories', sa.Boolean(), server_default='true', nullable=False))
    op.add_column('site_settings', sa.Column('show_recent_posts', sa.Boolean(), server_default='true', nullable=False))

    # Content Limits (3 columns)
    op.add_column('site_settings', sa.Column('carousel_limit', sa.Integer(), server_default='5', nullable=False))
    op.add_column('site_settings', sa.Column('categories_limit', sa.Integer(), server_default='6', nullable=False))
    op.add_column('site_settings', sa.Column('recent_posts_limit', sa.Integer(), server_default='6', nullable=False))

    # CTA Button URLs (2 columns)
    op.add_column('site_settings', sa.Column('cta_primary_url', sa.String(length=255), server_default='/blog', nullable=False))
    op.add_column('site_settings', sa.Column('cta_secondary_url', sa.String(length=255), server_default='/about', nullable=False))

    # Carousel Settings (4 columns - includes transition type)
    op.add_column('site_settings', sa.Column('carousel_autoplay', sa.Boolean(), server_default='true', nullable=False))
    op.add_column('site_settings', sa.Column('carousel_interval', sa.Integer(), server_default='7000', nullable=False))
    op.add_column('site_settings', sa.Column('carousel_transition', sa.String(length=20), server_default='crossfade', nullable=False))


def downgrade() -> None:
    # Remove all 13 columns in reverse order
    op.drop_column('site_settings', 'carousel_transition')
    op.drop_column('site_settings', 'carousel_interval')
    op.drop_column('site_settings', 'carousel_autoplay')
    op.drop_column('site_settings', 'cta_secondary_url')
    op.drop_column('site_settings', 'cta_primary_url')
    op.drop_column('site_settings', 'recent_posts_limit')
    op.drop_column('site_settings', 'categories_limit')
    op.drop_column('site_settings', 'carousel_limit')
    op.drop_column('site_settings', 'show_recent_posts')
    op.drop_column('site_settings', 'show_categories')
    op.drop_column('site_settings', 'show_carousel')
    op.drop_column('site_settings', 'show_hero')
