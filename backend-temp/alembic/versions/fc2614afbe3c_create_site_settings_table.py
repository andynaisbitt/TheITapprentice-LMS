"""create site_settings table

Revision ID: fc2614afbe3c
Revises: 5176ac1d7056
Create Date: 2025-12-07 19:26:03.202890

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "fc2614afbe3c"
down_revision: Union[str, None] = "5176ac1d7056"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create site_settings table
    op.create_table(
        'site_settings',
        sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
        sa.Column('google_analytics_id', sa.String(length=50), nullable=True),
        sa.Column('google_adsense_client_id', sa.String(length=50), nullable=True),
        sa.Column('site_title', sa.String(length=100), nullable=True, server_default='FastReactCMS'),
        sa.Column('site_tagline', sa.String(length=200), nullable=True),
        sa.Column('site_url', sa.String(length=255), nullable=True, server_default='https://yourdomain.com'),
        sa.Column('meta_description', sa.String(length=500), nullable=True, server_default='A modern blog platform'),
        sa.Column('meta_keywords', sa.String(length=500), nullable=True),
        sa.Column('hero_title', sa.String(length=200), nullable=True, server_default='Share Your Story'),
        sa.Column('hero_subtitle', sa.String(length=500), nullable=True),
        sa.Column('hero_badge_text', sa.String(length=50), nullable=True, server_default='Open Source'),
        sa.Column('hero_cta_primary', sa.String(length=100), nullable=True, server_default='Explore Articles'),
        sa.Column('hero_cta_secondary', sa.String(length=100), nullable=True, server_default='Learn More'),
        sa.Column('stats_articles', sa.String(length=20), nullable=True),
        sa.Column('stats_readers', sa.String(length=20), nullable=True),
        sa.Column('stats_free', sa.String(length=20), nullable=True, server_default='100% Free'),
        sa.Column('twitter_handle', sa.String(length=100), nullable=True),
        sa.Column('facebook_url', sa.String(length=255), nullable=True),
        sa.Column('linkedin_url', sa.String(length=255), nullable=True),
        sa.Column('github_url', sa.String(length=255), nullable=True),
        sa.Column('contact_email', sa.String(length=255), nullable=True),
        sa.Column('support_email', sa.String(length=255), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    # Drop site_settings table
    op.drop_table('site_settings')
