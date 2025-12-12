"""add canonical_url to pages

Revision ID: 6f7e8d9c0a1b
Revises: 08038c92d6b9
Create Date: 2025-12-10

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6f7e8d9c0a1b'
down_revision = '08038c92d6b9'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add canonical_url column to pages table
    op.add_column('pages', sa.Column('canonical_url', sa.String(length=500), nullable=True))

    # Add index for faster canonical URL lookups
    op.create_index(
        op.f('ix_pages_canonical_url'),
        'pages',
        ['canonical_url'],
        unique=False
    )


def downgrade() -> None:
    # Remove index first
    op.drop_index(op.f('ix_pages_canonical_url'), table_name='pages')

    # Remove canonical_url column
    op.drop_column('pages', 'canonical_url')
