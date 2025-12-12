"""create_newsletter_subscribers_table

Revision ID: 671355394ee5
Revises: 486b10205e55
Create Date: 2025-12-08 02:12:20.785499

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "671355394ee5"
down_revision: Union[str, None] = "486b10205e55"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create newsletter_subscribers table
    op.create_table(
        'newsletter_subscribers',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('confirmed', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('confirmation_token', sa.String(length=255), nullable=True),
        sa.Column('subscribed_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('unsubscribed_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_newsletter_email', 'newsletter_subscribers', ['email'], unique=True)
    op.create_index('idx_newsletter_active', 'newsletter_subscribers', ['is_active'])


def downgrade() -> None:
    op.drop_index('idx_newsletter_active', table_name='newsletter_subscribers')
    op.drop_index('idx_newsletter_email', table_name='newsletter_subscribers')
    op.drop_table('newsletter_subscribers')
