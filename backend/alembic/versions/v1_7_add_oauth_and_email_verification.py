"""v1.7 add oauth and email verification

Revision ID: v1_7_oauth_email_verification
Revises: 51798c8df2ec
Create Date: 2026-01-11 06:30:00.000000

This migration adds support for:
1. Google OAuth authentication (google_id, email_verified_at columns)
2. Email verification system (email_verifications table)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "v1_7_oauth_email_verification"
down_revision: Union[str, None] = "51798c8df2ec"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Upgrade database schema for v1.7 features:
    - Add OAuth support to users table
    - Create email_verifications table for email verification system
    """

    # ========================================================================
    # 1. Add OAuth columns to users table
    # ========================================================================

    # Add google_id column for Google OAuth (if not exists)
    # Using batch mode to handle cases where column might already exist
    try:
        op.add_column('users', sa.Column('google_id', sa.String(length=255), nullable=True))
        op.create_index('ix_users_google_id', 'users', ['google_id'], unique=True)
    except Exception as e:
        print(f"Note: google_id column may already exist: {e}")

    # Add email_verified_at column (if not exists)
    try:
        op.add_column('users', sa.Column('email_verified_at', sa.DateTime(timezone=True), nullable=True))
    except Exception as e:
        print(f"Note: email_verified_at column may already exist: {e}")

    # ========================================================================
    # 2. Create email_verifications table
    # ========================================================================

    op.create_table(
        'email_verifications',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('short_code', sa.String(length=6), nullable=False),
        sa.Column('long_token', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('verified_at', sa.DateTime(), nullable=True),
        sa.Column('is_used', sa.Boolean(), nullable=False, server_default='false'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes for email_verifications table
    op.create_index('ix_email_verifications_short_code', 'email_verifications', ['short_code'])
    op.create_index('ix_email_verifications_long_token', 'email_verifications', ['long_token'], unique=True)
    op.create_index('ix_email_verifications_user_id', 'email_verifications', ['user_id'])


def downgrade() -> None:
    """
    Downgrade database schema (remove v1.7 features)
    """

    # ========================================================================
    # 1. Drop email_verifications table
    # ========================================================================

    op.drop_index('ix_email_verifications_user_id', table_name='email_verifications')
    op.drop_index('ix_email_verifications_long_token', table_name='email_verifications')
    op.drop_index('ix_email_verifications_short_code', table_name='email_verifications')
    op.drop_table('email_verifications')

    # ========================================================================
    # 2. Remove OAuth columns from users table
    # ========================================================================

    try:
        op.drop_index('ix_users_google_id', table_name='users')
        op.drop_column('users', 'google_id')
    except Exception as e:
        print(f"Note: Could not drop google_id: {e}")

    try:
        op.drop_column('users', 'email_verified_at')
    except Exception as e:
        print(f"Note: Could not drop email_verified_at: {e}")
