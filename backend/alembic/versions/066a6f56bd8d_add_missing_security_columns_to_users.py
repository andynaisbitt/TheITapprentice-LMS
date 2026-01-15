"""add_missing_security_columns_to_users

Revision ID: 066a6f56bd8d
Revises: 8301d822b784
Create Date: 2026-01-15 08:11:13.617073

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "066a6f56bd8d"
down_revision: Union[str, None] = "8301d822b784"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add missing security columns to users table"""
    # Add email_verified_at column
    op.add_column(
        "users",
        sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
    )

    # Add MFA enabled flag
    op.add_column(
        "users", sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default="false")
    )
    op.create_index("ix_users_mfa_enabled", "users", ["mfa_enabled"])

    # Add failed login tracking
    op.add_column(
        "users", sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0")
    )

    # Add account lockout
    op.add_column(
        "users", sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    """Remove security columns from users table"""
    op.drop_column("users", "locked_until")
    op.drop_column("users", "failed_login_attempts")
    op.drop_index("ix_users_mfa_enabled", table_name="users")
    op.drop_column("users", "mfa_enabled")
    op.drop_column("users", "email_verified_at")
