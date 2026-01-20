"""add_missing_security_columns_to_users

Revision ID: 066a6f56bd8d
Revises: 8301d822b784
Create Date: 2026-01-15 08:11:13.617073

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


# revision identifiers, used by Alembic.
revision: str = "066a6f56bd8d"
down_revision: Union[str, None] = "8301d822b784"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def column_exists(table_name: str, column_name: str) -> bool:
    """Check if a column exists in a table"""
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [col['name'] for col in inspector.get_columns(table_name)]
    return column_name in columns


def index_exists(table_name: str, index_name: str) -> bool:
    """Check if an index exists on a table"""
    bind = op.get_bind()
    inspector = inspect(bind)
    indexes = [idx['name'] for idx in inspector.get_indexes(table_name)]
    return index_name in indexes


def upgrade() -> None:
    """Add missing security columns to users table (idempotent)"""

    # Add email_verified_at column
    if not column_exists("users", "email_verified_at"):
        op.add_column(
            "users",
            sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
        )

    # Add MFA enabled flag
    if not column_exists("users", "mfa_enabled"):
        op.add_column(
            "users", sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default="false")
        )

    if not index_exists("users", "ix_users_mfa_enabled"):
        op.create_index("ix_users_mfa_enabled", "users", ["mfa_enabled"])

    # Add failed login tracking
    if not column_exists("users", "failed_login_attempts"):
        op.add_column(
            "users", sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0")
        )

    # Add account lockout
    if not column_exists("users", "locked_until"):
        op.add_column(
            "users", sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True)
        )


def downgrade() -> None:
    """Remove security columns from users table"""
    if column_exists("users", "locked_until"):
        op.drop_column("users", "locked_until")
    if column_exists("users", "failed_login_attempts"):
        op.drop_column("users", "failed_login_attempts")
    if index_exists("users", "ix_users_mfa_enabled"):
        op.drop_index("ix_users_mfa_enabled", table_name="users")
    if column_exists("users", "mfa_enabled"):
        op.drop_column("users", "mfa_enabled")
    if column_exists("users", "email_verified_at"):
        op.drop_column("users", "email_verified_at")
