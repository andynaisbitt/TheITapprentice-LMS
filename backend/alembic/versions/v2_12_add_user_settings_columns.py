"""Add user settings columns missing from production DB

Revision ID: v2_12_user_settings_cols
Revises: v2_11_registration_control
Create Date: 2026-02-27

Adds the privacy/notification/preference columns that were defined in the
User model but never had a migration. These were added when building the
User Settings page. The production DB is missing them, breaking login.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers
revision: str = "v2_12_user_settings_cols"
down_revision: str = "v2_11_registration_control"
branch_labels = None
depends_on = None


def _col_exists(table: str, column: str) -> bool:
    from sqlalchemy import inspect
    bind = op.get_bind()
    return column in [c["name"] for c in inspect(bind).get_columns(table)]


def upgrade() -> None:
    # Privacy settings
    if not _col_exists("users", "show_on_leaderboard"):
        op.add_column("users", sa.Column("show_on_leaderboard", sa.Boolean(), nullable=False, server_default="true"))
    if not _col_exists("users", "show_profile_public"):
        op.add_column("users", sa.Column("show_profile_public", sa.Boolean(), nullable=False, server_default="true"))
    if not _col_exists("users", "show_activity_public"):
        op.add_column("users", sa.Column("show_activity_public", sa.Boolean(), nullable=False, server_default="true"))

    # Learning preferences
    if not _col_exists("users", "default_difficulty"):
        op.add_column("users", sa.Column("default_difficulty", sa.String(20), nullable=False, server_default="medium"))

    # Notification preferences
    if not _col_exists("users", "notify_challenge_reminders"):
        op.add_column("users", sa.Column("notify_challenge_reminders", sa.Boolean(), nullable=False, server_default="true"))
    if not _col_exists("users", "notify_streak_reminders"):
        op.add_column("users", sa.Column("notify_streak_reminders", sa.Boolean(), nullable=False, server_default="true"))
    if not _col_exists("users", "notify_achievement_alerts"):
        op.add_column("users", sa.Column("notify_achievement_alerts", sa.Boolean(), nullable=False, server_default="true"))
    if not _col_exists("users", "notify_weekly_digest"):
        op.add_column("users", sa.Column("notify_weekly_digest", sa.Boolean(), nullable=False, server_default="true"))


def downgrade() -> None:
    op.drop_column("users", "notify_weekly_digest")
    op.drop_column("users", "notify_achievement_alerts")
    op.drop_column("users", "notify_streak_reminders")
    op.drop_column("users", "notify_challenge_reminders")
    op.drop_column("users", "default_difficulty")
    op.drop_column("users", "show_activity_public")
    op.drop_column("users", "show_profile_public")
    op.drop_column("users", "show_on_leaderboard")
