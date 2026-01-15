"""v1.9 Add typing game plugin tables

Revision ID: v1_9_typing_game
Revises: 231994203e37
Create Date: 2026-01-15

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'v1_9_typing_game'
down_revision: Union[str, None] = '231994203e37'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create MatchStatus enum
    match_status_enum = postgresql.ENUM(
        'WAITING', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED',
        name='typing_match_status',
        create_type=False
    )

    # Check if enum exists, if not create it
    op.execute("DO $$ BEGIN CREATE TYPE typing_match_status AS ENUM ('WAITING', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'); EXCEPTION WHEN duplicate_object THEN null; END $$;")

    # Create typing_word_lists table
    op.create_table(
        'typing_word_lists',
        sa.Column('id', sa.String(100), primary_key=True),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('description', sa.Text, nullable=True),
        sa.Column('difficulty', sa.String(20), nullable=False, index=True),
        sa.Column('theme', sa.String(50), nullable=False, index=True),
        sa.Column('words', sa.JSON, nullable=False),
        sa.Column('related_skills', sa.JSON, default=list),
        sa.Column('unlock_level', sa.Integer, default=1),
        sa.Column('is_active', sa.Boolean, default=True, nullable=False),
        sa.Column('is_featured', sa.Boolean, default=False, nullable=False),
        sa.Column('display_order', sa.Integer, default=0),
        sa.Column('times_played', sa.Integer, default=0),
        sa.Column('avg_wpm', sa.Float, default=0.0),
        sa.Column('avg_accuracy', sa.Float, default=0.0),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.now(), onupdate=sa.func.now()),
    )

    # Create typing_game_sessions table
    op.create_table(
        'typing_game_sessions',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('word_list_id', sa.String(100), sa.ForeignKey('typing_word_lists.id'), nullable=True),
        sa.Column('mode', sa.String(20), nullable=False),
        sa.Column('duration', sa.Integer, default=60),
        sa.Column('text_content', sa.Text, nullable=False),
        sa.Column('text_checksum', sa.String(64), nullable=True),
        sa.Column('word_count', sa.Integer, default=0),
        sa.Column('wpm', sa.Integer, nullable=True),
        sa.Column('raw_wpm', sa.Integer, nullable=True),
        sa.Column('accuracy', sa.Float, nullable=True),
        sa.Column('mistakes', sa.Integer, default=0),
        sa.Column('time_taken', sa.Float, nullable=True),
        sa.Column('characters_typed', sa.Integer, default=0),
        sa.Column('user_input', sa.Text, nullable=True),
        sa.Column('total_xp_earned', sa.Integer, default=0),
        sa.Column('is_personal_best_wpm', sa.Boolean, default=False),
        sa.Column('is_personal_best_accuracy', sa.Boolean, default=False),
        sa.Column('status', sa.String(20), default='in_progress'),
        sa.Column('is_completed', sa.Boolean, default=False),
        sa.Column('started_at', sa.DateTime, server_default=sa.func.now(), nullable=False),
        sa.Column('completed_at', sa.DateTime, nullable=True),
    )

    # Create user_typing_stats table
    op.create_table(
        'user_typing_stats',
        sa.Column('user_id', sa.Integer, sa.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('best_wpm', sa.Integer, default=0),
        sa.Column('best_wpm_word_list', sa.String(100), nullable=True),
        sa.Column('best_wpm_achieved_at', sa.DateTime, nullable=True),
        sa.Column('best_accuracy', sa.Float, default=0.0),
        sa.Column('best_accuracy_achieved_at', sa.DateTime, nullable=True),
        sa.Column('total_games_played', sa.Integer, default=0),
        sa.Column('total_games_completed', sa.Integer, default=0),
        sa.Column('total_words_typed', sa.Integer, default=0),
        sa.Column('total_characters_typed', sa.Integer, default=0),
        sa.Column('total_time_seconds', sa.Integer, default=0),
        sa.Column('avg_wpm', sa.Float, default=0.0),
        sa.Column('avg_accuracy', sa.Float, default=0.0),
        sa.Column('reached_50_wpm_at', sa.DateTime, nullable=True),
        sa.Column('reached_100_wpm_at', sa.DateTime, nullable=True),
        sa.Column('reached_150_wpm_at', sa.DateTime, nullable=True),
        sa.Column('first_game_at', sa.DateTime, nullable=True),
        sa.Column('last_game_at', sa.DateTime, nullable=True),
        sa.Column('current_streak_days', sa.Integer, default=0),
        sa.Column('longest_streak_days', sa.Integer, default=0),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.now(), onupdate=sa.func.now()),
    )

    # Create typing_pvp_matches table
    op.create_table(
        'typing_pvp_matches',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('player1_id', sa.Integer, sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('player2_id', sa.Integer, sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=True, index=True),
        sa.Column('status', postgresql.ENUM('WAITING', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED', name='typing_match_status', create_type=False), default='WAITING', nullable=False),
        sa.Column('player1_score', sa.Integer, default=0),
        sa.Column('player2_score', sa.Integer, default=0),
        sa.Column('player1_wpm', sa.Integer, default=0),
        sa.Column('player2_wpm', sa.Integer, default=0),
        sa.Column('player1_accuracy', sa.Float, default=0.0),
        sa.Column('player2_accuracy', sa.Float, default=0.0),
        sa.Column('winner_id', sa.Integer, sa.ForeignKey('users.id'), nullable=True),
        sa.Column('content', sa.Text, nullable=True),
        sa.Column('checksum', sa.String(64), nullable=True),
        sa.Column('difficulty', sa.String(20), default='medium'),
        sa.Column('word_count', sa.Integer, default=50),
        sa.Column('total_rounds', sa.Integer, default=3),
        sa.Column('current_round', sa.Integer, default=1),
        sa.Column('round_results', sa.JSON, nullable=True),
        sa.Column('skill_bracket', sa.String(20), nullable=True),
        sa.Column('player1_rating', sa.Integer, default=1000),
        sa.Column('player2_rating', sa.Integer, default=1000),
        sa.Column('rating_change', sa.Integer, default=0),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now(), nullable=False),
        sa.Column('started_at', sa.DateTime, nullable=True),
        sa.Column('completed_at', sa.DateTime, nullable=True),
    )

    # Create user_pvp_stats table
    op.create_table(
        'user_pvp_stats',
        sa.Column('user_id', sa.Integer, sa.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('current_rating', sa.Integer, default=1500),
        sa.Column('peak_rating', sa.Integer, default=1500),
        sa.Column('lowest_rating', sa.Integer, default=1500),
        sa.Column('rating_tier', sa.String(20), default='Intermediate'),
        sa.Column('total_matches', sa.Integer, default=0),
        sa.Column('wins', sa.Integer, default=0),
        sa.Column('losses', sa.Integer, default=0),
        sa.Column('ties', sa.Integer, default=0),
        sa.Column('win_rate', sa.Float, default=0.0),
        sa.Column('best_wpm', sa.Integer, default=0),
        sa.Column('avg_wpm', sa.Float, default=0.0),
        sa.Column('best_accuracy', sa.Float, default=0.0),
        sa.Column('avg_accuracy', sa.Float, default=0.0),
        sa.Column('current_win_streak', sa.Integer, default=0),
        sa.Column('longest_win_streak', sa.Integer, default=0),
        sa.Column('current_loss_streak', sa.Integer, default=0),
        sa.Column('last_match_at', sa.DateTime, nullable=True),
        sa.Column('first_match_at', sa.DateTime, nullable=True),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.now(), onupdate=sa.func.now()),
    )

    # Create typing_challenges table
    op.create_table(
        'typing_challenges',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('description', sa.Text, nullable=True),
        sa.Column('category', sa.String(50), nullable=False),
        sa.Column('difficulty', sa.String(20), nullable=False),
        sa.Column('text_content', sa.Text, nullable=False),
        sa.Column('expected_wpm', sa.Integer, default=40),
        sa.Column('time_limit', sa.Integer, default=60),
        sa.Column('tags', sa.JSON, nullable=True),
        sa.Column('related_skills', sa.JSON, nullable=True),
        sa.Column('is_active', sa.Boolean, default=True),
        sa.Column('round_order', sa.Integer, default=1),
        sa.Column('times_played', sa.Integer, default=0),
        sa.Column('average_completion_time', sa.Integer, default=0),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.now(), onupdate=sa.func.now()),
    )

    # Create typing_leaderboard table
    op.create_table(
        'typing_leaderboard',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('leaderboard_type', sa.String(50), nullable=False),
        sa.Column('period', sa.String(50), nullable=True),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('games_played', sa.Integer, default=0),
        sa.Column('best_wpm', sa.Float, default=0.0),
        sa.Column('avg_wpm', sa.Float, default=0.0),
        sa.Column('avg_accuracy', sa.Float, default=0.0),
        sa.Column('rank', sa.Integer, nullable=True),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.now(), onupdate=sa.func.now()),
    )

    # Insert seed data - Default word lists
    op.execute("""
        INSERT INTO typing_word_lists (id, name, description, difficulty, theme, words, related_skills, is_active, is_featured, display_order)
        VALUES
        ('quick-brown-fox', 'Quick Brown Fox', 'The classic typing practice sentence', 'easy', 'general',
         '["The", "quick", "brown", "fox", "jumps", "over", "the", "lazy", "dog"]',
         '["typing"]', true, true, 1),

        ('it-basics', 'IT Basics', 'Common IT terminology for beginners', 'easy', 'general',
         '["computer", "network", "server", "database", "software", "hardware", "keyboard", "mouse", "screen", "monitor", "printer", "router", "modem", "cable", "wireless", "internet", "email", "browser", "website", "download", "upload", "file", "folder", "desktop", "laptop"]',
         '["it-fundamentals"]', true, false, 2),

        ('python-keywords', 'Python Keywords', 'Python programming keywords', 'medium', 'code',
         '["def", "class", "return", "import", "from", "if", "else", "elif", "for", "while", "try", "except", "finally", "with", "as", "lambda", "yield", "pass", "break", "continue", "True", "False", "None", "and", "or", "not", "in", "is"]',
         '["python", "programming"]', true, false, 3),

        ('linux-commands', 'Linux Commands', 'Essential Linux terminal commands', 'medium', 'commands',
         '["ls", "cd", "pwd", "mkdir", "rm", "cp", "mv", "cat", "grep", "find", "chmod", "chown", "sudo", "apt", "yum", "dnf", "ssh", "scp", "tar", "gzip", "curl", "wget", "ps", "kill", "top"]',
         '["linux", "devops"]', true, false, 4),

        ('git-commands', 'Git Commands', 'Version control with Git', 'medium', 'commands',
         '["git", "init", "clone", "add", "commit", "push", "pull", "fetch", "merge", "rebase", "branch", "checkout", "status", "log", "diff", "stash", "reset", "remote", "origin", "main", "master"]',
         '["git", "devops"]', true, false, 5),

        ('docker-commands', 'Docker Commands', 'Container management with Docker', 'hard', 'commands',
         '["docker", "build", "run", "pull", "push", "images", "ps", "stop", "start", "rm", "rmi", "exec", "logs", "compose", "volume", "network", "container", "dockerfile", "registry"]',
         '["docker", "devops"]', true, false, 6),

        ('sql-keywords', 'SQL Keywords', 'Database query language', 'medium', 'code',
         '["SELECT", "FROM", "WHERE", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER", "TABLE", "INDEX", "JOIN", "LEFT", "RIGHT", "INNER", "OUTER", "GROUP", "BY", "ORDER", "HAVING", "LIMIT", "OFFSET", "NULL", "PRIMARY", "KEY", "FOREIGN"]',
         '["sql", "databases"]', true, false, 7),

        ('security-terms', 'Security Terms', 'Cybersecurity vocabulary', 'hard', 'security',
         '["encryption", "firewall", "malware", "phishing", "ransomware", "vulnerability", "exploit", "authentication", "authorization", "certificate", "hash", "salt", "token", "session", "XSS", "CSRF", "injection", "penetration", "audit", "compliance"]',
         '["security"]', true, false, 8)
    """)


def downgrade() -> None:
    op.drop_table('typing_leaderboard')
    op.drop_table('typing_challenges')
    op.drop_table('user_pvp_stats')
    op.drop_table('typing_pvp_matches')
    op.drop_table('user_typing_stats')
    op.drop_table('typing_game_sessions')
    op.drop_table('typing_word_lists')
    op.execute("DROP TYPE IF EXISTS typing_match_status")
