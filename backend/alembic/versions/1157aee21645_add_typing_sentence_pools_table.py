"""Add typing_sentence_pools table

Revision ID: 1157aee21645
Revises: v2_6_lms_homepage
Create Date: 2026-01-21

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '1157aee21645'
down_revision = 'v2_6_lms_homepage'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('typing_sentence_pools',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('difficulty', sa.String(length=20), nullable=False),
        sa.Column('category', sa.String(length=50), nullable=False),
        sa.Column('sentences', sa.JSON(), nullable=False),
        sa.Column('min_length', sa.Integer(), nullable=True),
        sa.Column('max_length', sa.Integer(), nullable=True),
        sa.Column('avg_word_count', sa.Float(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_featured', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('display_order', sa.Integer(), nullable=True),
        sa.Column('round_suitable', sa.JSON(), nullable=True),
        sa.Column('difficulty_weight', sa.Float(), nullable=True),
        sa.Column('times_used', sa.Integer(), nullable=True),
        sa.Column('avg_wpm', sa.Float(), nullable=True),
        sa.Column('avg_accuracy', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_typing_sentence_pools_category', 'typing_sentence_pools', ['category'])
    op.create_index('ix_typing_sentence_pools_difficulty', 'typing_sentence_pools', ['difficulty'])

    op.create_table('certificates',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('course_id', sa.Integer(), nullable=False),
        sa.Column('enrollment_id', sa.Integer(), nullable=False),
        sa.Column('verification_code', sa.String(length=50), nullable=False),
        sa.Column('issued_at', sa.DateTime(), nullable=False),
        sa.Column('course_title', sa.String(length=255), nullable=False),
        sa.Column('user_name', sa.String(length=255), nullable=False),
        sa.Column('instructor_name', sa.String(length=255), nullable=True),
        sa.Column('skills_acquired', sa.JSON(), nullable=True),
        sa.Column('completion_date', sa.DateTime(), nullable=True),
        sa.Column('grade', sa.String(length=10), nullable=True),
        sa.Column('certificate_type', sa.String(length=50), nullable=True),
        sa.ForeignKeyConstraint(['course_id'], ['courses.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['enrollment_id'], ['course_enrollments.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_certificates_course_id', 'certificates', ['course_id'])
    op.create_index('ix_certificates_enrollment_id', 'certificates', ['enrollment_id'])
    op.create_index('ix_certificates_user_id', 'certificates', ['user_id'])
    op.create_index('ix_certificates_verification_code', 'certificates', ['verification_code'], unique=True)


def downgrade() -> None:
    op.drop_table('certificates')
    op.drop_table('typing_sentence_pools')
