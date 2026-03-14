"""PATCH0100_25S — Realtime sessions + events (auditability for WebRTC voice)

Revision ID: 0016
Revises: 0015
Create Date: 2026-02-26

Adds:
  - realtime_sessions
  - realtime_events
  - indexes for org_slug/session_id/thread_id
"""
from alembic import op
import sqlalchemy as sa

revision = '0016'
down_revision = '0015'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'realtime_sessions',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('org_slug', sa.String(), nullable=False, index=True),
        sa.Column('thread_id', sa.String(), nullable=False, index=True),
        sa.Column('agent_id', sa.String(), nullable=True),
        sa.Column('agent_name', sa.String(), nullable=True),
        sa.Column('user_id', sa.String(), nullable=True),
        sa.Column('user_name', sa.String(), nullable=True),
        sa.Column('model', sa.String(), nullable=True),
        sa.Column('voice', sa.String(), nullable=True),
        sa.Column('started_at', sa.BigInteger(), nullable=False),
        sa.Column('ended_at', sa.BigInteger(), nullable=True),
        sa.Column('meta', sa.Text(), nullable=True),
    )

    op.create_table(
        'realtime_events',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('org_slug', sa.String(), nullable=False, index=True),
        sa.Column('session_id', sa.String(), nullable=False, index=True),
        sa.Column('thread_id', sa.String(), nullable=False, index=True),
        sa.Column('role', sa.String(), nullable=False),
        sa.Column('agent_id', sa.String(), nullable=True),
        sa.Column('agent_name', sa.String(), nullable=True),
        sa.Column('event_type', sa.String(), nullable=False),
        sa.Column('content', sa.Text(), nullable=True),
        sa.Column('created_at', sa.BigInteger(), nullable=False),
        sa.Column('meta', sa.Text(), nullable=True),
    )

    # Composite indexes for common queries
    op.create_index('ix_rt_events_org_session', 'realtime_events', ['org_slug', 'session_id'])
    op.create_index('ix_rt_events_org_thread', 'realtime_events', ['org_slug', 'thread_id'])
    op.create_index('ix_rt_sessions_org_thread', 'realtime_sessions', ['org_slug', 'thread_id'])


def downgrade():
    op.drop_index('ix_rt_sessions_org_thread', table_name='realtime_sessions')
    op.drop_index('ix_rt_events_org_thread', table_name='realtime_events')
    op.drop_index('ix_rt_events_org_session', table_name='realtime_events')
    op.drop_table('realtime_events')
    op.drop_table('realtime_sessions')
