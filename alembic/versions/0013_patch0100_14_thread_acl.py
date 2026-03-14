"""patch0100_14 thread ACL (multiusuários)

Revision ID: 0013_patch0100_14_thread_acl
Revises: 0012_patch1008_leads
Create Date: 2026-02-18
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text as sa_text

revision = '0013_patch0100_14_thread_acl'
down_revision = '0012_patch1008_leads'
branch_labels = None
depends_on = None


def upgrade():
    # 1) Create thread_members table
    op.create_table(
        'thread_members',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('org_slug', sa.String(), nullable=False),
        sa.Column('thread_id', sa.String(), nullable=False),
        sa.Column('user_id', sa.String(), nullable=False),
        sa.Column('role', sa.String(), nullable=False),
        sa.Column('created_at', sa.BigInteger(), nullable=False),
        sa.UniqueConstraint('thread_id', 'user_id', name='uq_thread_members_thread_user'),
        sa.CheckConstraint("role IN ('owner','admin','member','viewer')", name='ck_thread_members_role'),
    )
    op.create_index('ix_thread_members_org_slug', 'thread_members', ['org_slug'])
    op.create_index('ix_thread_members_thread_id', 'thread_members', ['thread_id'])
    op.create_index('ix_thread_members_user_id', 'thread_members', ['user_id'])

    # 2) Seed existing threads: infer creator from first message per thread
    conn = op.get_bind()
    try:
        rows = conn.execute(sa_text("""
            SELECT t.id AS thread_id, t.org_slug,
                   (SELECT m.user_id FROM messages m
                    WHERE m.thread_id = t.id AND m.user_id IS NOT NULL
                    ORDER BY m.created_at ASC LIMIT 1) AS creator_id
            FROM threads t
        """)).fetchall()

        import uuid, time
        now_ms = int(time.time() * 1000)

        for row in rows:
            tid = row[0]
            org = row[1]
            creator = row[2]
            if not creator:
                continue
            # Idempotency: skip if already exists
            existing = conn.execute(sa_text(
                "SELECT 1 FROM thread_members WHERE thread_id = :tid AND user_id = :uid LIMIT 1"
            ), {"tid": tid, "uid": creator}).fetchone()
            if existing:
                continue
            mid = str(uuid.uuid4())
            conn.execute(sa_text(
                "INSERT INTO thread_members (id, org_slug, thread_id, user_id, role, created_at) "
                "VALUES (:id, :org, :tid, :uid, 'owner', :ts)"
            ), {"id": mid, "org": org, "tid": tid, "uid": creator, "ts": now_ms})
    except Exception as e:
        # Best-effort seed; don't block migration
        import logging
        logging.getLogger("alembic").warning("THREAD_ACL_SEED_PARTIAL: %s", str(e))


def downgrade():
    op.drop_index('ix_thread_members_user_id', table_name='thread_members')
    op.drop_index('ix_thread_members_thread_id', table_name='thread_members')
    op.drop_index('ix_thread_members_org_slug', table_name='thread_members')
    op.drop_table('thread_members')
