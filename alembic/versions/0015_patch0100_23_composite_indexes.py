"""PATCH0100_23 — Composite indexes for Message and CostEvent

Revision ID: 0015
Revises: 0014
Create Date: 2026-02-20

Adds:
  - ix_messages_org_thread    ON messages(org_slug, thread_id)
  - ix_cost_events_org_created ON cost_events(org_slug, created_at)

These are performance-critical for list_messages and admin_costs queries
at scale. Safe to apply on live DB (CREATE INDEX CONCURRENTLY on Postgres).
"""
from alembic import op
import sqlalchemy as sa

revision = '0015'
down_revision = '0014'
branch_labels = None
depends_on = None


def upgrade():
    # Use CONCURRENTLY to avoid locking the table on large deployments
    # Note: CONCURRENTLY cannot run inside a transaction, so we use
    # op.execute with connection.execution_options
    with op.get_context().autocommit_block():
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_messages_org_thread "
            "ON messages (org_slug, thread_id)"
        )
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_cost_events_org_created "
            "ON cost_events (org_slug, created_at)"
        )


def downgrade():
    op.execute("DROP INDEX IF EXISTS ix_messages_org_thread")
    op.execute("DROP INDEX IF EXISTS ix_cost_events_org_created")
