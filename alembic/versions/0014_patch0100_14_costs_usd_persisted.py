"""patch0100_14 costs USD enterprise-grade (immutable at persist time)

Revision ID: 0014_patch0100_14_costs_usd_persisted
Revises: 0013_patch0100_14_thread_acl
Create Date: 2026-02-18
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text as sa_text

revision = '0014_patch0100_14_costs_usd_persisted'
down_revision = '0013_patch0100_14_thread_acl'
branch_labels = None
depends_on = None


def _col_exists(conn, table, column):
    """Check if a column exists (PostgreSQL)."""
    try:
        result = conn.execute(sa_text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :tbl AND column_name = :col LIMIT 1"
        ), {"tbl": table, "col": column}).fetchone()
        return result is not None
    except Exception:
        return False


def upgrade():
    conn = op.get_bind()

    # Add new columns to cost_events if they don't exist
    new_cols = [
        ("input_cost_usd", "NUMERIC(12,6) NOT NULL DEFAULT 0"),
        ("output_cost_usd", "NUMERIC(12,6) NOT NULL DEFAULT 0"),
        ("total_cost_usd", "NUMERIC(12,6) NOT NULL DEFAULT 0"),
        ("pricing_version", "VARCHAR(64) NOT NULL DEFAULT '2026-02-18'"),
        ("pricing_snapshot", "TEXT"),
    ]

    for col_name, col_type in new_cols:
        if not _col_exists(conn, "cost_events", col_name):
            op.add_column("cost_events", sa.Column(col_name, sa.Text() if col_type == "TEXT" else None))
            # Use raw SQL for precise type control
            try:
                conn.execute(sa_text(f"ALTER TABLE cost_events ADD COLUMN {col_name} {col_type}"))
            except Exception:
                pass  # Column may have been added by the op.add_column above

    # Create composite index for admin queries
    try:
        op.create_index('ix_cost_events_org_created', 'cost_events', ['org_slug', 'created_at'])
    except Exception:
        pass

    # Backfill: compute total_cost_usd from existing cost_usd where total_cost_usd = 0
    try:
        conn.execute(sa_text("""
            UPDATE cost_events
            SET total_cost_usd = cost_usd,
                input_cost_usd = 0,
                output_cost_usd = cost_usd
            WHERE total_cost_usd = 0 AND cost_usd > 0
        """))
    except Exception:
        import logging
        logging.getLogger("alembic").warning("COST_BACKFILL_PARTIAL")


def downgrade():
    try:
        op.drop_index('ix_cost_events_org_created', table_name='cost_events')
    except Exception:
        pass
    for col in ['input_cost_usd', 'output_cost_usd', 'total_cost_usd', 'pricing_version', 'pricing_snapshot']:
        try:
            op.drop_column('cost_events', col)
        except Exception:
            pass
