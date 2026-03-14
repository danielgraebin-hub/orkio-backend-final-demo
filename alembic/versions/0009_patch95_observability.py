"""patch95: audit+costs observability hardening

Revision ID: 0009_patch95
Revises: 0008_patch94
Create Date: 2026-02-07
"""

from alembic import op
import sqlalchemy as sa

revision = "0009_patch95"
down_revision = "0008_patch94"
branch_labels = None
depends_on = None


def upgrade():
    # ---- cost_events: add monetary + provider + flags ----
    with op.batch_alter_table("cost_events") as batch:
        batch.add_column(sa.Column("provider", sa.String(), nullable=True))
        batch.add_column(sa.Column("cost_usd", sa.Numeric(12, 6), nullable=False, server_default="0"))
        batch.add_column(sa.Column("usage_missing", sa.Boolean(), nullable=False, server_default=sa.text("false")))
        batch.add_column(sa.Column("metadata", sa.Text(), nullable=True))

    # indexes for faster dashboards
    op.create_index("ix_cost_events_user_id", "cost_events", ["user_id"])
    op.create_index("ix_cost_events_model", "cost_events", ["model"])
    op.create_index("ix_cost_events_created_at", "cost_events", ["created_at"])

    # ---- audit_logs: strengthen indexes ----
    # audit_logs already exists since init; add indexes if missing
    op.create_index("ix_audit_logs_org_created", "audit_logs", ["org_slug", "created_at"])
    op.create_index("ix_audit_logs_user_created", "audit_logs", ["user_id", "created_at"])
    op.create_index("ix_audit_logs_action_created", "audit_logs", ["action", "created_at"])


def downgrade():
    # drop indexes (best effort)
    for ix in ["ix_audit_logs_action_created","ix_audit_logs_user_created","ix_audit_logs_org_created",
               "ix_cost_events_created_at","ix_cost_events_model","ix_cost_events_user_id"]:
        try:
            op.drop_index(ix, table_name=("audit_logs" if ix.startswith("ix_audit_logs") else "cost_events"))
        except Exception:
            pass

    with op.batch_alter_table("cost_events") as batch:
        for col in ["metadata","usage_missing","cost_usd","provider"]:
            try:
                batch.drop_column(col)
            except Exception:
                pass
