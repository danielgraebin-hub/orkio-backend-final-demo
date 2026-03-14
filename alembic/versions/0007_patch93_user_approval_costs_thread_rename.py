"""patch93: user approval + cost events + message user fields

Revision ID: 0007_patch93
Revises: 0006_patch85_intent_and_message_agent
Create Date: 2026-02-05
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0007_patch93"
down_revision = "0006_patch85_intent_and_message_agent"
branch_labels = None
depends_on = None


def upgrade():
    # users.approved_at (nullable). Keep existing users approved by default.
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("approved_at", sa.BigInteger(), nullable=True))
    op.execute("UPDATE users SET approved_at = created_at WHERE approved_at IS NULL")

    # messages.user_id + messages.user_name
    with op.batch_alter_table("messages") as batch:
        batch.add_column(sa.Column("user_id", sa.String(), nullable=True))
        batch.add_column(sa.Column("user_name", sa.String(), nullable=True))

    # cost_events
    op.create_table(
        "cost_events",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_slug", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=True),
        sa.Column("thread_id", sa.String(), nullable=True),
        sa.Column("message_id", sa.String(), nullable=True),
        sa.Column("agent_id", sa.String(), nullable=True),
        sa.Column("model", sa.String(), nullable=True),
        sa.Column("prompt_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("completion_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
    )
    op.create_index("ix_cost_events_org_slug", "cost_events", ["org_slug"])
    op.create_index("ix_cost_events_thread_id", "cost_events", ["thread_id"])
    op.create_index("ix_cost_events_message_id", "cost_events", ["message_id"])
    op.create_index("ix_cost_events_agent_id", "cost_events", ["agent_id"])


def downgrade():
    op.drop_index("ix_cost_events_agent_id", table_name="cost_events")
    op.drop_index("ix_cost_events_message_id", table_name="cost_events")
    op.drop_index("ix_cost_events_thread_id", table_name="cost_events")
    op.drop_index("ix_cost_events_org_slug", table_name="cost_events")
    op.drop_table("cost_events")

    with op.batch_alter_table("messages") as batch:
        batch.drop_column("user_name")
        batch.drop_column("user_id")

    with op.batch_alter_table("users") as batch:
        batch.drop_column("approved_at")
