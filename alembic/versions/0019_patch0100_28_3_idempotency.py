"""PATCH0100_28.3 — Idempotency keys for chat + realtime batch

Adds:
- messages.client_message_id + unique index (org_slug, thread_id, client_message_id)
- realtime_events.client_event_id + unique index (org_slug, session_id, client_event_id)
"""

from alembic import op
import sqlalchemy as sa

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade():
    # messages: client_message_id
    with op.batch_alter_table("messages") as batch:
        batch.add_column(sa.Column("client_message_id", sa.String(), nullable=True))
    op.create_index(
        "ux_messages_org_thread_client_msg",
        "messages",
        ["org_slug", "thread_id", "client_message_id"],
        unique=True,
    )

    # realtime_events: client_event_id
    with op.batch_alter_table("realtime_events") as batch:
        batch.add_column(sa.Column("client_event_id", sa.String(), nullable=True))
    op.create_index(
        "ux_realtime_events_org_sess_client_eid",
        "realtime_events",
        ["org_slug", "session_id", "client_event_id"],
        unique=True,
    )


def downgrade():
    op.drop_index("ux_realtime_events_org_sess_client_eid", table_name="realtime_events")
    with op.batch_alter_table("realtime_events") as batch:
        batch.drop_column("client_event_id")

    op.drop_index("ux_messages_org_thread_client_msg", table_name="messages")
    with op.batch_alter_table("messages") as batch:
        batch.drop_column("client_message_id")
