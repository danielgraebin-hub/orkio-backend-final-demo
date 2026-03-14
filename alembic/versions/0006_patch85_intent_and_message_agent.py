"""patch85: upload intent + message agent identity

Revision ID: 0006_patch85_intent_and_message_agent
Revises: 0003_institutional_and_links
Create Date: 2026-01-28
"""

from alembic import op

revision = "0006_patch85_intent_and_message_agent"
down_revision = "0003_institutional_and_links"
branch_labels = None
depends_on = None

def upgrade():
    # Files: preserve original filename, origin, and scope
    op.execute("ALTER TABLE IF EXISTS files ADD COLUMN IF NOT EXISTS original_filename TEXT;")
    op.execute("ALTER TABLE IF EXISTS files ADD COLUMN IF NOT EXISTS origin TEXT NOT NULL DEFAULT 'unknown';")
    op.execute("ALTER TABLE IF EXISTS files ADD COLUMN IF NOT EXISTS scope_thread_id TEXT;")
    op.execute("ALTER TABLE IF EXISTS files ADD COLUMN IF NOT EXISTS scope_agent_id TEXT;")

    # Messages: store agent identity for auditability
    op.execute("ALTER TABLE IF EXISTS messages ADD COLUMN IF NOT EXISTS agent_id TEXT;")
    op.execute("ALTER TABLE IF EXISTS messages ADD COLUMN IF NOT EXISTS agent_name TEXT;")

    op.execute("CREATE INDEX IF NOT EXISTS ix_files_origin ON files (origin);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_files_scope_thread ON files (scope_thread_id);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_files_scope_agent ON files (scope_agent_id);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_messages_agent_id ON messages (agent_id);")

def downgrade():
    return
