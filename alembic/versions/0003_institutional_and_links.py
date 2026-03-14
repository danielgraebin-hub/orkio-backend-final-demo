"""institutional files + agent links safety

Revision ID: 0003_institutional_and_links
Revises: 0002_pgvector_optional
Create Date: 2026-01-27
"""

from alembic import op

revision = "0003_institutional_and_links"
down_revision = "0002_pgvector_optional"
branch_labels = None
depends_on = None

def upgrade():
    # Add column to mark institutional (global) documents.
    # Use IF NOT EXISTS to avoid blocking existing installations.
    op.execute("ALTER TABLE IF EXISTS files ADD COLUMN IF NOT EXISTS is_institutional BOOLEAN NOT NULL DEFAULT FALSE;")

    # Ensure agent_links table exists (best-effort). Some environments may already have it.
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS agent_links (
            id TEXT PRIMARY KEY,
            org_slug TEXT NOT NULL,
            source_agent_id TEXT NOT NULL,
            target_agent_id TEXT NOT NULL,
            mode TEXT NOT NULL DEFAULT 'consult',
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_at BIGINT NOT NULL
        );
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_agent_links_org ON agent_links (org_slug);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_agent_links_source ON agent_links (source_agent_id);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_agent_links_target ON agent_links (target_agent_id);")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_links_org_src_tgt ON agent_links (org_slug, source_agent_id, target_agent_id);")

    # Ensure agent_knowledge table exists (best-effort) because RAG depends on it.
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS agent_knowledge (
            id TEXT PRIMARY KEY,
            org_slug TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            file_id TEXT NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_at BIGINT NOT NULL
        );
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_agent_knowledge_org ON agent_knowledge (org_slug);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_agent_knowledge_agent ON agent_knowledge (agent_id);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_agent_knowledge_file ON agent_knowledge (file_id);")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_knowledge_org_agent_file ON agent_knowledge (org_slug, agent_id, file_id);")

def downgrade():
    # Keep downgrade conservative (do not drop tables in prod).
    return
