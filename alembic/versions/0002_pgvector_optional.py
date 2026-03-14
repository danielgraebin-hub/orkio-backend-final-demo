"""pgvector optional (best-effort, no-op)

Revision ID: 0002_pgvector_optional
Revises: 0001_init
Create Date: 2026-01-15
"""

from alembic import op

revision = "0002_pgvector_optional"
down_revision = "0001_init"
branch_labels = None
depends_on = None

def upgrade():
    # Intentionally a NO-OP in Phase2 baseline.
    # pgvector is optional and MUST NOT block deploy/migrations on Railway.
    return

def downgrade():
    return
