"""patch94: file requests for institutional uploads

Revision ID: 0008_patch94
Revises: 0007_patch93
Create Date: 2026-02-05
"""

from alembic import op
import sqlalchemy as sa

revision = "0008_patch94"
down_revision = "0007_patch93"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "file_requests",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_slug", sa.String(), nullable=False),
        sa.Column("file_id", sa.String(), nullable=False),
        sa.Column("requested_by_user_id", sa.String(), nullable=True),
        sa.Column("requested_by_user_name", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("resolved_at", sa.BigInteger(), nullable=True),
        sa.Column("resolved_by_admin_id", sa.String(), nullable=True),
    )
    op.create_index("ix_file_requests_org_slug", "file_requests", ["org_slug"])
    op.create_index("ix_file_requests_file_id", "file_requests", ["file_id"])
    op.create_index("ix_file_requests_status", "file_requests", ["status"])


def downgrade():
    op.drop_index("ix_file_requests_status", table_name="file_requests")
    op.drop_index("ix_file_requests_file_id", table_name="file_requests")
    op.drop_index("ix_file_requests_org_slug", table_name="file_requests")
    op.drop_table("file_requests")
