"""init phase2 baseline

Revision ID: 0001_init
Revises:
Create Date: 2026-01-15
"""

from alembic import op
import sqlalchemy as sa

revision = "0001_init"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "users",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_slug", sa.String(), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False, server_default="user"),
        sa.Column("salt", sa.String(), nullable=False),
        sa.Column("pw_hash", sa.String(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.UniqueConstraint("org_slug", "email", name="uq_user_org_email"),
    )
    op.create_index("ix_users_org", "users", ["org_slug"])
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "threads",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_slug", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
    )
    op.create_index("ix_threads_org", "threads", ["org_slug"])

    op.create_table(
        "messages",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_slug", sa.String(), nullable=False),
        sa.Column("thread_id", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
    )
    op.create_index("ix_messages_thread_org", "messages", ["org_slug", "thread_id"])

    op.create_table(
        "files",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_slug", sa.String(), nullable=False),
        sa.Column("thread_id", sa.String(), nullable=True),
        sa.Column("filename", sa.String(), nullable=False),
        sa.Column("mime_type", sa.String(), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("content", sa.LargeBinary(), nullable=True),
        sa.Column("extraction_failed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
    )
    op.create_index("ix_files_org", "files", ["org_slug"])

    op.create_table(
        "file_texts",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_slug", sa.String(), nullable=False),
        sa.Column("file_id", sa.String(), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("extracted_chars", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
    )
    op.create_index("ix_file_texts_org", "file_texts", ["org_slug"])
    op.create_index("ix_file_texts_file", "file_texts", ["file_id"])

    op.create_table(
        "file_chunks",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_slug", sa.String(), nullable=False),
        sa.Column("file_id", sa.String(), nullable=False),
        sa.Column("idx", sa.Integer(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
    )
    op.create_index("ix_file_chunks_org", "file_chunks", ["org_slug"])
    op.create_index("ix_file_chunks_file", "file_chunks", ["file_id"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_slug", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=True),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("meta", sa.Text(), nullable=True),
        sa.Column("request_id", sa.String(), nullable=True),
        sa.Column("path", sa.String(), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
    )
    op.create_index("ix_audit_org", "audit_logs", ["org_slug"])

def downgrade():
    op.drop_index("ix_audit_org", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index("ix_file_chunks_file", table_name="file_chunks")
    op.drop_index("ix_file_chunks_org", table_name="file_chunks")
    op.drop_table("file_chunks")
    op.drop_index("ix_file_texts_file", table_name="file_texts")
    op.drop_index("ix_file_texts_org", table_name="file_texts")
    op.drop_table("file_texts")
    op.drop_index("ix_files_org", table_name="files")
    op.drop_table("files")
    op.drop_index("ix_messages_thread_org", table_name="messages")
    op.drop_table("messages")
    op.drop_index("ix_threads_org", table_name="threads")
    op.drop_table("threads")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_index("ix_users_org", table_name="users")
    op.drop_table("users")
