"""patch1007: file uploader provenance fields

Revision ID: 0011_patch1007
Revises: 0010_patch1006
Create Date: 2026-02-12
"""

from alembic import op
import sqlalchemy as sa


revision = "0011_patch1007"
down_revision = "0010_patch1006"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("files") as batch:
        batch.add_column(sa.Column("uploader_id", sa.String(), nullable=True))
        batch.add_column(sa.Column("uploader_name", sa.String(), nullable=True))
        batch.add_column(sa.Column("uploader_email", sa.String(), nullable=True))


def downgrade():
    with op.batch_alter_table("files") as batch:
        batch.drop_column("uploader_email")
        batch.drop_column("uploader_name")
        batch.drop_column("uploader_id")
