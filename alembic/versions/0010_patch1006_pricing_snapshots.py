"""patch1006: pricing snapshots for auto USD calculation

Revision ID: 0010_patch1006
Revises: 0009_patch95
Create Date: 2026-02-11
"""

from alembic import op
import sqlalchemy as sa

revision = "0010_patch1006"
down_revision = "0009_patch95"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "pricing_snapshots",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_slug", sa.String(), nullable=False, index=True),
        sa.Column("provider", sa.String(), nullable=False, index=True),
        sa.Column("model", sa.String(), nullable=False, index=True),
        sa.Column("input_per_1m", sa.Numeric(10, 6), nullable=False, server_default="0"),
        sa.Column("output_per_1m", sa.Numeric(10, 6), nullable=False, server_default="0"),
        sa.Column("currency", sa.String(), nullable=False, server_default="USD"),
        sa.Column("source", sa.String(), nullable=True),
        sa.Column("fetched_at", sa.BigInteger(), nullable=False),
        sa.Column("effective_at", sa.BigInteger(), nullable=False),
    )


def downgrade():
    op.drop_table("pricing_snapshots")
