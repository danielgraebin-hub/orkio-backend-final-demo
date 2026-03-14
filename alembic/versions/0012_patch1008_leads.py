"""patch1008 leads

Revision ID: 0012_patch1008_leads
Revises: 0011_patch1007_file_uploader_fields
Create Date: 2026-02-12
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0012_patch1008_leads'
down_revision = '0011_patch1007_file_uploader_fields'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'leads',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('org_slug', sa.String(), nullable=False, index=True),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('company', sa.String(), nullable=False),
        sa.Column('role', sa.String(), nullable=True),
        sa.Column('segment', sa.String(), nullable=True),
        sa.Column('source', sa.String(), nullable=True),
        sa.Column('ua', sa.String(), nullable=True),
        sa.Column('created_at', sa.BigInteger(), nullable=False),
    )
    op.create_index('ix_leads_email', 'leads', ['email'], unique=False)


def downgrade():
    op.drop_index('ix_leads_email', table_name='leads')
    op.drop_table('leads')
