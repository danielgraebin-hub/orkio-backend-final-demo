"""PATCH0100_28 — Summit Hardening + Legal Compliance

New tables: signup_codes, otp_codes, user_sessions, usage_events,
            feature_flags, contact_requests, marketing_consents, terms_acceptances
New columns on users: signup_code_label, signup_source, usage_tier,
                      terms_accepted_at, terms_version, marketing_consent
"""

from alembic import op
import sqlalchemy as sa

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade():
    # ── New columns on users ──────────────────────────────────────────
    op.add_column("users", sa.Column("signup_code_label", sa.String(), nullable=True))
    op.add_column("users", sa.Column("signup_source", sa.String(), nullable=True))
    op.add_column("users", sa.Column("usage_tier", sa.String(), nullable=True, server_default="summit_standard"))
    op.add_column("users", sa.Column("terms_accepted_at", sa.BigInteger(), nullable=True))
    op.add_column("users", sa.Column("terms_version", sa.String(), nullable=True))
    op.add_column("users", sa.Column("marketing_consent", sa.Boolean(), nullable=True, server_default=sa.text("false")))

    # ── signup_codes ──────────────────────────────────────────────────
    op.create_table(
        "signup_codes",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_slug", sa.String(), nullable=False, index=True),
        sa.Column("code_hash", sa.String(), nullable=False),
        sa.Column("label", sa.String(), nullable=False),           # human-readable label
        sa.Column("source", sa.String(), nullable=False),          # pitch | invite
        sa.Column("expires_at", sa.BigInteger(), nullable=False),  # UTC ms
        sa.Column("max_uses", sa.Integer(), nullable=False, server_default="500"),
        sa.Column("used_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=True),
    )

    # ── otp_codes ─────────────────────────────────────────────────────
    op.create_table(
        "otp_codes",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), nullable=False, index=True),
        sa.Column("code_hash", sa.String(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),  # UTC ms
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("verified", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
    )

    # ── user_sessions ─────────────────────────────────────────────────
    op.create_table(
        "user_sessions",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), nullable=False, index=True),
        sa.Column("org_slug", sa.String(), nullable=False, index=True),
        sa.Column("login_at", sa.BigInteger(), nullable=False),
        sa.Column("logout_at", sa.BigInteger(), nullable=True),
        sa.Column("last_seen_at", sa.BigInteger(), nullable=False),
        sa.Column("ended_reason", sa.String(), nullable=True),     # logout | timeout | admin_kick
        sa.Column("duration_seconds", sa.Integer(), nullable=True),
        sa.Column("source_code_label", sa.String(), nullable=True),
        sa.Column("usage_tier", sa.String(), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=True),
    )

    # ── usage_events ──────────────────────────────────────────────────
    op.create_table(
        "usage_events",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), nullable=False, index=True),
        sa.Column("org_slug", sa.String(), nullable=False, index=True),
        sa.Column("event_type", sa.String(), nullable=False),      # chat | realtime | tts
        sa.Column("tokens_used", sa.Integer(), nullable=True),
        sa.Column("duration_seconds", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
    )

    # ── feature_flags ─────────────────────────────────────────────────
    op.create_table(
        "feature_flags",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_slug", sa.String(), nullable=False, index=True),
        sa.Column("flag_key", sa.String(), nullable=False),
        sa.Column("flag_value", sa.String(), nullable=False, server_default="true"),
        sa.Column("updated_by", sa.String(), nullable=True),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
    )
    op.create_index("ix_feature_flags_org_key", "feature_flags", ["org_slug", "flag_key"], unique=True)

    # ── contact_requests ──────────────────────────────────────────────
    op.create_table(
        "contact_requests",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("full_name", sa.String(), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("whatsapp", sa.String(), nullable=True),
        sa.Column("subject", sa.String(), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("privacy_request_type", sa.String(), nullable=True),
        sa.Column("consent_terms", sa.Boolean(), nullable=False),
        sa.Column("consent_marketing", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("user_agent", sa.String(), nullable=True),
        sa.Column("terms_version", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("retention_until", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
    )

    # ── marketing_consents ────────────────────────────────────────────
    op.create_table(
        "marketing_consents",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), nullable=True),
        sa.Column("contact_id", sa.String(), nullable=True),
        sa.Column("channel", sa.String(), nullable=False),         # email | whatsapp
        sa.Column("opt_in_date", sa.BigInteger(), nullable=True),
        sa.Column("opt_out_date", sa.BigInteger(), nullable=True),
        sa.Column("ip", sa.String(), nullable=True),
        sa.Column("source", sa.String(), nullable=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
    )

    # ── terms_acceptances ─────────────────────────────────────────────
    op.create_table(
        "terms_acceptances",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), nullable=False, index=True),
        sa.Column("terms_version", sa.String(), nullable=False),
        sa.Column("accepted_at", sa.BigInteger(), nullable=False),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("user_agent", sa.String(), nullable=True),
    )


def downgrade():
    op.drop_table("terms_acceptances")
    op.drop_table("marketing_consents")
    op.drop_table("contact_requests")
    op.drop_index("ix_feature_flags_org_key", table_name="feature_flags")
    op.drop_table("feature_flags")
    op.drop_table("usage_events")
    op.drop_table("user_sessions")
    op.drop_table("otp_codes")
    op.drop_table("signup_codes")
    op.drop_column("users", "marketing_consent")
    op.drop_column("users", "terms_version")
    op.drop_column("users", "terms_accepted_at")
    op.drop_column("users", "usage_tier")
    op.drop_column("users", "signup_source")
    op.drop_column("users", "signup_code_label")
