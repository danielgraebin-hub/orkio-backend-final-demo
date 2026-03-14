from __future__ import annotations
from sqlalchemy import Column, String, Text, BigInteger, Integer, LargeBinary, Boolean, Numeric, UniqueConstraint, CheckConstraint, Index
from .db import Base

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    email = Column(String, index=True, nullable=False)
    name = Column(String, nullable=False)
    role = Column(String, nullable=False, default="user")  # user|admin
    salt = Column(String, nullable=False)
    pw_hash = Column(String, nullable=False)
    created_at = Column(BigInteger, nullable=False)
    approved_at = Column(BigInteger, nullable=True)
    # PATCH0100_28: Summit fields
    signup_code_label = Column(String, nullable=True)
    signup_source = Column(String, nullable=True)       # pitch | invite
    usage_tier = Column(String, nullable=True, default="summit_standard")  # summit_standard | summit_vip
    terms_accepted_at = Column(BigInteger, nullable=True)
    terms_version = Column(String, nullable=True)
    marketing_consent = Column(Boolean, nullable=True, default=False)

class Thread(Base):
    __tablename__ = "threads"
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    title = Column(String, nullable=False)
    created_at = Column(BigInteger, nullable=False)

class Message(Base):
    __tablename__ = "messages"
    __table_args__ = (
        Index("ix_messages_org_thread", "org_slug", "thread_id"),
        Index("ux_messages_org_thread_client_msg", "org_slug", "thread_id", "client_message_id", unique=True),
    )
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    thread_id = Column(String, index=True, nullable=False)
    user_id = Column(String, nullable=True)
    user_name = Column(String, nullable=True)
    role = Column(String, nullable=False)  # user|assistant|system
    content = Column(Text, nullable=False)
    agent_id = Column(String, nullable=True)
    agent_name = Column(String, nullable=True)
    client_message_id = Column(String, nullable=True)
    created_at = Column(BigInteger, nullable=False)

class File(Base):
    __tablename__ = "files"
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    thread_id = Column(String, index=True, nullable=True)
    uploader_id = Column(String, nullable=True)
    uploader_name = Column(String, nullable=True)
    uploader_email = Column(String, nullable=True)
    filename = Column(String, nullable=False)
    original_filename = Column(String, nullable=True)
    origin = Column(String, nullable=False, default='unknown')
    scope_thread_id = Column(String, nullable=True)
    scope_agent_id = Column(String, nullable=True)
    mime_type = Column(String, nullable=True)
    size_bytes = Column(Integer, nullable=False, default=0)
    content = Column(LargeBinary, nullable=True)
    extraction_failed = Column(Boolean, nullable=False, default=False)
    is_institutional = Column(Boolean, nullable=False, default=False)
    created_at = Column(BigInteger, nullable=False)

class FileText(Base):
    __tablename__ = "file_texts"
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    file_id = Column(String, index=True, nullable=False)
    text = Column(Text, nullable=False)
    extracted_chars = Column(Integer, nullable=False, default=0)
    created_at = Column(BigInteger, nullable=False)

class FileChunk(Base):
    __tablename__ = "file_chunks"
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    file_id = Column(String, index=True, nullable=False)
    idx = Column(Integer, nullable=False)
    content = Column(Text, nullable=False)
    agent_id = Column(String, nullable=True)
    agent_name = Column(String, nullable=True)
    created_at = Column(BigInteger, nullable=False)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    user_id = Column(String, nullable=True)
    action = Column(String, nullable=False)
    meta = Column(Text, nullable=True)
    request_id = Column(String, nullable=True)
    path = Column(String, nullable=True)
    status_code = Column(Integer, nullable=True)
    latency_ms = Column(Integer, nullable=True)
    created_at = Column(BigInteger, nullable=False)


class Agent(Base):
    __tablename__ = "agents"
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    system_prompt = Column(Text, nullable=False, default="")
    model = Column(String, nullable=True)
    embedding_model = Column(String, nullable=True)
    temperature = Column(String, nullable=True)
    rag_enabled = Column(Boolean, nullable=False, default=True)
    rag_top_k = Column(Integer, nullable=False, default=6)
    is_default = Column(Boolean, nullable=False, default=False)
    voice_id = Column(String, nullable=True, default="nova")
    avatar_url = Column(String, nullable=True)
    created_at = Column(BigInteger, nullable=False)
    updated_at = Column(BigInteger, nullable=False)

class AgentKnowledge(Base):
    __tablename__ = "agent_knowledge"
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    agent_id = Column(String, index=True, nullable=False)
    file_id = Column(String, index=True, nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(BigInteger, nullable=False)


class AgentLink(Base):
    __tablename__ = "agent_links"
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    source_agent_id = Column(String, index=True, nullable=False)
    target_agent_id = Column(String, index=True, nullable=False)
    mode = Column(String, nullable=False, default="consult")
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(BigInteger, nullable=False)


class CostEvent(Base):
    __tablename__ = "cost_events"
    __table_args__ = (
        Index("ix_cost_events_org_created", "org_slug", "created_at"),
    )
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    user_id = Column(String, nullable=True)
    thread_id = Column(String, index=True, nullable=True)
    message_id = Column(String, index=True, nullable=True)
    agent_id = Column(String, index=True, nullable=True)
    provider = Column(String, nullable=True)
    model = Column(String, nullable=True, index=True)
    prompt_tokens = Column(Integer, nullable=False, default=0)
    completion_tokens = Column(Integer, nullable=False, default=0)
    total_tokens = Column(Integer, nullable=False, default=0)
    input_cost_usd = Column(Numeric(12, 6), nullable=False, default=0)
    output_cost_usd = Column(Numeric(12, 6), nullable=False, default=0)
    total_cost_usd = Column(Numeric(12, 6), nullable=False, default=0)
    cost_usd = Column(Numeric(12, 6), nullable=False, default=0)
    pricing_version = Column(String, nullable=False, default="2026-02-18")
    pricing_snapshot = Column(Text, nullable=True)
    usage_missing = Column(Boolean, nullable=False, default=False)
    meta = Column("metadata", Text, nullable=True)
    created_at = Column(BigInteger, nullable=False)


class FileRequest(Base):
    __tablename__ = "file_requests"
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    file_id = Column(String, index=True, nullable=False)
    requested_by_user_id = Column(String, nullable=True)
    requested_by_user_name = Column(String, nullable=True)
    status = Column(String, nullable=False, default="pending")
    created_at = Column(BigInteger, nullable=False)
    resolved_at = Column(BigInteger, nullable=True)
    resolved_by_admin_id = Column(String, nullable=True)


class PricingSnapshot(Base):
    __tablename__ = "pricing_snapshots"
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False, default="public")
    provider = Column(String, index=True, nullable=False, default="openai")
    model = Column(String, index=True, nullable=False)
    input_per_1m = Column(Numeric(10, 6), nullable=False, default=0)
    output_per_1m = Column(Numeric(10, 6), nullable=False, default=0)
    currency = Column(String, nullable=False, default="USD")
    source = Column(String, nullable=True)
    fetched_at = Column(BigInteger, nullable=False)
    effective_at = Column(BigInteger, nullable=False)


class Lead(Base):
    __tablename__ = "leads"
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False, default="public")
    name = Column(String, nullable=False)
    email = Column(String, nullable=False, index=True)
    company = Column(String, nullable=False)
    role = Column(String, nullable=True)
    segment = Column(String, nullable=True)
    source = Column(String, nullable=True, default="qr")
    ua = Column(String, nullable=True)
    created_at = Column(BigInteger, nullable=False)


class ThreadMember(Base):
    __tablename__ = "thread_members"
    __table_args__ = (
        UniqueConstraint("thread_id", "user_id", name="uq_thread_members_thread_user"),
        CheckConstraint("role IN ('owner','admin','member','viewer')", name="ck_thread_members_role"),
    )
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    thread_id = Column(String, index=True, nullable=False)
    user_id = Column(String, index=True, nullable=False)
    role = Column(String, nullable=False)
    created_at = Column(BigInteger, nullable=False)


class RealtimeSession(Base):
    __tablename__ = "realtime_sessions"
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    thread_id = Column(String, index=True, nullable=False)
    agent_id = Column(String, nullable=True)
    agent_name = Column(String, nullable=True)
    user_id = Column(String, nullable=True)
    user_name = Column(String, nullable=True)
    model = Column(String, nullable=True)
    voice = Column(String, nullable=True)
    started_at = Column(BigInteger, nullable=False)
    ended_at = Column(BigInteger, nullable=True)
    meta = Column(Text, nullable=True)

class RealtimeEvent(Base):
    __tablename__ = "realtime_events"
    __table_args__ = (
        Index("ux_realtime_events_org_sess_client_eid", "org_slug", "session_id", "client_event_id", unique=True),
    )
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    session_id = Column(String, index=True, nullable=False)
    thread_id = Column(String, index=True, nullable=False)
    role = Column(String, nullable=False)
    agent_id = Column(String, nullable=True)
    agent_name = Column(String, nullable=True)
    event_type = Column(String, nullable=False)
    content = Column(Text, nullable=True)
    transcript_punct = Column(Text, nullable=True)
    created_at = Column(BigInteger, nullable=False)
    client_event_id = Column(String, nullable=True)
    meta = Column(Text, nullable=True)


# ═══════════════════════════════════════════════════════════════════════
# PATCH0100_28 — Summit Hardening + Legal Compliance
# ═══════════════════════════════════════════════════════════════════════

class SignupCode(Base):
    __tablename__ = "signup_codes"
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    code_hash = Column(String, nullable=False)
    label = Column(String, nullable=False)
    source = Column(String, nullable=False)          # pitch | invite
    expires_at = Column(BigInteger, nullable=False)
    max_uses = Column(Integer, nullable=False, default=500)
    used_count = Column(Integer, nullable=False, default=0)
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(BigInteger, nullable=False)
    created_by = Column(String, nullable=True)

class OtpCode(Base):
    __tablename__ = "otp_codes"
    id = Column(String, primary_key=True)
    user_id = Column(String, index=True, nullable=False)
    code_hash = Column(String, nullable=False)
    expires_at = Column(BigInteger, nullable=False)
    attempts = Column(Integer, nullable=False, default=0)
    verified = Column(Boolean, nullable=False, default=False)
    created_at = Column(BigInteger, nullable=False)

class UserSession(Base):
    __tablename__ = "user_sessions"
    id = Column(String, primary_key=True)
    user_id = Column(String, index=True, nullable=False)
    org_slug = Column(String, index=True, nullable=False)
    login_at = Column(BigInteger, nullable=False)
    logout_at = Column(BigInteger, nullable=True)
    last_seen_at = Column(BigInteger, nullable=False)
    ended_reason = Column(String, nullable=True)     # logout | timeout | admin_kick
    duration_seconds = Column(Integer, nullable=True)
    source_code_label = Column(String, nullable=True)
    usage_tier = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)

class UsageEvent(Base):
    __tablename__ = "usage_events"
    id = Column(String, primary_key=True)
    user_id = Column(String, index=True, nullable=False)
    org_slug = Column(String, index=True, nullable=False)
    event_type = Column(String, nullable=False)      # chat | realtime | tts
    tokens_used = Column(Integer, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    created_at = Column(BigInteger, nullable=False)

class FeatureFlag(Base):
    __tablename__ = "feature_flags"
    __table_args__ = (
        Index("ix_feature_flags_org_key", "org_slug", "flag_key", unique=True),
    )
    id = Column(String, primary_key=True)
    org_slug = Column(String, index=True, nullable=False)
    flag_key = Column(String, nullable=False)
    flag_value = Column(String, nullable=False, default="true")
    updated_by = Column(String, nullable=True)
    updated_at = Column(BigInteger, nullable=False)

class ContactRequest(Base):
    __tablename__ = "contact_requests"
    id = Column(String, primary_key=True)
    full_name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    whatsapp = Column(String, nullable=True)
    subject = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    privacy_request_type = Column(String, nullable=True)
    consent_terms = Column(Boolean, nullable=False)
    consent_marketing = Column(Boolean, nullable=False, default=False)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    terms_version = Column(String, nullable=True)
    status = Column(String, nullable=False, default="pending")
    retention_until = Column(BigInteger, nullable=True)
    created_at = Column(BigInteger, nullable=False)

class MarketingConsent(Base):
    __tablename__ = "marketing_consents"
    id = Column(String, primary_key=True)
    user_id = Column(String, nullable=True)
    contact_id = Column(String, nullable=True)
    channel = Column(String, nullable=False)         # email | whatsapp
    opt_in_date = Column(BigInteger, nullable=True)
    opt_out_date = Column(BigInteger, nullable=True)
    ip = Column(String, nullable=True)
    source = Column(String, nullable=True)
    created_at = Column(BigInteger, nullable=False)

class TermsAcceptance(Base):
    __tablename__ = "terms_acceptances"
    id = Column(String, primary_key=True)
    user_id = Column(String, index=True, nullable=False)
    terms_version = Column(String, nullable=False)
    accepted_at = Column(BigInteger, nullable=False)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
