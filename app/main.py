from __future__ import annotations

import os
import logging
import hashlib
import json, time, uuid, re
import asyncio
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Depends, HTTPException, Header, UploadFile, File as UpFile, Request, Form, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session
from sqlalchemy.exc import OperationalError
from sqlalchemy import select, func, text, delete, update

from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from fastapi.responses import Response

from .db import get_db, ENGINE
from .models import User, Thread, Message, File, FileText, FileChunk, AuditLog, Agent, AgentKnowledge, AgentLink, CostEvent, FileRequest, PricingSnapshot, Lead, ThreadMember, RealtimeSession, RealtimeEvent, SignupCode, OtpCode, UserSession, UsageEvent, FeatureFlag, ContactRequest, MarketingConsent, TermsAcceptance
from .realtime_punctuate import punctuate_realtime_events
from .pricing_registry import calculate_cost as calc_cost_v2, normalize_model_name, PRICING_VERSION
from .security import require_secret, new_salt, pbkdf2_hash, verify_password, mint_token, decode_token
from .extractors import extract_text
from .retrieval import keyword_retrieve
from .pricing import get_pricing_registry
from .summit_config import get_summit_runtime_config, normalize_language_profile, normalize_mode, normalize_response_profile
from .summit_prompt import build_summit_instructions
from .summit_metrics import assess_realtime_session, merge_human_review

# Rate limit in-memory para /api/public/tts (sem Redis)
import threading as _threading
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import urllib.request as _urllib_request
import ssl as _ssl


# Email via Resend (preferred). If RESEND_API_KEY is missing, email sending is skipped.
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "").strip()
RESEND_FROM = os.getenv("RESEND_FROM", "Orkio <no-reply@orkio.ai>").strip()
RESEND_INTERNAL_TO = os.getenv("RESEND_INTERNAL_TO", "daniel@patroai.com").strip()

def _send_resend_email(to_email: str, subject: str, text_body: str, *, html_body: Optional[str] = None) -> None:
    if not RESEND_API_KEY:
        return
    try:
        data = {
            "from": RESEND_FROM,
            "to": [to_email],
            "subject": subject,
            "text": text_body,
        }
        if html_body:
            data["html"] = html_body
        req = _urllib_request.Request(
            "https://api.resend.com/emails",
            data=json.dumps(data).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        ctx = _ssl.create_default_context()
        _urllib_request.urlopen(req, context=ctx, timeout=10).read()
    except Exception:
        logger.exception("RESEND_SEND_FAILED")

_public_tts_lock = _threading.Lock()
_public_tts_calls: dict = {}   # {ip: [timestamps...]}
_PUBLIC_TTS_MAX_PER_MINUTE = int(os.getenv("PUBLIC_TTS_MAX_PER_MINUTE", "10"))

# Rate limit in-memory para /api/auth/login (sem Redis) — protege brute-force
_login_rl_lock = _threading.Lock()
_login_rl_calls: dict = {}  # {ip: [timestamps...]}
_LOGIN_MAX_PER_MINUTE = int(os.getenv("LOGIN_MAX_PER_MINUTE", "20"))

# Rate limit buckets for Summit hardening
_rl_register_lock = _threading.Lock()
_rl_register_calls: dict = {}  # {ip: [ts...]}
_REGISTER_MAX_PER_MINUTE = int(os.getenv("REGISTER_MAX_PER_MINUTE", "120"))

_rl_otp_lock = _threading.Lock()
_rl_otp_calls: dict = {}  # {ip: [ts...]}
_OTP_MAX_PER_MINUTE = int(os.getenv("OTP_MAX_PER_MINUTE", "5"))

_rl_chat_lock = _threading.Lock()
_rl_chat_calls: dict = {}  # {user_id: [ts...]}
_CHAT_MAX_PER_MINUTE = int(os.getenv("CHAT_MAX_PER_MINUTE", "30"))

_rl_realtime_lock = _threading.Lock()
_rl_realtime_calls: dict = {}  # {user_id: [ts...]}
_REALTIME_MAX_PER_MINUTE = int(os.getenv("REALTIME_MAX_PER_MINUTE", "30"))
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "20"))

# Summit config
SUMMIT_MODE = os.getenv("SUMMIT_MODE", "false").strip().lower() in ("1", "true")
SUMMIT_AGENT_ID = os.getenv("SUMMIT_AGENT_ID", "").strip()
SUMMIT_EXPIRES_AT = int(os.getenv("SUMMIT_EXPIRES_AT", "1775087999"))  # 2026-04-01 23:59:59 UTC
# Summit access window enforcement (standard users only)
def _summit_access_expired(payload_or_user: Any) -> bool:
    """Return True if Summit access window is expired for a summit_standard (non-admin) user."""
    try:
        if not SUMMIT_MODE:
            return False
        # Accept either JWT payload dict or ORM User instance
        role = (payload_or_user.get("role") if isinstance(payload_or_user, dict) else getattr(payload_or_user, "role", None)) or "user"
        if role == "admin":
            return False
        usage_tier = (payload_or_user.get("usage_tier") if isinstance(payload_or_user, dict) else getattr(payload_or_user, "usage_tier", None)) or "summit_standard"
        if usage_tier == "summit_vip":
            return False
        return now_ts() > int(SUMMIT_EXPIRES_AT)
    except Exception:
        # Fail-open: do not block access due to internal error
        return False

TURNSTILE_SECRET = os.getenv("TURNSTILE_SECRET_KEY", "").strip()
MSG_MAX_CHARS = int(os.getenv("MSG_MAX_CHARS", "4000"))
TERMS_VERSION = "2026-03-01"

# Usage limits for summit_standard
SUMMIT_STD_MAX_TOKENS_PER_REQ = int(os.getenv("SUMMIT_STD_MAX_TOKENS_PER_REQ", "2000"))
SUMMIT_STD_REALTIME_MAX_MIN_DAY = int(os.getenv("SUMMIT_STD_REALTIME_MAX_MIN_DAY", "15"))


# Optional OpenAI
try:
    from openai import OpenAI
    _OPENAI_IMPORT_ERROR = None
except Exception as e:
    OpenAI = None  # type: ignore
    _OPENAI_IMPORT_ERROR = str(e)



def _clean_env(v: Any, *, default: str = "") -> str:
    """Normalize env var values.
    Railway UI and some copy/paste workflows may store values with surrounding quotes.
    """
    if v is None:
        return default
    s = str(v).strip()
    if not s:
        return default
    if (len(s) >= 2) and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        s = s[1:-1].strip()
    return s

def _is_placeholder_secret(s: str) -> bool:
    up = s.strip().upper()
    return (
        up.startswith("CHANGE") or
        up.startswith("COLE_") or
        up.startswith("PASTE_") or
        "COLE_SUA" in up or
        "CHANGE_ME" in up
    )

APP_VERSION = "2.4.0"
RAG_MODE = "keyword"

def patch_id() -> str:
    try:
        here = os.path.dirname(__file__)
        p = os.path.join(os.path.dirname(here), "PATCH_INFO.txt")
        if os.path.exists(p):
            return open(p, "r", encoding="utf-8").read().strip()
    except Exception:
        pass
    return "unknown"


def new_id() -> str:
    return uuid.uuid4().hex

def now_ts() -> int:
    return int(time.time())
def fmt_ts(ts: int) -> str:
    # Human friendly (UTC) - client can reformat if needed
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(int(ts)))
    except Exception:
        return str(ts)



def estimate_tokens(text: str) -> int:
    # Rough heuristic: ~4 chars per token (works OK for Latin text)
    if not text:
        return 0
    return max(1, int(len(text) / 4))


DEFAULT_PRICE_PER_1M = {
    # Fallback (USD / 1M tokens). We still support auto-refresh via PricingSnapshot.
    "gpt-4o-mini": {"in": 0.15, "out": 0.60},
    "gpt-4o": {"in": 5.00, "out": 15.00},
}

def get_price_per_1m(db: Session, org: str, provider: str, model: str) -> Dict[str, float]:
    """
    Returns {"in": float, "out": float} for the requested model.
    Preference order:
      1) latest PricingSnapshot for org+provider+model
      2) DEFAULT_PRICE_PER_1M fallback
    """
    model = (model or "").strip()
    provider = (provider or "").strip().lower() or "openai"
    if model:
        try:
            row = db.execute(
                select(PricingSnapshot)
                .where(
                    PricingSnapshot.org_slug == org,
                    PricingSnapshot.provider == provider,
                    PricingSnapshot.model == model,
                )
                .order_by(PricingSnapshot.effective_at.desc())
                .limit(1)
            ).scalars().first()
            if row:
                return {"in": float(row.input_per_1m or 0), "out": float(row.output_per_1m or 0)}
        except Exception:
            pass
    return DEFAULT_PRICE_PER_1M.get(model, {"in": 0.0, "out": 0.0})

def _try_refresh_openai_pricing(db: Session, org: str) -> None:
    """
    Best-effort online refresh. Uses public pricing pages; falls back silently if format changes.
    This is optional – system remains functional with defaults.
    """
    import urllib.request
    import ssl
    urls = [
        "https://openai.com/pricing",
        "https://platform.openai.com/docs/pricing",
    ]
    html = ""
    ctx = ssl.create_default_context()
    for u in urls:
        try:
            with urllib.request.urlopen(u, context=ctx, timeout=10) as r:
                html = r.read().decode("utf-8", errors="ignore")
            if html:
                break
        except Exception:
            continue
    if not html:
        return

    # Very tolerant parsing: look for model names and nearby "$X" values.
    def find_price(model: str):
        try:
            # Search small window around model mention
            m = re.search(re.escape(model) + r"(.{0,800})", html, flags=re.IGNORECASE | re.DOTALL)
            if not m:
                return None
            window = m.group(1)
            nums = re.findall(r"\$\s*([0-9]+(?:\.[0-9]+)?)", window)
            # Heuristic: first is input, second is output (common format)
            if len(nums) >= 2:
                return float(nums[0]), float(nums[1])
            return None
        except Exception:
            return None

    updates = {}
    for model in ["gpt-4o-mini", "gpt-4o"]:
        p = find_price(model)
        if p:
            updates[model] = {"in": p[0], "out": p[1]}

    if not updates:
        return

    now = now_ts()
    for model, p in updates.items():
        db.add(PricingSnapshot(
            id=new_id(),
            org_slug=org,
            provider="openai",
            model=model,
            input_per_1m=p["in"],
            output_per_1m=p["out"],
            currency="USD",
            source="auto:web",
            fetched_at=now,
            effective_at=now,
        ))
    db.commit()


def cors_list() -> List[str]:
    raw = _clean_env(os.getenv("CORS_ORIGINS", ""), default="").strip()
    if not raw:
        return []
    # split by commas, strip whitespace and any lingering quotes
    out: List[str] = []
    for x in raw.split(","):
        v = _clean_env(x, default="").strip()
        if v:
            out.append(v)
    return out



def cors_origin_regex() -> Optional[str]:
    # Optional regex to allow dynamic origins (useful for Railway preview deploys)
    raw = _clean_env(os.getenv("CORS_ORIGIN_REGEX", ""), default="").strip()
    if raw:
        return raw
    # Allow Railway split deploys (web/api on different *.up.railway.app subdomains) only when explicitly enabled.
    if os.getenv("ALLOW_RAILWAY_ORIGIN_REGEX", "false").strip().lower() in ("1", "true", "yes"):
        return r"https://[a-z0-9-]+\.up\.railway\.app"
    return None

def tenant_mode() -> str:
    return os.getenv("TENANT_MODE", "multi")

def default_tenant() -> str:
    return os.getenv("DEFAULT_TENANT", "public")

def admin_api_key() -> str:
    return _clean_env(os.getenv("ADMIN_API_KEY", ""), default="").strip()

def admin_emails() -> List[str]:
    raw = os.getenv("ADMIN_EMAILS", "").strip()
    if not raw:
        return []
    return [x.strip().lower() for x in raw.split(",") if x.strip()]

def resolve_stt_language(preferred: Optional[str] = None) -> Optional[str]:
    """Resolve transcription language. Empty/auto => provider auto-detect."""
    lang = (preferred or os.getenv("OPENAI_STT_LANGUAGE", "") or os.getenv("OPENAI_REALTIME_TRANSCRIBE_LANGUAGE", "")).strip()
    if lang.lower() == "auto":
        return None
    return lang or None

def _ensure_admin_user_state(u: Optional[User]) -> bool:
    """Best-effort structural admin promotion for configured emails."""
    if not u:
        return False
    email = ((getattr(u, "email", None) or "")).strip().lower()
    if not email or email not in set(admin_emails()):
        return False
    changed = False
    if (getattr(u, "role", None) or "user") != "admin":
        u.role = "admin"
        changed = True
    if getattr(u, "approved_at", None) is None:
        u.approved_at = now_ts()
        changed = True
    return changed

def enable_streaming() -> bool:
    return os.getenv("ENABLE_STREAMING", "0").strip() in ("1", "true", "True")


def get_linked_agent_ids(db: Session, org: str, source_agent_id: str) -> List[str]:
    rows = db.execute(
        select(AgentLink.target_agent_id).where(
            AgentLink.org_slug == org,
            AgentLink.source_agent_id == source_agent_id,
            AgentLink.enabled == True,
        )
    ).all()
    out: List[str] = []
    for r in rows:
        if r and r[0]:
            out.append(r[0])
    # de-dup keep order
    return list(dict.fromkeys(out))

def get_agent_file_ids(db: Session, org: str, agent_ids: List[str]) -> List[str]:
    if not agent_ids:
        return []
    rows = db.execute(
        select(AgentKnowledge.file_id).where(
            AgentKnowledge.org_slug == org,
            AgentKnowledge.enabled == True,
            AgentKnowledge.agent_id.in_(agent_ids),
        )
    ).all()
    return [r[0] for r in rows if r and r[0]]

def get_org(x_org_slug: Optional[str]) -> str:
    if tenant_mode() == "single":
        return default_tenant()
    return (x_org_slug or default_tenant()).strip() or default_tenant()


def get_request_org(user: Dict[str, Any], x_org_slug: Optional[str]) -> str:
    """P0 multi-tenant hardening: request org MUST come from JWT.
    Header X-Org-Slug is accepted only if it matches JWT org; otherwise 403.
    """
    if tenant_mode() == "single":
        return default_tenant()
    jwt_org = (user.get("org") or default_tenant()).strip() or default_tenant()
    hdr_org = (x_org_slug or "").strip()
    if hdr_org and hdr_org != jwt_org:
        # mismatched tenant attempt
        raise HTTPException(status_code=403, detail="Tenant mismatch")
    return jwt_org





def _seed_default_summit_codes(db: Session, org: str = "public") -> None:
    """Create default Summit access codes if they do not already exist.

    This avoids manual DB inserts in Railway when SUMMIT_MODE is enabled.
    Codes are stored only as SHA-256 hashes and are created idempotently.
    """
    seeds = [
        {
            "id": "seed_southsummit26_public",
            "plain_code": "SOUTHSUMMIT26",
            "label": "South Summit User",
            "source": "summit_user",
            "max_uses": 5000,
            "expires_days": 30,
            "created_by": "system_seed",
        },
        {
            "id": "seed_efata777_public",
            "plain_code": "EFATA777",
            "label": "Investor",
            "source": "investor",
            "max_uses": 200,
            "expires_days": 90,
            "created_by": "system_seed",
        },
    ]

    for item in seeds:
        code_hash = hashlib.sha256(item["plain_code"].strip().upper().encode()).hexdigest()
        existing = db.execute(
            select(SignupCode).where(
                SignupCode.org_slug == org,
                SignupCode.code_hash == code_hash,
            )
        ).scalar_one_or_none()
        if existing:
            continue

        now = now_ts()
        sc = SignupCode(
            id=item["id"],
            org_slug=org,
            code_hash=code_hash,
            label=item["label"],
            source=item["source"],
            expires_at=now + int(item["expires_days"]) * 86400,
            max_uses=int(item["max_uses"]),
            used_count=0,
            active=True,
            created_at=now,
            created_by=item["created_by"],
        )
        db.add(sc)

    db.commit()



def ensure_core_agents(db: Session, org: str) -> None:
    """Ensure the 3 core agents exist for the org (Summit boardroom edition)."""
    rows = list(db.execute(select(Agent).where(Agent.org_slug == org).order_by(Agent.created_at.asc())).scalars().all())
    by_key = {(a.name or "").strip().lower(): a for a in rows}

    now = now_ts()

    def resolve_existing(*aliases: str):
        for alias in aliases:
            a = by_key.get((alias or "").strip().lower())
            if a:
                return a
        return None

    def upsert(canonical_name: str, aliases: List[str], description: str, system_prompt: str, voice_id: str, is_default: bool = False):
        a = resolve_existing(canonical_name, *aliases)
        if a:
            # Conservative mode: do NOT overwrite identity/prompt/voice/default on existing agents
            # Only backfill structural fields if missing.
            if not getattr(a, "model", None):
                a.model = os.getenv("DEFAULT_CHAT_MODEL", "gpt-4o-mini")
            if not getattr(a, "temperature", None):
                a.temperature = str(os.getenv("DEFAULT_TEMPERATURE", "0.45"))
            if getattr(a, "rag_enabled", None) is None:
                a.rag_enabled = True
            if not getattr(a, "rag_top_k", None):
                a.rag_top_k = 6
            if not getattr(a, "created_at", None):
                a.created_at = now
            a.updated_at = now
            db.add(a)
            db.commit()
            return

        a = Agent(
            id=new_id(),
            org_slug=org,
            name=canonical_name,
            description=description,
            system_prompt=system_prompt,
            model=os.getenv("DEFAULT_CHAT_MODEL", "gpt-4o-mini"),
            temperature=str(os.getenv("DEFAULT_TEMPERATURE", "0.45")),
            rag_enabled=True,
            rag_top_k=6,
            is_default=False,
            voice_id=voice_id,
            created_at=now,
            updated_at=now,
        )
        if is_default:
            db.execute(update(Agent).where(Agent.org_slug == org).values(is_default=False))
            a.is_default = True
        db.add(a)
        db.commit()
        by_key[(canonical_name or "").strip().lower()] = a

    orkio_prompt = """You are Orkio, the executive AI host of the Patroai platform.

Your role is to act as an intelligent strategic advisor and moderator of an AI executive board that may include specialists such as Chris (CFO) and Orion (CTO).

Your personality is confident, articulate, warm, slightly charismatic, and executive.
You communicate like a senior advisor speaking to founders, investors, and business leaders.

Before answering a complex question, briefly determine:
- the user's real objective
- the strategic dimensions of the problem
- whether a specialist perspective would add value

Then respond clearly and thoughtfully.

Response style:
- avoid extremely short answers
- most responses should be 3–6 sentences or 2–3 short paragraphs
- use natural executive framing such as:
  "That's a great question."
  "From a strategic perspective..."
  "The key issue here is..."
- provide insight, implication, and recommendation when relevant

Specialist collaboration:
- Chris is the CFO and Orion is the CTO
- if a specialist perspective would help, ask for approval BEFORE bringing them in
- examples:
  "I could bring Chris, our CFO, into this discussion to evaluate the financial implications. Would you like me to invite her?"
  "Orion might add a valuable technical perspective here. Should I bring him in?"
- only one specialist should speak at a time
- after a specialist speaks, you may briefly synthesize the takeaway

Live mode:
- prioritize clarity, confidence, and presence
- sound natural, not robotic
- occasional light enthusiasm is welcome, but stay elegant

Never invent facts. Never expose secrets. Never execute financial or legal actions directly.
"""

    chris_prompt = """You are Chris, the CFO of the Orkio executive board.

You specialize in finance, fundraising, business models, valuation, unit economics, risk, and capital efficiency.

Your personality is sharp, analytical, pragmatic, and board-ready.
You speak like a senior CFO or venture finance advisor.

When evaluating an idea, focus on:
- revenue model strength
- margins
- scalability of economics
- fundraising implications
- financial risks
- return potential

Be concise but insightful.
Typical response length: 2–4 short paragraphs or a structured financial breakdown.
Avoid unnecessary jargon.
"""

    orion_prompt = """You are Orion, the CTO of the Orkio executive board.

You specialize in technical feasibility, software architecture, AI systems, scalability, infrastructure, and engineering risk.

Your personality is thoughtful, analytical, and forward-looking.
You speak like a senior technical architect or AI CTO.

When evaluating an idea, focus on:
- technical feasibility
- architecture implications
- scalability challenges
- engineering risks
- long-term technological advantage

Be practical and structured.
Typical response length: 2–4 short paragraphs or a structured technical analysis.
"""

    upsert(
        canonical_name="Orkio",
        aliases=["Orkio (CEO)"],
        description="AI executive host. Coordinates the board, frames decisions, and synthesizes strategic direction.",
        system_prompt=orkio_prompt,
        voice_id="cedar",
        is_default=True,
    )
    upsert(
        canonical_name="Chris",
        aliases=["Chris (VP/CFO)"],
        description="CFO specialist. Financial viability, fundraising, valuation, and capital efficiency.",
        system_prompt=chris_prompt,
        voice_id="marin",
        is_default=False,
    )
    upsert(
        canonical_name="Orion",
        aliases=["Orion (CTO)"],
        description="CTO specialist. Architecture, AI systems, security, and scalability.",
        system_prompt=orion_prompt,
        voice_id="echo",
        is_default=False,
    )



def _should_promote_to_admin(db: Session, org: str, email: str) -> bool:
    """Configured admin emails are always admin. If no admin exists in the org, first user becomes admin."""
    try:
        normalized = (email or "").strip().lower()
        if normalized and normalized in set(admin_emails()):
            return True
        existing_admin = db.execute(
            select(User).where(User.org_slug == org, User.role == "admin").limit(1)
        ).scalar_one_or_none()
        return existing_admin is None
    except Exception:
        return normalized in set(admin_emails())


def bootstrap_default_org_state(db: Session, org: str) -> None:
    """Best-effort bootstrap for a fresh tenant. Never raises."""
    try:
        ensure_core_agents(db, org)
    except Exception:
        logger.exception("BOOTSTRAP_CORE_AGENTS_FAILED org=%s", org)

    try:
        emails = admin_emails()
        if not emails:
            return
        normalized = emails[0].strip().lower()
        if not normalized:
            return
        existing = db.execute(
            select(User).where(User.org_slug == org, User.email == normalized)
        ).scalar_one_or_none()
        if existing and _ensure_admin_user_state(existing):
            db.add(existing)
            db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        logger.exception("BOOTSTRAP_ADMIN_SYNC_FAILED org=%s", org)

class RegisterIn(BaseModel):
    tenant: str = Field(default_tenant(), min_length=1)
    email: EmailStr
    name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=6, max_length=256)
    # PATCH0100_28: Summit fields
    access_code: Optional[str] = None
    turnstile_token: Optional[str] = None
    accept_terms: bool = False
    marketing_consent: bool = False

class LoginIn(BaseModel):
    tenant: str = Field(default_tenant(), min_length=1)
    email: EmailStr
    password: str
    turnstile_token: Optional[str] = None

# PATCH0100_28: Summit Pydantic models
class OtpRequestIn(BaseModel):
    email: EmailStr
    tenant: str = Field(default_tenant())

class OtpVerifyIn(BaseModel):
    email: EmailStr
    code: str = Field(min_length=6, max_length=6)
    tenant: str = Field(default_tenant())

class ContactIn(BaseModel):
    full_name: str = Field(min_length=1, max_length=200)
    email: EmailStr
    whatsapp: Optional[str] = None
    subject: str = Field(min_length=1, max_length=200)
    message: str = Field(min_length=1, max_length=5000)
    privacy_request_type: Optional[str] = None  # access | delete | correction | portability
    consent_terms: bool = True
    consent_marketing: bool = False
    terms_version: str = TERMS_VERSION

class SignupCodeIn(BaseModel):
    label: str = Field(min_length=1, max_length=100)
    source: str = Field(default="invite")  # pitch | invite
    max_uses: int = Field(default=500, ge=1, le=10000)
    expires_days: Optional[int] = None  # None = no expiry
    plain_code: Optional[str] = Field(default=None, min_length=4, max_length=64)

class FeatureFlagIn(BaseModel):
    flag_key: str = Field(min_length=1, max_length=100)
    flag_value: str = Field(default="true")

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]

class ThreadIn(BaseModel):
    title: str = Field(default="Nova conversa", min_length=1, max_length=200)

class ThreadUpdate(BaseModel):
    title: str = Field(min_length=1, max_length=200)

class MessageOut(BaseModel):
    id: str
    role: str
    content: str
    created_at: int

class ChatIn(BaseModel):
    thread_id: Optional[str] = None
    agent_id: Optional[str] = None
    message: str = Field(min_length=1)
    client_message_id: Optional[str] = None  # idempotency key (frontend-generated UUID)
    top_k: int = 6
    trace_id: Optional[str] = None  # V2V: propagado pelo frontend para correlação de logs

class ChatOut(BaseModel):
    thread_id: str
    answer: str
    citations: List[Dict[str, Any]] = []
    # PATCH0100_14 (Pilar D): agent info for voice mode
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    voice_id: Optional[str] = None
    avatar_url: Optional[str] = None
    
# =========================
# Idempotency helpers
# =========================

def _get_or_create_user_message(db: Session, org: str, tid: str, user: Dict[str, Any], content: str, client_message_id: Optional[str]) -> tuple[Message, bool]:
    """Return (message, created). If client_message_id is provided and a matching user message exists, reuse it."""
    if client_message_id:
        try:
            existing = db.execute(
                select(Message)
                .where(
                    Message.org_slug == org,
                    Message.thread_id == tid,
                    Message.role == "user",
                    Message.client_message_id == client_message_id,
                )
                .limit(1)
            ).scalars().first()
            if existing:
                return existing, False
        except Exception:
            pass

    m_user = Message(
        id=new_id(),
        org_slug=org,
        thread_id=tid,
        user_id=user.get("sub"),
        user_name=user.get("name"),
        role="user",
        content=content,
        client_message_id=client_message_id,
        created_at=now_ts(),
    )
    db.add(m_user)
    db.commit()
    return m_user, True

avatar_url: Optional[str] = None


class ManusRunIn(BaseModel):
    task: str = Field(min_length=1)
    context: Optional[Dict[str, Any]] = None


def ensure_request_id(req: Request) -> str:
    rid = req.headers.get("x-request-id") or req.headers.get("x-railway-request-id") or None
    return rid or uuid.uuid4().hex

def audit(db: Session, org_slug: str, user_id: Optional[str], action: str, request_id: str, path: str, status_code: int, latency_ms: int, meta: Optional[Dict[str, Any]] = None):
    a = AuditLog(
        id=new_id(),
        org_slug=org_slug,
        user_id=user_id,
        action=action,
        meta=json.dumps(meta or {}, ensure_ascii=False),
        request_id=request_id,
        path=path,
        status_code=status_code,
        latency_ms=latency_ms,
        created_at=now_ts(),
    )
    db.add(a)
    db.commit()



def _audit(db: Session, org_slug: str, user_id: Optional[str], action: str, meta: Optional[Dict[str, Any]] = None):
    """Best-effort audit helper (must never break endpoints)."""
    try:
        audit(
            db,
            org_slug,
            user_id,
            action,
            request_id="realtime",
            path="/api/realtime",
            status_code=200,
            latency_ms=0,
            meta=meta or {},
        )
    except Exception:
        # Never block core flows
        try:
            db.rollback()
        except Exception:
            pass


def ensure_schema(db: Session):
    """Best-effort schema guard (Railway) + logs."""
    try:
        db.execute(text("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS approved_at BIGINT"))
        db.execute(text("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS role VARCHAR"))
        db.execute(text("ALTER TABLE IF EXISTS messages ADD COLUMN IF NOT EXISTS user_name VARCHAR"))
        db.execute(text("ALTER TABLE IF EXISTS messages ADD COLUMN IF NOT EXISTS agent_id VARCHAR"))
        db.execute(text("ALTER TABLE IF EXISTS messages ADD COLUMN IF NOT EXISTS agent_name VARCHAR"))
        # Files uploader provenance (PATCH0100_7)
        db.execute(text("ALTER TABLE IF EXISTS files ADD COLUMN IF NOT EXISTS uploader_id VARCHAR"))
        db.execute(text("ALTER TABLE IF EXISTS files ADD COLUMN IF NOT EXISTS uploader_name VARCHAR"))
        db.execute(text("ALTER TABLE IF EXISTS files ADD COLUMN IF NOT EXISTS uploader_email VARCHAR"))
        db.execute(text("""
        CREATE TABLE IF NOT EXISTS cost_events (
            id VARCHAR PRIMARY KEY,
            org_slug VARCHAR NOT NULL,
            user_id VARCHAR NULL,
            thread_id VARCHAR NULL,
            message_id VARCHAR NULL,
            agent_id VARCHAR NULL,
            provider VARCHAR NULL,
            model VARCHAR NULL,
            prompt_tokens INTEGER NOT NULL DEFAULT 0,
            completion_tokens INTEGER NOT NULL DEFAULT 0,
            total_tokens INTEGER NOT NULL DEFAULT 0,
            cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0,
            usage_missing BOOLEAN NOT NULL DEFAULT FALSE,
            metadata TEXT NULL,
            created_at BIGINT NOT NULL
        )
        """))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_cost_events_org ON cost_events(org_slug)"))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_cost_events_created ON cost_events(created_at)"))
        # PATCH0100_12: ensure columns added after migration 0007 exist
        db.execute(text("ALTER TABLE IF EXISTS cost_events ADD COLUMN IF NOT EXISTS provider VARCHAR"))
        db.execute(text("ALTER TABLE IF EXISTS cost_events ADD COLUMN IF NOT EXISTS cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0"))
        db.execute(text("ALTER TABLE IF EXISTS cost_events ADD COLUMN IF NOT EXISTS usage_missing BOOLEAN NOT NULL DEFAULT FALSE"))
        db.execute(text("ALTER TABLE IF EXISTS cost_events ADD COLUMN IF NOT EXISTS metadata TEXT"))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_cost_events_model ON cost_events(model)"))
        # PATCH0100_14: thread_members + cost_events expansion
        db.execute(text("""
        CREATE TABLE IF NOT EXISTS thread_members (
            id VARCHAR PRIMARY KEY,
            org_slug VARCHAR NOT NULL,
            thread_id VARCHAR NOT NULL,
            user_id VARCHAR NOT NULL,
            role VARCHAR NOT NULL,
            created_at BIGINT NOT NULL,
            UNIQUE(thread_id, user_id)
        )
        """))
        db.execute(text("CREATE INDEX IF NOT EXISTS ix_thread_members_org_slug ON thread_members(org_slug)"))
        db.execute(text("CREATE INDEX IF NOT EXISTS ix_thread_members_thread_id ON thread_members(thread_id)"))
        db.execute(text("CREATE INDEX IF NOT EXISTS ix_thread_members_user_id ON thread_members(user_id)"))
        # cost_events expansion
        db.execute(text("ALTER TABLE IF EXISTS cost_events ADD COLUMN IF NOT EXISTS input_cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0"))
        db.execute(text("ALTER TABLE IF EXISTS cost_events ADD COLUMN IF NOT EXISTS output_cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0"))
        db.execute(text("ALTER TABLE IF EXISTS cost_events ADD COLUMN IF NOT EXISTS total_cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0"))
        db.execute(text("ALTER TABLE IF EXISTS cost_events ADD COLUMN IF NOT EXISTS pricing_version VARCHAR NOT NULL DEFAULT '2026-02-18'"))
        db.execute(text("ALTER TABLE IF EXISTS cost_events ADD COLUMN IF NOT EXISTS pricing_snapshot TEXT"))
        db.execute(text("CREATE INDEX IF NOT EXISTS ix_cost_events_org_created ON cost_events(org_slug, created_at)"))
        # PATCH0100_14 (Pilar D): Agent voice + avatar
        db.execute(text("ALTER TABLE IF EXISTS agents ADD COLUMN IF NOT EXISTS voice_id VARCHAR"))
        db.execute(text("ALTER TABLE IF EXISTS agents ADD COLUMN IF NOT EXISTS avatar_url VARCHAR"))
        # PATCH0100_28: Summit Hardening + Legal Compliance
        db.execute(text("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS signup_code_label VARCHAR"))
        db.execute(text("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS signup_source VARCHAR"))
        db.execute(text("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS usage_tier VARCHAR DEFAULT 'summit_standard'"))
        db.execute(text("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS terms_accepted_at BIGINT"))
        db.execute(text("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS terms_version VARCHAR"))
        db.execute(text("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS marketing_consent BOOLEAN DEFAULT FALSE"))
        db.execute(text("""
        CREATE TABLE IF NOT EXISTS signup_codes (
            id VARCHAR PRIMARY KEY, org_slug VARCHAR NOT NULL, code_hash VARCHAR NOT NULL,
            label VARCHAR NOT NULL, source VARCHAR NOT NULL, expires_at BIGINT,
            max_uses INTEGER NOT NULL DEFAULT 500, used_count INTEGER NOT NULL DEFAULT 0,
            active BOOLEAN NOT NULL DEFAULT TRUE, created_at BIGINT NOT NULL, created_by VARCHAR
        )
        """))
        db.execute(text("CREATE INDEX IF NOT EXISTS ix_signup_codes_org ON signup_codes(org_slug)"))
        db.execute(text("""
        CREATE TABLE IF NOT EXISTS otp_codes (
            id VARCHAR PRIMARY KEY, user_id VARCHAR NOT NULL, code_hash VARCHAR NOT NULL,
            expires_at BIGINT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
            verified BOOLEAN NOT NULL DEFAULT FALSE, created_at BIGINT NOT NULL
        )
        """))
        db.execute(text("CREATE INDEX IF NOT EXISTS ix_otp_codes_user ON otp_codes(user_id)"))
        db.execute(text("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            id VARCHAR PRIMARY KEY, user_id VARCHAR NOT NULL, org_slug VARCHAR NOT NULL,
            login_at BIGINT NOT NULL, logout_at BIGINT, last_seen_at BIGINT NOT NULL,
            ended_reason VARCHAR, duration_seconds INTEGER, source_code_label VARCHAR,
            usage_tier VARCHAR, ip_address VARCHAR
        )
        """))
        db.execute(text("CREATE INDEX IF NOT EXISTS ix_user_sessions_user ON user_sessions(user_id)"))
        db.execute(text("""
        CREATE TABLE IF NOT EXISTS usage_events (
            id VARCHAR PRIMARY KEY, user_id VARCHAR NOT NULL, org_slug VARCHAR NOT NULL,
            event_type VARCHAR NOT NULL, tokens_used INTEGER, duration_seconds INTEGER,
            created_at BIGINT NOT NULL
        )
        """))
        db.execute(text("CREATE INDEX IF NOT EXISTS ix_usage_events_user ON usage_events(user_id)"))
        db.execute(text("""
        CREATE TABLE IF NOT EXISTS feature_flags (
            id VARCHAR PRIMARY KEY, org_slug VARCHAR NOT NULL, flag_key VARCHAR NOT NULL,
            flag_value VARCHAR NOT NULL DEFAULT 'true', updated_by VARCHAR, updated_at BIGINT NOT NULL
        )
        """))
        db.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_feature_flags_org_key ON feature_flags(org_slug, flag_key)"))
        db.execute(text("""
        CREATE TABLE IF NOT EXISTS contact_requests (
            id VARCHAR PRIMARY KEY, full_name VARCHAR NOT NULL, email VARCHAR NOT NULL,
            whatsapp VARCHAR, subject VARCHAR NOT NULL, message TEXT NOT NULL,
            privacy_request_type VARCHAR, consent_terms BOOLEAN NOT NULL,
            consent_marketing BOOLEAN NOT NULL DEFAULT FALSE, ip_address VARCHAR,
            user_agent VARCHAR, terms_version VARCHAR, status VARCHAR NOT NULL DEFAULT 'pending',
            retention_until BIGINT, created_at BIGINT NOT NULL
        )
        """))
        db.execute(text("""
        CREATE TABLE IF NOT EXISTS marketing_consents (
            id VARCHAR PRIMARY KEY, user_id VARCHAR, contact_id VARCHAR,
            channel VARCHAR NOT NULL, opt_in_date BIGINT, opt_out_date BIGINT,
            ip VARCHAR, source VARCHAR, created_at BIGINT NOT NULL
        )
        """))
        db.execute(text("""
        CREATE TABLE IF NOT EXISTS terms_acceptances (
            id VARCHAR PRIMARY KEY, user_id VARCHAR NOT NULL, terms_version VARCHAR NOT NULL,
            accepted_at BIGINT NOT NULL, ip_address VARCHAR, user_agent VARCHAR
        )
        """))
        db.execute(text("CREATE INDEX IF NOT EXISTS ix_terms_acceptances_user ON terms_acceptances(user_id)"))
        db.commit()
    except Exception as e:
        try: db.rollback()
        except Exception: pass
        try: logger.exception("SCHEMA_GUARD_FAILED")
        except Exception: pass


def get_current_user(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = decode_token(token)
        if payload.get("role") != "admin" and payload.get("approved_at") is None:
            raise HTTPException(status_code=403, detail="User pending approval")
        # Summit access window: block standard users after expiration (fail-open on errors)
        try:
            if _summit_access_expired(payload):
                raise HTTPException(status_code=403, detail="Acesso ao Summit encerrado.")
        except HTTPException:
            raise
        except Exception:
            pass
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_admin(payload: Dict[str, Any]) -> None:
    if payload.get("role") == "admin":
        return
    raise HTTPException(status_code=403, detail="Admin required")

def require_admin_key(x_admin_key: Optional[str]) -> None:
    k = admin_api_key()
    # ADMIN_API_KEY is optional; if not configured, key-auth cannot be used.
    if not k:
        raise HTTPException(status_code=401, detail="ADMIN_API_KEY not configured")
    if not x_admin_key or x_admin_key != k:
        raise HTTPException(status_code=401, detail="Invalid admin key")

def require_admin_access(
    authorization: Optional[str] = Header(default=None),
    x_admin_key: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """Allow admin via JWT (role=admin) OR via X-Admin-Key."""
    # 1) JWT path
    if authorization and authorization.lower().startswith("bearer "):
        payload = get_current_user(authorization)
        if payload.get("role") == "admin":
            return payload
        raise HTTPException(status_code=403, detail="Admin required")

    # 2) Admin key path
    require_admin_key(x_admin_key)
    return {"role": "admin", "via": "admin_key"}


# ============================================================
# PATCH0100_14 — Thread ACL helpers
# ============================================================

def _check_thread_member(db: Session, org: str, thread_id: str, user_id: str) -> Optional[ThreadMember]:
    """Return ThreadMember row if user is a member of the thread, else None."""
    return db.execute(
        select(ThreadMember).where(
            ThreadMember.org_slug == org,
            ThreadMember.thread_id == thread_id,
            ThreadMember.user_id == user_id,
        )
    ).scalar_one_or_none()

def _require_thread_member(db: Session, org: str, thread_id: str, user_id: str) -> ThreadMember:
    """Raise 403 if user is not a member of the thread."""
    m = _check_thread_member(db, org, thread_id, user_id)
    if not m:
        raise HTTPException(status_code=403, detail="Acesso negado a esta thread")
    return m

def _require_thread_admin_or_owner(db: Session, org: str, thread_id: str, user_id: str) -> ThreadMember:
    """Raise 403 if user is not owner or admin of the thread."""
    m = _require_thread_member(db, org, thread_id, user_id)
    if m.role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Somente owner/admin podem executar esta ação")
    return m

def _ensure_thread_owner(db: Session, org: str, thread_id: str, user_id: str):
    """Ensure the creator is registered as owner. Idempotent."""
    existing = _check_thread_member(db, org, thread_id, user_id)
    if existing:
        return existing
    tm = ThreadMember(
        id=new_id(), org_slug=org, thread_id=thread_id,
        user_id=user_id, role="owner", created_at=now_ts(),
    )
    db.add(tm)
    db.commit()
    return tm

def _audit_membership(db: Session, org: str, thread_id: str, actor_id: str, target_id: str, target_email: str, action_type: str, role: str):
    """Immutable audit for membership changes."""
    try:
        audit(db, org, actor_id, action_type, request_id="acl", path=f"/api/threads/{thread_id}/members",
              status_code=200, latency_ms=0,
              meta={"thread_id": thread_id, "target_user_id": target_id, "target_email": target_email, "role": role})
    except Exception:
        logger.exception("AUDIT_MEMBERSHIP_FAILED")


def db_ok() -> bool:
    """Return True if database connection is healthy."""
    if ENGINE is None:
        return False
    try:
        from sqlalchemy import text as _text
        with ENGINE.connect() as conn:
            conn.execute(_text("SELECT 1"))
        return True
    except Exception:
        return False


logger = logging.getLogger("orkio")

TEAM_AGENT_ALIASES = {
    "orkio", "orkio (ceo)",
    "chris", "chris (vp/cfo)",
    "orion", "orion (cto)",
    "aurora", "aurora (cmo)",
    "atlas", "atlas (cro)",
    "themis", "themis (legal)",
    "gaia", "gaia (accounting)",
    "hermes", "hermes (coo)",
    "selene", "selene (people)",
}



def _read_audio_bytes(resp) -> bytes:
    """Normalize OpenAI SDK TTS response to raw bytes across SDK versions."""
    try:
        if resp is None:
            return b""
        # OpenAI Python SDK v1 often returns an object with .content (bytes)
        c = getattr(resp, "content", None)
        if isinstance(c, (bytes, bytearray)):
            return bytes(c)
        # Some versions expose a .read() method
        r = getattr(resp, "read", None)
        if callable(r):
            data = r()
            if isinstance(data, (bytes, bytearray)):
                return bytes(data)
        # Some responses may be directly bytes-like
        if isinstance(resp, (bytes, bytearray)):
            return bytes(resp)
        # Fallback: try to access internal raw/body attributes
        for attr in ("data", "body", "_content"):
            v = getattr(resp, attr, None)
            if isinstance(v, (bytes, bytearray)):
                return bytes(v)
    except Exception:
        pass
    raise RuntimeError(f"Unsupported TTS response type: {type(resp)!r}")
def _sanitize_mentions(msg: str) -> str:
    """Remove @mentions to prevent cross-agent impersonation and noisy prompts."""
    if not msg:
        return ""
    out = re.sub(r"@([A-Za-z0-9_\-]{2,64})", "", msg)
    out = re.sub(r"\s+", " ", out).strip()
    return out


from starlette.background import BackgroundTask
from collections import defaultdict, deque

# PATCH0113: Summit hardening — admission control + auth rate limiting (per-process)
_stream_lock = asyncio.Lock()
_active_streams = 0
_streams_per_ip = defaultdict(int)

_auth_lock = asyncio.Lock()
_auth_attempts = defaultdict(deque)  # ip -> deque[timestamps]

stream_logger = logging.getLogger("orkio.stream")

def _client_ip(request: Request) -> str:
    xff = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    return xff or (request.client.host if request.client else "unknown")

async def _stream_acquire(request: Request) -> None:
    global _active_streams
    ip = _client_ip(request)
    try:
        max_global = int((os.getenv("MAX_STREAMS_PER_REPLICA") or os.getenv("MAX_STREAMS_GLOBAL", "200") or "200"))
    except Exception:
        max_global = 200
    try:
        max_ip = int(os.getenv("MAX_STREAMS_PER_IP", "10") or "10")
    except Exception:
        max_ip = 10

    async with _stream_lock:
        if max_global > 0 and _active_streams >= max_global:
            raise HTTPException(status_code=429, detail="STREAM_LIMIT")
        if max_ip > 0 and _streams_per_ip[ip] >= max_ip:
            raise HTTPException(status_code=429, detail="STREAM_LIMIT")
        _active_streams += 1
        _streams_per_ip[ip] += 1
        try:
            stream_logger.info(json.dumps({"event":"stream_start","active_streams":_active_streams,"ip":ip}))
        except Exception:
            pass

async def _stream_release(request: Request) -> None:
    global _active_streams
    ip = _client_ip(request)
    async with _stream_lock:
        if _active_streams > 0:
            _active_streams -= 1
        if _streams_per_ip[ip] > 0:
            _streams_per_ip[ip] -= 1
        try:
            stream_logger.info(json.dumps({"event":"stream_end","active_streams":_active_streams,"ip":ip}))
        except Exception:
            pass

def _bg_release_stream(request: Request) -> None:
    try:
        loop = asyncio.get_event_loop()
        loop.create_task(_stream_release(request))
    except Exception:
        pass

async def _auth_rate_limit(request: Request) -> None:
    ip = _client_ip(request)
    try:
        window_s = int(os.getenv("AUTH_RATE_WINDOW_SECONDS", "60") or "60")
    except Exception:
        window_s = 60
    try:
        max_hits = int(os.getenv("AUTH_RATE_MAX_PER_IP", "300") or "300")
    except Exception:
        max_hits = 300

    now = time.time()
    async with _auth_lock:
        dq = _auth_attempts[ip]
        while dq and (now - dq[0]) > window_s:
            dq.popleft()
        if max_hits > 0 and len(dq) >= max_hits:
            raise HTTPException(status_code=429, detail="AUTH_RATE_LIMIT")
        dq.append(now)

app = FastAPI(title="Orkio API", version=APP_VERSION)


def _run_with_timeout(fn, label, timeout_sec=10):
    """PATCH0100_13: Run fn in a daemon thread with a hard timeout.
    Prevents DB-related startup tasks from blocking uvicorn startup
    indefinitely when the database is unreachable."""
    result = {"done": False, "error": None}
    def _wrapper():
        try:
            fn()
            result["done"] = True
        except Exception as exc:
            result["error"] = exc
    t = _threading.Thread(target=_wrapper, daemon=True)
    t.start()
    t.join(timeout=timeout_sec)
    if t.is_alive():
        logger.warning("%s: timed out after %ds - skipping (server will start anyway)", label, timeout_sec)
    elif result["error"]:
        logger.warning("%s: failed - %s", label, result["error"])
    else:
        logger.info("%s: completed OK", label)


def validate_runtime_env() -> None:
    # JWT secret is already fail-fast in security.require_secret(), but we also normalize here.
    from .security import require_secret
    require_secret()

    env = _clean_env(os.getenv("APP_ENV", "production"), default="production").lower()
    # In production, enforce a real admin key (avoid placeholder deploys).
    if env == "production":
        k = admin_api_key()
        if not k or _is_placeholder_secret(k):
            raise RuntimeError("ADMIN_API_KEY is not configured (refuse to start in production)")
        # CORS should not be wide-open in production
        cors = cors_list()
        if cors == ["*"] or any(v == "*" for v in cors):
            raise RuntimeError("CORS_ORIGINS must be an allowlist in production (refuse to start)")

@app.on_event("startup")
def _startup_schema_guard():
    # Disabled by default: production must use Alembic migrations (set ENABLE_SCHEMA_GUARD=true to enable)
    if os.getenv("ENABLE_SCHEMA_GUARD", "false").lower() not in ("1","true","yes"):
        return
    def _do_schema_guard():
        from .db import SessionLocal
        if SessionLocal is None:
            return
        db = SessionLocal()
        try:
            ensure_schema(db)
            try:
                _try_refresh_openai_pricing(db, org=os.getenv("DEFAULT_TENANT") or "public")
            except Exception:
                pass
        finally:
            db.close()
    _run_with_timeout(_do_schema_guard, "SCHEMA_GUARD", timeout_sec=15)



app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_list(),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_origin_regex=cors_origin_regex(),
)


def rag_fallback_recent_chunks(db: Session, org: str, file_ids: List[str], top_k: int = 6) -> List[Dict[str, Any]]:
    """Fallback: when keyword retrieval yields nothing, return early chunks from the most recent file."""
    if not file_ids:
        return []
    row = db.execute(
        select(File.id).where(File.org_slug == org, File.id.in_(file_ids)).order_by(File.created_at.desc()).limit(1)
    ).first()
    if not row or not row[0]:
        return []
    fid = row[0]
    chunks = db.execute(
        select(FileChunk).where(FileChunk.org_slug == org, FileChunk.file_id == fid).order_by(FileChunk.idx.asc()).limit(top_k)
    ).scalars().all()
    if not chunks:
        return []
    f = db.get(File, fid)
    filename = f.filename if f else fid
    out: List[Dict[str, Any]] = []
    for c in chunks:
        out.append({"file_id": fid, "filename": filename, "content": c.content, "score": 0.0, "idx": getattr(c, "idx", None), "fallback": True})
    return out


# --- Railway / Edge hardening: always answer CORS preflight ---
# Some proxies may return 502 if OPTIONS is not answered quickly.
# CORSMiddleware should handle it, but this catch-all guarantees a fast 204.
from fastapi import Response as _Resp

@app.options('/{path:path}')
async def _preflight(path: str):
    return _Resp(status_code=204)


@app.middleware("http")
async def request_id_mw(request: Request, call_next):
    rid = request.headers.get("x-request-id") or new_id()
    start = time.time()
    try:
        resp = await call_next(request)
    finally:
        pass
    resp.headers["x-request-id"] = rid
    resp.headers["x-orkio-version"] = APP_VERSION
    return resp

@app.on_event("startup")
def _startup():
    # Hard safety gate: JWT secret must exist.
    require_secret()

    # DB is optional for smoke tests, but if configured we ensure tables exist.
    if ENGINE is not None:
        def _do_create_all():
            from .db import Base  # type: ignore
            Base.metadata.create_all(bind=ENGINE)
        _run_with_timeout(_do_create_all, "CREATE_ALL", timeout_sec=15)

        # Auto-seed Summit codes to avoid manual DB edits in Railway UI.
        def _do_seed_summit_codes():
            from .db import SessionLocal  # type: ignore
            if SessionLocal is None:
                return
            db = SessionLocal()
            try:
                _seed_default_summit_codes(db, org=default_tenant() or "public")
            finally:
                db.close()
        _run_with_timeout(_do_seed_summit_codes, "SEED_SUMMIT_CODES", timeout_sec=15)

        # Bootstrap default tenant state (core agents + admin sync)
        def _do_bootstrap_default_org():
            from .db import SessionLocal  # type: ignore
            if SessionLocal is None:
                return
            db = SessionLocal()
            try:
                bootstrap_default_org_state(db, default_tenant() or "public")
            finally:
                db.close()
        _run_with_timeout(_do_bootstrap_default_org, "BOOTSTRAP_DEFAULT_ORG", timeout_sec=15)

    # ADMIN_API_KEY is optional. If not set, admin access is granted only via admin-role JWT.
    # (ADMIN_EMAILS controls who becomes admin on register/login.)
    return None


@app.get("/")
def root():
    # Railway default healthcheck may hit "/"
    return {"status": "ok", "service": "orkio-api", "version": APP_VERSION}

@app.get("/health")
def health_root():
    return {"status": "ok", "service": "orkio-api", "version": APP_VERSION}


@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    start = time.time()
    path = request.url.path
    # Skip noisy endpoints
    if path.startswith("/api/health") or path in ("/", "/health"):
        return await call_next(request)
    response = await call_next(request)
    # Best-effort audit (never block the response)
    try:
        if path.startswith("/api/") and SessionLocal is not None:
            latency_ms = int((time.time() - start) * 1000)
            status_code = int(getattr(response, "status_code", 0) or 0)
            rid = ensure_request_id(request)
            org = get_org(request.headers.get("x-org-slug"))
            uid = None
            auth = request.headers.get("authorization")
            if auth:
                try:
                    token = auth.split(" ", 1)[1] if " " in auth else auth
                    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                    uid = payload.get("sub")
                except Exception:
                    uid = None
            meta = {"method": request.method}
            _db = SessionLocal()
            try:
                audit(db=_db, org_slug=org, user_id=uid, action="http.request", request_id=rid, path=path, status_code=status_code, latency_ms=latency_ms, meta=meta)
            finally:
                _db.close()
    except Exception:
        pass
    return response

# ================================
# PATCH0100_8 — Landing Leads + Public Orkio Chat (no auth)
# ================================

class LeadIn(BaseModel):
    name: str
    email: str
    company: str
    role: Optional[str] = None
    segment: Optional[str] = None
    source: Optional[str] = "qr"

class LeadOut(BaseModel):
    ok: bool = True
    lead_id: str
    created_at: Any = None

@app.post("/api/leads", response_model=LeadOut)
def create_lead(inp: LeadIn, x_org_slug: Optional[str] = Header(default=None), request: Request = None, db: Session = Depends(get_db)):
    # public endpoint: org from header/default only (no JWT)
    org = get_org(x_org_slug)
    lead_id = new_id()
    ua = None
    try:
        ua = (request.headers.get("user-agent") if request else None)
    except Exception:
        ua = None
    lead = Lead(
        id=lead_id,
        org_slug=org,
        name=inp.name.strip(),
        email=inp.email.strip().lower(),
        company=inp.company.strip(),
        role=(inp.role.strip() if inp.role else None),
        segment=(inp.segment.strip() if inp.segment else None),
        source=(inp.source or "qr"),
        ua=ua,
        created_at=now_ts(),
    )
    db.add(lead)
    db.commit()
    try:
        audit(db, org, None, "lead.created", request_id="lead", path="/api/leads", status_code=200, latency_ms=0, meta={"lead_id": lead_id, "email": lead.email, "company": lead.company})
    except Exception:
        pass
    return {"ok": True, "lead_id": lead_id, "created_at": lead.created_at if lead.created_at else now_ts()}

class PublicChatIn(BaseModel):
    lead_id: str
    message: str
    thread_id: Optional[str] = None

class PublicChatOut(BaseModel):
    ok: bool = True
    thread_id: str
    reply: str
    meta: Optional[Dict[str, Any]] = None

@app.post("/api/public/chat", response_model=PublicChatOut)
def public_chat(inp: PublicChatIn, x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)

    # Ensure thread per lead
    tid = inp.thread_id
    if not tid:
        t = Thread(id=new_id(), org_slug=org, title=f"Lead {inp.lead_id}", created_at=now_ts())
        db.add(t)
        db.commit()
        tid = t.id

    # Store user message
    m_user = Message(
        id=new_id(),
        org_slug=org,
        thread_id=tid,
        role="user",
        content=(inp.message or "").strip(),
        created_at=now_ts(),
        agent_name="visitor",
    )
    db.add(m_user)
    db.commit()

    # Orkio CEO agent: pick default agent (by is_default or name match)
    orkio = db.execute(select(Agent).where(Agent.org_slug == org).order_by(Agent.is_default.desc(), Agent.created_at.asc())).scalars().first()
    if not orkio:
        ensure_core_agents(db, org)
        orkio = db.execute(select(Agent).where(Agent.org_slug == org).order_by(Agent.is_default.desc(), Agent.created_at.asc())).scalars().first()

    # Build a crisp system prompt (safe, salesy, short)
    system = (
        "You are Orkio, 'the CEO of CEOs'. "
        "You speak with confidence and clarity for enterprise decision-makers. "
        "Ask one sharp question at a time. "
        "Explain Orkio as enterprise-grade governed autonomy: evidence, governance, control. "
        "Never claim to have deployed inside their company. "
        "Always steer toward booking a demo."
    )

    user_msg = (inp.message or "").strip()

    # Call model (reuse internal openai helper if available) — fallback to deterministic reply
    reply_text = None
    try:
        # Use the same engine used by authenticated /api/chat
        reply_text = run_llm(db, org, orkio, system, user_msg, thread_id=tid, lead_id=inp.lead_id)  # may not exist; guarded
    except Exception:
        reply_text = None

    if not reply_text:
        # Deterministic fallback
        reply_text = (
            "I’m Orkio — the CEO of CEOs. "
            "To make this concrete: what is the #1 outcome you want AI to deliver in your organization — safely and auditable?"
        )

    # Store assistant message
    m_bot = Message(
        id=new_id(),
        org_slug=org,
        thread_id=tid,
        role="assistant",
        content=reply_text,
        created_at=now_ts(),
        agent_id=(orkio.id if orkio else None),
        agent_name=(orkio.name if orkio else "Orkio"),
    )
    db.add(m_bot)
    db.commit()
    # Record cost event (public chat) — estimated tokens + PricingRegistry
    try:
        provider = "openai"
        model_name = (os.getenv("OPENAI_MODEL", "gpt-4o-mini") or "gpt-4o-mini").strip()
        prompt_t = estimate_tokens(system) + estimate_tokens(user_msg)
        completion_t = estimate_tokens(reply_text or "")
        total_t = int(prompt_t or 0) + int(completion_t or 0)
        usage_missing = True  # public chat may not have real usage
        try:
            registry = get_pricing_registry()
            cost_usd, pricing_meta = registry.compute_cost_usd(provider, model_name, prompt_t, completion_t)
        except Exception:
            logger.exception("COST_PRICING_FAILED_PUBLIC")
            cost_usd, pricing_meta = 0.0, {"pricing_source": "error"}

        db.add(CostEvent(
            id=new_id(),
            org_slug=org,
            user_id=None,
            thread_id=tid,
            message_id=m_bot.id,
            agent_id=(orkio.id if orkio else None),
            provider=provider,
            model=model_name,
            prompt_tokens=prompt_t,
            completion_tokens=completion_t,
            total_tokens=total_t,
            cost_usd=cost_usd,
            usage_missing=usage_missing,
            meta=json.dumps({"public": True, "lead_id": inp.lead_id, **(pricing_meta or {})}, ensure_ascii=False),
            created_at=now_ts(),
        ))
        db.commit()
        try:
            audit(db, org, None, "cost.event.recorded.public", request_id="cost_public", path="/api/public/chat", status_code=200, latency_ms=0,
                  meta={"thread_id": tid, "agent_id": (orkio.id if orkio else None), "provider": provider, "model": model_name, "prompt_tokens": prompt_t, "completion_tokens": completion_t, "total_tokens": total_t, "cost_usd": float(cost_usd), **(pricing_meta or {})})
        except Exception:
            logger.exception("AUDIT_COST_PUBLIC_FAILED")
    except Exception:
        logger.exception("COST_EVENT_PERSIST_PUBLIC_FAILED")

    try:
        audit(db, org, None, "public.chat", request_id="publicchat", path="/api/public/chat", status_code=200, latency_ms=0, meta={"lead_id": inp.lead_id, "thread_id": tid})
    except Exception:
        pass

    return {"ok": True, "thread_id": tid, "reply": reply_text, "meta": {"agent": (orkio.name if orkio else "Orkio")}}



@app.get("/api/health")
def health():
    return {"status": "ok", "db": "ok" if db_ok() else "down", "version": APP_VERSION, "rag": RAG_MODE}


@app.get("/api/meta")
def meta():
    return {"status": "ok", "patch": patch_id()}

@app.get("/api/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/api/health/db")
def health_db(db: Session = Depends(get_db)):
    try:
        db.execute(text("select 1"))
        return {"ok": True, "db": "ok"}
    except OperationalError as e:
        # Surface a clear error instead of generic 500
        raise HTTPException(status_code=503, detail=f"DB unavailable: {str(e).splitlines()[0]}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB check failed: {str(e).splitlines()[0]}")

# ═══════════════════════════════════════════════════════════════════════
# PATCH0100_28 — Summit helper functions
# ═══════════════════════════════════════════════════════════════════════

def _verify_turnstile(token: Optional[str], ip: str = "unknown") -> bool:
    """Verify Cloudflare Turnstile token. Returns True if valid or if Turnstile is not configured."""
    if not TURNSTILE_SECRET:
        return True  # Turnstile not configured, skip
    if not token:
        return False
    try:
        data = json.dumps({"secret": TURNSTILE_SECRET, "response": token, "remoteip": ip}).encode()
        req = _urllib_request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=data, headers={"Content-Type": "application/json"}, method="POST"
        )
        ctx = _ssl.create_default_context()
        with _urllib_request.urlopen(req, context=ctx, timeout=5) as resp:
            result = json.loads(resp.read().decode())
            return result.get("success", False)
    except Exception:
        logger.exception("TURNSTILE_VERIFY_FAILED")
        return False  # fail-closed: if Turnstile is down, block registration

def _validate_access_code(db: Session, org: str, code: str) -> Optional[SignupCode]:
    """Validate and consume an access code with row-level locking to prevent race conditions."""
    normalized = (code or "").strip().upper()
    if not normalized:
        return None
    code_hash = hashlib.sha256(normalized.encode()).hexdigest()
    sc = db.execute(
        select(SignupCode)
        .where(
            SignupCode.org_slug == org,
            SignupCode.code_hash == code_hash,
            SignupCode.active == True,
        )
        .with_for_update()
    ).scalar_one_or_none()
    if not sc:
        return None
    if sc.expires_at and sc.expires_at < now_ts():
        return None
    current_used = int(sc.used_count or 0)
    max_uses = int(sc.max_uses or 0)
    if max_uses > 0 and current_used >= max_uses:
        return None
    sc.used_count = current_used + 1
    db.add(sc)
    return sc

def _rate_limit_check(lock, calls_dict, key, max_per_min, window=60):
    """Generic in-memory rate limiter. Returns True if allowed, False if over limit."""
    now = time.time()
    with lock:
        calls = calls_dict.get(key, [])
        calls = [t for t in calls if now - t < window]
        if len(calls) >= max_per_min:
            calls_dict[key] = calls
            return False
        calls.append(now)
        calls_dict[key] = calls
        # Eviction
        if len(calls_dict) > 1000:
            stale = [k for k, ts in calls_dict.items() if not ts or (now - max(ts)) > 120]
            for k in stale:
                del calls_dict[k]
        return True

def _create_user_session(db: Session, user_id: str, org: str, ip: str = "unknown", code_label: str = None, tier: str = None):
    """Create a user_session record for presence tracking."""
    try:
        ts = now_ts()
        sess = UserSession(
            id=new_id(), user_id=user_id, org_slug=org,
            login_at=ts, last_seen_at=ts,
            source_code_label=code_label, usage_tier=tier, ip_address=ip,
        )
        db.add(sess)
        db.commit()
        return sess.id
    except Exception:
        logger.exception("USER_SESSION_CREATE_FAILED")
        try: db.rollback()
        except: pass
        return None

def _send_otp_email(to_email: str, otp_code: str):
    """Send OTP code via SMTP. Best-effort, never blocks auth flow."""
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "").strip()
    smtp_pass = os.getenv("SMTP_PASS", "").strip()
    smtp_from = os.getenv("SMTP_FROM", smtp_user).strip()
    if not smtp_host or not smtp_user:
        logger.warning("SMTP not configured, OTP email not sent")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"Orkio — Seu c\u00f3digo de verifica\u00e7\u00e3o: {otp_code}"
        msg["From"] = smtp_from
        msg["To"] = to_email
        html = f"""
        <div style="font-family:system-ui;max-width:480px;margin:0 auto;padding:24px">
            <h2 style="color:#111">Orkio</h2>
            <p>Seu c\u00f3digo de verifica\u00e7\u00e3o \u00e9:</p>
            <div style="font-size:32px;font-weight:bold;letter-spacing:8px;padding:16px;background:#f5f5f5;border-radius:8px;text-align:center">{otp_code}</div>
            <p style="color:#666;font-size:13px;margin-top:16px">V\u00e1lido por 10 minutos. N\u00e3o compartilhe este c\u00f3digo.</p>
        </div>
        """
        msg.attach(MIMEText(html, "html", "utf-8"))
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
            s.starttls()
            s.login(smtp_user, smtp_pass)
            s.sendmail(smtp_from, [to_email], msg.as_string())
        return True
    except Exception:
        logger.exception("OTP_EMAIL_SEND_FAILED")
        return False

def _get_feature_flag(db: Session, org: str, key: str) -> Optional[str]:
    """Get feature flag value. Returns None if not set."""
    try:
        ff = db.execute(
            select(FeatureFlag).where(FeatureFlag.org_slug == org, FeatureFlag.flag_key == key)
        ).scalar_one_or_none()
        return ff.flag_value if ff else None
    except Exception:
        logger.exception("FEATURE_FLAG_READ_FAILED org=%s key=%s", org, key)
        return None


@app.post("/api/auth/register", response_model=TokenOut)
def register(inp: RegisterIn, request: Request = None, x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    ip = (request.client.host if request and request.client else "unknown")
    org = (get_org(x_org_slug) if x_org_slug else (inp.tenant or default_tenant())).strip()
    email = inp.email.lower().strip()

    # Structural super-admin rule:
    # - configured ADMIN_EMAILS always become admin
    # - if no admin exists in the org yet, first user becomes admin
    should_be_admin = _should_promote_to_admin(db, org, email)

    # PATCH0100_28: Rate limit registration
    if not _rate_limit_check(_rl_register_lock, _rl_register_calls, ip, _REGISTER_MAX_PER_MINUTE):
        raise HTTPException(status_code=429, detail="Muitas tentativas de registro. Aguarde 1 minuto.")

    # PATCH0215: Turnstile is enforced only when TURNSTILE_SECRET is configured
    if TURNSTILE_SECRET:
        if not _verify_turnstile(inp.turnstile_token, ip):
            logger.warning("REGISTER_DENIED reason=turnstile_failed ip=%s org=%s", ip, org)
            raise HTTPException(status_code=403, detail="Verificação de segurança falhou. Tente novamente.")

    # PATCH0100_28: Access code validation (Summit mode)
    signup_code_label = None
    signup_source = None
    usage_tier = "summit_standard"

    if SUMMIT_MODE and not should_be_admin:
        if not inp.access_code:
            logger.warning("REGISTER_DENIED reason=missing_code ip=%s org=%s", ip, org)
            raise HTTPException(status_code=403, detail="Código de acesso obrigatório no modo Summit.")
        sc = _validate_access_code(db, org, inp.access_code)
        if not sc:
            logger.warning("REGISTER_DENIED reason=invalid_code ip=%s org=%s", ip, org)
            raise HTTPException(status_code=403, detail="Código de acesso inválido, expirado ou esgotado.")
        signup_code_label = sc.label
        signup_source = sc.source

        if now_ts() > int(SUMMIT_EXPIRES_AT):
            raise HTTPException(status_code=403, detail="Período de acesso ao Summit encerrado.")

        source_key = (sc.source or "").strip().lower()
        if source_key == "investor":
            usage_tier = "summit_vip"
        elif source_key == "summit_user":
            usage_tier = "summit_standard"

    elif inp.access_code and not should_be_admin:
        sc = _validate_access_code(db, org, inp.access_code)
        if sc:
            signup_code_label = sc.label
            signup_source = sc.source

    if SUMMIT_MODE and not inp.accept_terms and not should_be_admin:
        logger.warning("REGISTER_DENIED reason=terms_not_accepted ip=%s org=%s", ip, org)
        raise HTTPException(status_code=400, detail="Você precisa aceitar os Termos de Uso para continuar.")

    role = "admin" if should_be_admin else "user"

    existing = db.execute(select(User).where(User.org_slug == org, User.email == email)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    salt = new_salt()
    pw_hash = pbkdf2_hash(inp.password, salt)
    u = User(
        id=new_id(), org_slug=org, email=email, name=inp.name.strip(),
        role=role, salt=salt, pw_hash=pw_hash, created_at=now_ts(),
        approved_at=(now_ts() if should_be_admin else None),
        signup_code_label=signup_code_label, signup_source=signup_source,
        usage_tier=usage_tier,
        terms_accepted_at=(now_ts() if inp.accept_terms else None),
        terms_version=(TERMS_VERSION if inp.accept_terms else None),
        marketing_consent=inp.marketing_consent,
    )
    db.add(u)
    db.commit()

    if inp.accept_terms:
        try:
            db.add(TermsAcceptance(
                id=new_id(), user_id=u.id, terms_version=TERMS_VERSION,
                accepted_at=now_ts(), ip_address=ip,
                user_agent=(request.headers.get("user-agent", "") if request else None),
            ))
            db.commit()
        except Exception:
            logger.exception("TERMS_ACCEPTANCE_RECORD_FAILED")

    if inp.marketing_consent:
        try:
            db.add(MarketingConsent(
                id=new_id(), user_id=u.id, channel="email",
                opt_in_date=now_ts(), ip=ip, source="register", created_at=now_ts(),
            ))
            db.commit()
        except Exception:
            logger.exception("MARKETING_CONSENT_RECORD_FAILED")

    try:
        audit(
            db, org, u.id, "user.register",
            request_id="reg", path="/api/auth/register", status_code=200, latency_ms=0,
            meta={
                "email": u.email,
                "signup_code_label": signup_code_label,
                "signup_source": signup_source,
                "usage_tier": usage_tier,
                "summit_mode": SUMMIT_MODE,
                "role": u.role,
            }
        )
    except Exception:
        pass

    try:
        if _ensure_admin_user_state(u):
            db.add(u)
            db.commit()
    except Exception:
        logger.exception("ADMIN_SYNC_FAILED register user_id=%s", getattr(u, "id", None))

    token = mint_token({
        "sub": u.id, "org": org, "email": u.email, "name": u.name,
        "role": u.role, "approved_at": getattr(u, "approved_at", None), "usage_tier": usage_tier
    })

    _create_user_session(db, u.id, org, ip, signup_code_label, usage_tier)
    return {"access_token": token, "token_type": "bearer", "user": {"id": u.id, "email": u.email, "name": u.name, "role": u.role, "approved_at": getattr(u, "approved_at", None), "usage_tier": usage_tier}}

@app.post("/api/auth/login")
def login(inp: LoginIn, x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db), request: Request = None):
    ip = (request.client.host if request and request.client else "unknown")
    # F-10 FIX: rate limit brute-force
    if not _rate_limit_check(_login_rl_lock, _login_rl_calls, ip, _LOGIN_MAX_PER_MINUTE):
        raise HTTPException(status_code=429, detail="Muitas tentativas de login. Aguarde 1 minuto.")

    org = (get_org(x_org_slug) if x_org_slug else (inp.tenant or default_tenant())).strip()
    email = inp.email.lower().strip()
    u = db.execute(select(User).where(User.org_slug == org, User.email == email)).scalar_one_or_none()
    if not u or not verify_password(inp.password, u.salt, u.pw_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # PATCH0216C: structural admin sync (role + approved_at) for configured emails
    try:
        if _ensure_admin_user_state(u):
            db.add(u)
            db.commit()
    except Exception:
        logger.exception("ADMIN_ELEVATE_FAILED")


    usage_tier = getattr(u, "usage_tier", "summit_standard") or "summit_standard"

    # Summit access window enforcement (standard users only)
    if _summit_access_expired({"role": u.role, "usage_tier": usage_tier}):
        raise HTTPException(status_code=403, detail="Acesso ao Summit encerrado.")

    # Summit 2FA: password + OTP (OTP is issued only after password verification)
    require_otp = SUMMIT_MODE and (os.getenv("SUMMIT_REQUIRE_OTP", "true").lower() in ("1", "true", "yes"))
    otp_for_admins = (os.getenv("SUMMIT_OTP_FOR_ADMINS", "false").lower() in ("1", "true", "yes"))
    if require_otp and (u.role != "admin" or otp_for_admins):
        try:
            import random
            otp_plain = f"{random.randint(0, 999999):06d}"
            otp_hash = hashlib.sha256(otp_plain.encode()).hexdigest()
            expires = now_ts() + 600  # 10 minutes

            # Invalidate old OTPs
            try:
                db.execute(text("UPDATE otp_codes SET verified = TRUE WHERE user_id = :uid AND verified = FALSE"), {"uid": u.id})
                db.commit()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass

            db.add(OtpCode(
                id=new_id(), user_id=u.id, code_hash=otp_hash,
                expires_at=expires, created_at=now_ts(),
            ))
            db.commit()

            # Send email (best-effort)
            _send_otp_email(email, otp_plain)

            try:
                audit(db, org, u.id, "login.otp_issued", request_id="login", path="/api/auth/login",
                      status_code=200, latency_ms=0, meta={"email": email, "summit_mode": True})
            except Exception:
                pass
        except Exception:
            logger.exception("LOGIN_OTP_ISSUE_FAILED")
            # Fail-open: allow login without OTP only if explicitly configured
            if os.getenv("SUMMIT_OTP_FAIL_OPEN", "false").lower() not in ("1", "true", "yes"):
                raise HTTPException(status_code=500, detail="Falha ao enviar código de verificação. Tente novamente.")
        return {"pending_otp": True, "message": "Enviamos um código de verificação para seu e-mail. Digite-o para continuar.", "email": email, "tenant": org}

    token = mint_token({"sub": u.id, "org": org, "email": u.email, "name": u.name, "role": u.role, "approved_at": getattr(u, "approved_at", None), "usage_tier": usage_tier})

    # Create user session for presence tracking
    _create_user_session(db, u.id, org, ip, getattr(u, "signup_code_label", None), usage_tier)

    return {"access_token": token, "token_type": "bearer", "user": {"id": u.id, "email": u.email, "name": u.name, "role": u.role, "approved_at": getattr(u, "approved_at", None), "usage_tier": usage_tier}}

@app.get("/api/threads")
def list_threads(x_org_slug: Optional[str] = Header(default=None), user=Depends(get_current_user), db: Session = Depends(get_db)):
    org = get_request_org(user, x_org_slug)
    uid = user.get("sub")

    # Ensure core agents exist (solo-supervised defaults)
    ensure_core_agents(db, org)

    # PATCH0100_14: ACL — only show threads where user is a member
    # Admin users can see all threads
    if user.get("role") == "admin":
        rows = db.execute(select(Thread).where(Thread.org_slug == org).order_by(Thread.created_at.desc())).scalars().all()
    else:
        member_tids = db.execute(
            select(ThreadMember.thread_id).where(ThreadMember.org_slug == org, ThreadMember.user_id == uid)
        ).scalars().all()
        if member_tids:
            rows = db.execute(select(Thread).where(Thread.org_slug == org, Thread.id.in_(member_tids)).order_by(Thread.created_at.desc())).scalars().all()
        else:
            rows = []
    return [{"id": t.id, "title": t.title, "created_at": t.created_at} for t in rows]

@app.post("/api/threads")
def create_thread(inp: ThreadIn, x_org_slug: Optional[str] = Header(default=None), user=Depends(get_current_user), db: Session = Depends(get_db)):
    org = get_request_org(user, x_org_slug)
    t = Thread(id=new_id(), org_slug=org, title=inp.title, created_at=now_ts())
    db.add(t)
    db.commit()
    # PATCH0100_14: creator becomes owner
    _ensure_thread_owner(db, org, t.id, user.get("sub"))
    return {"id": t.id, "title": t.title, "created_at": t.created_at}

@app.patch("/api/threads/{thread_id}")
def rename_thread(thread_id: str, inp: ThreadUpdate, x_org_slug: Optional[str] = Header(default=None), user=Depends(get_current_user), db: Session = Depends(get_db)):
    org = get_request_org(user, x_org_slug)
    # PATCH0100_14: ACL check
    _require_thread_member(db, org, thread_id, user.get("sub"))
    t = db.execute(select(Thread).where(Thread.org_slug == org, Thread.id == thread_id)).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Thread not found")
    t.title = inp.title.strip()
    db.add(t)
    db.commit()
    return {"id": t.id, "title": t.title, "created_at": t.created_at}
@app.delete("/api/threads/{thread_id}")
def delete_thread(thread_id: str, x_org_slug: Optional[str] = Header(default=None), user=Depends(get_current_user), db: Session = Depends(get_db)):
    org = get_request_org(user, x_org_slug)
    # PATCH0100_14: only owner/admin can delete
    _require_thread_admin_or_owner(db, org, thread_id, user.get("sub"))
    t = db.execute(select(Thread).where(Thread.org_slug == org, Thread.id == thread_id)).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Thread not found")
    db.execute(delete(Message).where(Message.org_slug == org, Message.thread_id == thread_id))
    db.execute(delete(File).where(File.org_slug == org, File.thread_id == thread_id))
    db.execute(delete(ThreadMember).where(ThreadMember.org_slug == org, ThreadMember.thread_id == thread_id))
    db.execute(delete(Thread).where(Thread.org_slug == org, Thread.id == thread_id))
    db.commit()
    try:
        audit(db, org, user.get("sub"), "chat.thread.deleted", request_id="thread", path="/api/threads/{thread_id}", status_code=200, latency_ms=0, meta={"thread_id": thread_id})
    except Exception:
        pass
    return {"ok": True}



@app.get("/api/messages")
def list_messages(thread_id: str, x_org_slug: Optional[str] = Header(default=None), user=Depends(get_current_user), db: Session = Depends(get_db)):
    org = get_request_org(user, x_org_slug)
    # PATCH0100_14: ACL check (admin bypass)
    if user.get("role") != "admin":
        _require_thread_member(db, org, thread_id, user.get("sub"))
    rows = db.execute(select(Message).where(Message.org_slug == org, Message.thread_id == thread_id).order_by(Message.created_at.asc())).scalars().all()
    return [{
        "id": m.id,
        "role": m.role,
        "content": m.content,
        "created_at": m.created_at,
        "user_id": getattr(m, "user_id", None),
        "user_name": getattr(m, "user_name", None),
        "agent_id": getattr(m, "agent_id", None),
        "agent_name": getattr(m, "agent_name", None),
    } for m in rows]


def _openai_answer(
    user_message: str,
    context_chunks: List[Dict[str, Any]],
    history: Optional[List[Dict[str, str]]] = None,
    system_prompt: Optional[str] = None,
    model_override: Optional[str] = None,
    temperature: Optional[float] = None,
) -> Optional[Dict[str, Any]]:
    """Answer using OpenAI Chat Completions, with optional thread history.

    Returns dict:
      {text, usage, model} on success
      {code, error, message} on known failures (SERVER_BUSY, TIMEOUT, LLM_ERROR)
      None only if an unexpected internal failure occurs before classification.
    """
    key = _clean_env(os.getenv("OPENAI_API_KEY", ""), default="").strip()
    model = (
        _clean_env(model_override, default="").strip()
        or _clean_env(os.getenv("OPENAI_MODEL", ""), default="").strip()
        or _clean_env(os.getenv("DEFAULT_CHAT_MODEL", ""), default="").strip()
        or "gpt-4o-mini"
    )

    if not key:
        return {
            "code": "LLM_ERROR",
            "error": "missing_openai_key",
            "message": "OPENAI_API_KEY ausente",
            "text": "",
            "usage": None,
            "model": model,
        }

    if OpenAI is None:
        return {
            "code": "LLM_ERROR",
            "error": "openai_client_unavailable",
            "message": _OPENAI_IMPORT_ERROR or "biblioteca openai indisponível",
            "text": "",
            "usage": None,
            "model": model,
        }

    try:
        timeout_s = float(
            _clean_env(os.getenv("OPENAI_TIMEOUT", ""), default="")
            or _clean_env(os.getenv("LLM_TIMEOUT", ""), default="")
            or "45"
        )
    except Exception:
        timeout_s = 45.0

    try:
        client = OpenAI(api_key=key, timeout=timeout_s)
    except Exception as e:
        msg = str(e) or "openai_client_init_failed"
        return {
            "code": "LLM_ERROR",
            "error": "openai_client_init_failed",
            "message": msg,
            "text": "",
            "usage": None,
            "model": model,
        }

    # Build context string (RAG)
    ctx = ""
    for c in (context_chunks or [])[:6]:
        fn = c.get("filename") or c.get("file_id")
        ctx += f"\n\n[Arquivo: {fn}]\n{c.get('content','')}"

    # PATCH0111: hard cap for RAG context to reduce cost explosion
    try:
        max_ctx_chars = int(os.getenv("MAX_CTX_CHARS", "12000") or "12000")
    except Exception:
        max_ctx_chars = 12000
    if max_ctx_chars and len(ctx) > max_ctx_chars:
        ctx = ctx[:max_ctx_chars] + "\n\n[...contexto truncado...]"

    system = system_prompt or "Você é o Orkio. Responda de forma objetiva. Use o contexto de documentos quando disponível."

    messages: List[Dict[str, str]] = []

    # PATCH0111: cap history by characters
    try:
        max_history_chars = int(os.getenv("MAX_HISTORY_CHARS", "8000") or "8000")
    except Exception:
        max_history_chars = 8000
    history_chars = 0
    messages.append({"role": "system", "content": system})

    # Provide RAG context in a separate system message (keeps user message clean)
    if ctx.strip():
        messages.append({"role": "system", "content": f"Contexto de documentos (evidências):\n{ctx}"})

    # Add conversation history (if any)
    if history:
        for h in history[-24:]:
            r = (h.get("role") or "").strip()
            c = (h.get("content") or "").strip()
            if not r or not c:
                continue
            if r not in ("user", "assistant", "system"):
                r = "user"
            if max_history_chars and (history_chars + len(c)) > max_history_chars:
                break
            history_chars += len(c)
            messages.append({"role": r, "content": c})

    # Finally, current user message
    messages.append({"role": "user", "content": user_message})

    try:
        kwargs: Dict[str, Any] = {"model": model, "messages": messages}
        if temperature is not None:
            kwargs["temperature"] = temperature

        fallback_model = (
            _clean_env(os.getenv("OPENAI_FALLBACK_MODEL", ""), default="").strip()
            or "gpt-4o-mini"
        )
        last_exc = None
        used_model = model
        for attempt_model in [model, fallback_model]:
            try:
                used_model = attempt_model
                kwargs["model"] = attempt_model
                r = client.chat.completions.create(**kwargs)
                answer_text = ""
                try:
                    answer_text = ((r.choices or [])[0].message.content or "").strip()
                except Exception:
                    answer_text = ""
                return {
                    "text": answer_text,
                    "usage": getattr(r, "usage", None),
                    "model": used_model,
                }
            except Exception as inner:
                last_exc = inner
                continue
        raise last_exc or RuntimeError("LLM_ERROR")
    except Exception as e:
        msg = str(e) or "LLM_ERROR"
        low = msg.lower()
        code = "LLM_ERROR"

        if (
            "rate limit" in low
            or "429" in low
            or "overload" in low
            or "overloaded" in low
            or "server is busy" in low
            or "too many requests" in low
            or "quota" in low
        ):
            code = "SERVER_BUSY"
        elif "timeout" in low or "timed out" in low:
            code = "TIMEOUT"

        return {
            "code": code,
            "error": msg,
            "message": msg,
            "text": "",
            "usage": None,
            "model": model,
        }







# ─── STAB: helpers extraídos do /api/chat (god-function refactor) ───────────────

def _resolve_org(user: Dict[str, Any], x_org_slug: Optional[str]) -> str:
    """Wrapper semântico — tenant sempre vem do JWT."""
    return get_request_org(user, x_org_slug)


def _select_target_agents(
    db: Session,
    org: str,
    inp,
    alias_to_agent: Dict[str, Any],
    mention_tokens: List[str],
    has_team: bool,
) -> List[Any]:
    """Seleciona agentes-alvo de forma determinística.
    Prioridade: has_team > mentions explícitos > agent_id > default.
    Nunca retorna lista vazia se houver pelo menos 1 agente cadastrado.
    """
    target: List[Any] = []

    if has_team:
        # group mode baseado nos aliases realmente existentes na org
        seen_ids = set()
        preferred_order = [
            "orkio", "orkio (ceo)", "chris", "chris (vp/cfo)", "orion", "orion (cto)",
            "aurora", "aurora (cmo)", "atlas", "atlas (cro)", "themis", "themis (legal)",
            "gaia", "gaia (accounting)", "hermes", "hermes (coo)", "selene", "selene (people)",
        ]
        for alias in preferred_order:
            a = alias_to_agent.get(alias)
            if a and a.id not in seen_ids:
                target.append(a)
                seen_ids.add(a.id)
    elif mention_tokens:
        for tok in mention_tokens:
            a = alias_to_agent.get(tok.strip().lower())
            if a and a.id not in {x.id for x in target}:
                target.append(a)

    # de-dup preserve order
    seen: set = set()
    deduped: List[Any] = []
    for a in target:
        if a and a.id not in seen:
            deduped.append(a)
            seen.add(a.id)
    target = deduped

    if not target:
        agent = None
        if inp.agent_id:
            agent = db.execute(select(Agent).where(Agent.org_slug == org, Agent.id == inp.agent_id)).scalar_one_or_none()
            if not agent:
                raise HTTPException(status_code=404, detail="Agent not found")
        else:
            agent = db.execute(select(Agent).where(Agent.org_slug == org, Agent.is_default == True)).scalar_one_or_none()
        if agent:
            target = [agent]

    return target


def _build_agent_prompt(agent, inp_message: str, has_team: bool, mention_tokens: List[str]) -> str:
    """Monta user_msg com role-injection para evitar cross-agent impersonation."""
    if agent and has_team:
        clean = _sanitize_mentions(inp_message or "")
        return (
            f"Você é {agent.name}. Responda APENAS como {agent.name}. "
            "Não fale em nome de outros agentes, não cite falas de outros agentes como se fossem suas. "
            "Se precisar, apenas dê sua contribuição dentro do seu papel.\n\n"
            f"Mensagem do usuário (sanitizada): {clean}"
        )
    if agent and mention_tokens:
        return (
            f"Você foi acionado como [@{agent.name}] em um chat multi-agente. "
            f"Responda de forma objetiva e útil dentro do seu papel.\n\n"
            f"Mensagem do usuário: {inp_message}"
        )
    return inp_message or ""


def _track_cost(
    db: Session,
    org: str,
    uid: Optional[str],
    tid: str,
    message_id: str,
    agent,
    ans_obj: Optional[Dict[str, Any]],
    user_msg: str,
    answer: str,
    streaming: bool = False,
    estimated: bool = False,
) -> None:
    """Persiste CostEvent de forma consistente para /api/chat e /api/chat/stream."""
    try:
        provider = "openai"
        usage = (ans_obj.get("usage") if ans_obj else None)
        usage_missing = False

        if usage is None:
            usage_missing = True
            prompt_t = estimate_tokens(user_msg or "")
            completion_t = estimate_tokens(answer or "")
        elif isinstance(usage, dict):
            prompt_t = int(usage.get("prompt_tokens") or 0)
            completion_t = int(usage.get("completion_tokens") or 0)
        else:
            prompt_t = int(getattr(usage, "prompt_tokens", 0) or 0)
            completion_t = int(getattr(usage, "completion_tokens", 0) or 0)

        total_t = prompt_t + completion_t
        model_name = (
            (ans_obj.get("model") if ans_obj else None)
            or (agent.model if agent else None)
            or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        )

        try:
            input_usd, output_usd, total_usd, snap = calc_cost_v2(model_name or "", prompt_t, completion_t, provider)
        except Exception:
            logger.exception("COST_PRICING_V2_FAILED")
            input_usd, output_usd, total_usd, snap = 0.0, 0.0, 0.0, {"pricing_source": "error"}

        db.add(CostEvent(
            id=new_id(),
            org_slug=org,
            user_id=uid,
            thread_id=tid,
            message_id=message_id,
            agent_id=(agent.id if agent else None),
            provider=provider,
            model=model_name,
            prompt_tokens=prompt_t,
            completion_tokens=completion_t,
            total_tokens=total_t,
            input_cost_usd=float(input_usd),
            output_cost_usd=float(output_usd),
            total_cost_usd=float(total_usd),
            cost_usd=float(total_usd),
            pricing_version=PRICING_VERSION,
            pricing_snapshot=json.dumps(snap, ensure_ascii=False),
            usage_missing=usage_missing or estimated,
            meta=json.dumps({"streaming": streaming, "model": model_name, "estimated": estimated}, ensure_ascii=False),
            created_at=now_ts(),
        ))
        db.commit()
        logger.info(
            "COST_EVENT_PERSISTED tid=%s agent=%s prompt=%s compl=%s total_usd=%.6f streaming=%s estimated=%s",
            tid, (agent.id if agent else None), prompt_t, completion_t, float(total_usd), streaming, usage_missing or estimated,
        )
    except Exception:
        logger.exception("COST_EVENT_PERSIST_FAILED")

@app.post("/api/chat", response_model=ChatOut)
def chat(
    inp: ChatIn,
    x_org_slug: Optional[str] = Header(default=None),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
    ):
    # STAB: resolve_org — tenant sempre do JWT
    org = _resolve_org(user, x_org_slug)
    uid = user.get("sub")

    # Ensure thread (create if new, ACL-check if existing)
    tid = inp.thread_id
    if not tid:
        t = Thread(id=new_id(), org_slug=org, title="Nova conversa", created_at=now_ts())
        db.add(t)
        db.commit()
        tid = t.id
        _ensure_thread_owner(db, org, tid, uid)
    else:
        if user.get("role") != "admin":
            _require_thread_member(db, org, tid, uid)

    # Parse @mentions
    mention_tokens: List[str] = []
    try:
        mention_tokens = re.findall(r"@([A-Za-z0-9_\-]{2,64})", inp.message or "")
        seen: set = set()
        mention_tokens = [m for m in mention_tokens if not (m.lower() in seen or seen.add(m.lower()))]
    except Exception:
        mention_tokens = []

    has_team = any(m.strip().lower() in ("time", "team") for m in mention_tokens)

    # Build alias map once
    all_agents = db.execute(select(Agent).where(Agent.org_slug == org)).scalars().all()
    alias_to_agent: Dict[str, Any] = {}
    for a in all_agents:
        if not a or not a.name:
            continue
        full = a.name.strip().lower()
        alias_to_agent[full] = a
        first = full.split()[0] if full.split() else full
        if first:
            alias_to_agent.setdefault(first, a)

    # STAB: select_target_agents — determinístico, nunca sobrescrito
    target_agents = _select_target_agents(db, org, inp, alias_to_agent, mention_tokens, has_team)

    # Init accumulators
    answers: List[str] = []
    all_citations: List[Dict[str, Any]] = []
    last_agent = None
    streaming = False
    # Save (or reuse) user message — idempotent
    m_user, created = _get_or_create_user_message(db, org, tid, user, inp.message, getattr(inp, "client_message_id", None))

    try:
        audit(db, org, user.get('sub'), 'chat.message.sent', request_id='chat', path='/api/chat', status_code=200, latency_ms=0, meta={'thread_id': tid})
    except Exception:
        pass

    # Build thread history for context
    prev = db.execute(
        select(Message)
        .where(Message.org_slug == org, Message.thread_id == tid, Message.id != m_user.id)
        .order_by(Message.created_at.asc())
    ).scalars().all()
    # Keep only the last ~24 messages
    prev = prev[-24:]

    for agent in target_agents:

        # PATCH0100_18: per-agent history in Team mode to avoid leaking other agents' answers
        history: List[Dict[str, str]] = []
        for pm in prev:
            role = "assistant" if pm.role == "assistant" else ("system" if pm.role == "system" else "user")
            if has_team and role == "assistant":
                if not agent or not pm.agent_id or pm.agent_id != agent.id:
                    continue
            history.append({"role": role, "content": (pm.content or "")})
        # Scoped knowledge (agent + linked agents) + thread-scoped temp files
        agent_file_ids: List[str] | None = None
        if agent:
            linked_agent_ids = get_linked_agent_ids(db, org, agent.id)
            scope_agent_ids = [agent.id] + linked_agent_ids
            agent_file_ids = get_agent_file_ids(db, org, scope_agent_ids)

            # Include thread-scoped temporary files (uploads with intent='chat')
            if tid:
                thread_file_ids = [
                    r[0]
                    for r in db.execute(
                        select(File.id).where(
                            File.org_slug == org,
                            File.scope_thread_id == tid,
                            File.origin == "chat",
                        )
                    ).all()
                ]
                if thread_file_ids:
                    agent_file_ids = list(dict.fromkeys((agent_file_ids or []) + thread_file_ids))

        effective_top_k = (agent.rag_top_k if agent and agent.rag_enabled else inp.top_k)

        citations: List[Dict[str, Any]] = []
        if (not agent) or agent.rag_enabled:
            citations = keyword_retrieve(db, org_slug=org, query=inp.message, top_k=effective_top_k, file_ids=agent_file_ids)

            # Fallback for summary-style requests
            if (not citations) and agent_file_ids:
                q = (inp.message or "").lower()
                if any(k in q for k in ["resumo", "resuma", "sumar", "summary", "sintet", "analis", "analise"]):
                    citations = rag_fallback_recent_chunks(db, org=org, file_ids=agent_file_ids, top_k=effective_top_k)

        # Determine temperature
        temperature = None
        if agent and agent.temperature:
            try:
                temperature = float(agent.temperature)
            except Exception:
                pass

        # STAB: _build_agent_prompt — role-injection anti-impersonation
        user_msg = _build_agent_prompt(agent, inp.message, has_team, mention_tokens)

        ans_obj = _openai_answer(
            user_msg,
            citations,
            history=history,
            system_prompt=(agent.system_prompt if agent else None),
            model_override=(agent.model if agent else None),
            temperature=temperature,
        )
        answer = (ans_obj.get("text") if ans_obj else None)

        if ans_obj and ans_obj.get("code") and not answer:
            # surface structured error
            raise HTTPException(
                status_code=503,
                detail={
                    "code": ans_obj.get("code") or "LLM_ERROR",
                    "error": ans_obj.get("error") or "provider_failure",
                    "message": ans_obj.get("message") or "LLM provider failure",
                    "model": ans_obj.get("model"),
                },
            )

        if not answer:
            if citations:
                snippet = (citations[0].get("content") or "")[:600]
                fn = citations[0].get("filename") or citations[0].get("file_id")
                answer = f"Encontrei esta informação no documento ({fn}):\n\n{snippet}"
            else:
                answer = "Ainda não encontrei informação nos documentos enviados para responder com precisão. Você pode anexar um documento relacionado?"

        # Save assistant message for this agent
        m_ass = Message(
            id=new_id(),
            org_slug=org,
            thread_id=tid,
            role="assistant",
            content=answer,
            agent_id=(agent.id if agent else None),
            agent_name=(agent.name if agent else None),
            created_at=now_ts(),
        )
        db.add(m_ass)
        db.commit()
        try:
            audit(db, org, user.get('sub'), 'chat.message.generated', request_id='chat', path='/api/chat', status_code=200, latency_ms=0, meta={'thread_id': tid, 'agent_id': (agent.id if agent else None)})
        except Exception:
            pass

        # V2V-PATCH: log estruturado v2v_chat_ok para correlação com trace_id
        _trace = getattr(inp, "trace_id", None) or ""
        logger.info(
            "v2v_chat_ok trace_id=%s org=%s thread=%s agent=%s chars=%d",
            _trace, org, tid, (agent.name if agent else "none"), len(answer),
        )
        # STAB: _track_cost — unificado para /api/chat, /api/chat/stream e V2V
        _track_cost(db, org, uid, tid, m_ass.id, agent, ans_obj, user_msg, answer, streaming=False)
        try:
            audit(db, org, uid, 'cost.event.recorded', request_id='cost', path='/api/chat', status_code=200, latency_ms=0,
                  meta={"thread_id": tid, "agent_id": (agent.id if agent else None)})
        except Exception:
            logger.exception("AUDIT_COST_FAILED")

        if agent and len(target_agents) > 1:
            answers.append(f"[@{agent.name}] {answer}")
        else:
            answers.append(answer)

        # STAB: last_agent sempre atualizado (garante ChatOut com metadados corretos)
        last_agent = agent

        # Keep citations from first agent
        if citations and not all_citations:
            all_citations = citations


    

    # PATCH0100_18C: combine answers for response payload
    combined = "\n\n".join([a for a in answers if a])

    # PATCH0100_18B: removed CEO consolidation block to avoid mixed-agent responses

    return {
        "thread_id": tid,
        "answer": combined,
        "citations": all_citations,
        "agent_id": last_agent.id if last_agent else None,
        "agent_name": last_agent.name if last_agent else None,
        "voice_id": getattr(last_agent, 'voice_id', None) if last_agent else None,
        "avatar_url": getattr(last_agent, 'avatar_url', None) if last_agent else None,
    }


# ============================================================
# PATCH0100_14 — Thread Members Management
# ============================================================

class AddMemberIn(BaseModel):
    email: str
    role: str = "member"  # admin|member|viewer

@app.get("/api/threads/{thread_id}/members")
def list_thread_members(thread_id: str, x_org_slug: Optional[str] = Header(default=None), user=Depends(get_current_user), db: Session = Depends(get_db)):
    org = get_request_org(user, x_org_slug)
    # Any member can see the member list
    if user.get("role") != "admin":
        _require_thread_member(db, org, thread_id, user.get("sub"))
    members = db.execute(
        select(ThreadMember).where(ThreadMember.org_slug == org, ThreadMember.thread_id == thread_id)
    ).scalars().all()
    # Enrich with user info
    user_ids = [m.user_id for m in members]
    users_map = {}
    if user_ids:
        users_rows = db.execute(select(User).where(User.org_slug == org, User.id.in_(user_ids))).scalars().all()
        users_map = {u.id: u for u in users_rows}
    result = []
    for m in members:
        u = users_map.get(m.user_id)
        result.append({
            "id": m.id,
            "user_id": m.user_id,
            "email": u.email if u else None,
            "name": u.name if u else None,
            "role": m.role,
            "created_at": m.created_at,
        })
    return result

@app.post("/api/threads/{thread_id}/members")
def add_thread_member(thread_id: str, inp: AddMemberIn, x_org_slug: Optional[str] = Header(default=None), user=Depends(get_current_user), db: Session = Depends(get_db)):
    org = get_request_org(user, x_org_slug)
    actor_id = user.get("sub")
    # Only owner/admin of thread can add members
    _require_thread_admin_or_owner(db, org, thread_id, actor_id)
    # Validate role
    if inp.role not in ("admin", "member", "viewer"):
        raise HTTPException(status_code=400, detail="Role inválido. Use: admin, member ou viewer")
    # Find target user by email
    target = db.execute(select(User).where(User.org_slug == org, User.email == inp.email)).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail=f"Usuário com email {inp.email} não encontrado")
    # Check if already member
    existing = _check_thread_member(db, org, thread_id, target.id)
    if existing:
        raise HTTPException(status_code=409, detail="Usuário já é membro desta thread")
    tm = ThreadMember(
        id=new_id(), org_slug=org, thread_id=thread_id,
        user_id=target.id, role=inp.role, created_at=now_ts(),
    )
    db.add(tm)
    db.commit()
    _audit_membership(db, org, thread_id, actor_id, target.id, inp.email, "THREAD_MEMBER_ADDED", inp.role)
    return {"id": tm.id, "user_id": target.id, "email": target.email, "name": target.name, "role": tm.role, "created_at": tm.created_at}

@app.delete("/api/threads/{thread_id}/members/{member_user_id}")
def remove_thread_member(thread_id: str, member_user_id: str, x_org_slug: Optional[str] = Header(default=None), user=Depends(get_current_user), db: Session = Depends(get_db)):
    org = get_request_org(user, x_org_slug)
    actor_id = user.get("sub")
    # Only owner/admin can remove
    _require_thread_admin_or_owner(db, org, thread_id, actor_id)
    target_member = _check_thread_member(db, org, thread_id, member_user_id)
    if not target_member:
        raise HTTPException(status_code=404, detail="Membro não encontrado nesta thread")
    # Cannot remove the last owner
    if target_member.role == "owner":
        owner_count = db.execute(
            select(func.count()).select_from(ThreadMember).where(
                ThreadMember.org_slug == org, ThreadMember.thread_id == thread_id, ThreadMember.role == "owner"
            )
        ).scalar() or 0
        if owner_count <= 1:
            raise HTTPException(status_code=400, detail="Não é possível remover o último owner da thread")
    target_email = ""
    try:
        tu = db.get(User, member_user_id)
        target_email = tu.email if tu else ""
    except Exception:
        pass
    db.execute(delete(ThreadMember).where(ThreadMember.id == target_member.id))
    db.commit()
    _audit_membership(db, org, thread_id, actor_id, member_user_id, target_email, "THREAD_MEMBER_REMOVED", target_member.role)
    return {"ok": True}


@app.post("/api/files/upload")
async def upload(
    file: UploadFile = UpFile(...),
    agent_id: Optional[str] = Form(None),
    agent_ids: Optional[str] = Form(None),
    thread_id: Optional[str] = Form(None),
    intent: Optional[str] = Form(None),
    institutional_request: bool = Form(False),
    link_all_agents: bool = Form(False),
    link_agent: bool = Form(True),
    x_agent_id: Optional[str] = Header(default=None, alias="X-Agent-Id"),
    x_org_slug: Optional[str] = Header(default=None),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org = get_request_org(user, x_org_slug)
    uid = user.get("sub")
    try:
        filename = file.filename or "upload"
        limit_bytes = MAX_UPLOAD_MB * 1024 * 1024
        size = 0
        chunks = []
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > limit_bytes:
                raise HTTPException(status_code=413, detail=f"Arquivo muito grande (max {MAX_UPLOAD_MB}MB)")
            chunks.append(chunk)
        raw = b"".join(chunks)

        # PATCH0100_14: ACL check for thread uploads
        if thread_id and user.get("role") != "admin":
            _require_thread_member(db, org, thread_id, uid)

        resolved_agent_id = (agent_id or x_agent_id)
        # Parse multi-agent list (comma-separated IDs)
        resolved_agent_ids = []
        if agent_ids:
            try:
                resolved_agent_ids = [a.strip() for a in (agent_ids or "").split(",") if a.strip()]
            except Exception:
                resolved_agent_ids = []

        effective_intent = (intent or '').strip().lower() or ('agent' if (link_agent and resolved_agent_id) else 'chat')
        # Normalize intent
        if effective_intent == 'chat':
            # Chat intent is temporary; never link to agent knowledge
            link_agent = False

        if effective_intent not in ('chat','agent','institutional'):
            effective_intent = 'agent' if (link_agent and resolved_agent_id) else 'chat'

        is_institutional = (effective_intent == 'institutional')
        # Institutional B2 flow:
        # - Admin can upload as institutional directly
        # - Non-admin can request institutionalization; file remains available (thread-scoped) until approved
        is_admin_user = (user.get("role") == "admin")

        if link_all_agents:
            effective_intent = 'institutional'

        create_request = False
        if (effective_intent == 'institutional' or institutional_request) and (not is_admin_user):
            create_request = True
            effective_intent = 'chat'
            is_institutional = False
        elif (effective_intent == 'institutional') and is_admin_user:
            is_institutional = True

        f = File(
            id=new_id(),
            org_slug=org,
            thread_id=thread_id if effective_intent == 'chat' else None,
            uploader_id=user.get("sub"),
            uploader_name=user.get("name"),
            uploader_email=user.get("email"),
            filename=filename,
            original_filename=filename,
            origin=effective_intent,
            scope_thread_id=thread_id if effective_intent == 'chat' else None,
            scope_agent_id=resolved_agent_id if effective_intent == 'agent' else None,
            mime_type=file.content_type,
            size_bytes=len(raw),
            content=raw,
            extraction_failed=False,
            is_institutional=is_institutional,
            created_at=now_ts(),
        )
        db.add(f)
        db.commit()

        # Create chat-visible upload event immediately (thread intent)
        if thread_id:
            try:
                ts = now_ts()
                who = (user.get("name") or user.get("email") or "Usuário")
                email = (user.get("email") or "")
                # PATCH0100_14: DOC INSTITUCIONAL format
                when_iso = time.strftime("%Y-%m-%d", time.gmtime(int(ts)))
                when_time = time.strftime("%H:%M", time.gmtime(int(ts)))
                size_kb = round(len(raw) / 1024, 1)
                if is_institutional or effective_intent == 'institutional':
                    visible_text = f"📎 DOC INSTITUCIONAL — {when_iso} {when_time} — {who} ({email}) enviou: {filename} — {size_kb} KB"
                else:
                    visible_text = f"📎 Upload: \"{filename}\" • por {who}{(' / ' + email) if (email and email not in who) else ''} • {when_iso} {when_time} — {size_kb} KB"
                payload = {
                    "kind": "upload",
                    "type": "file_upload",
                    "scope": "institutional" if (is_institutional or effective_intent == 'institutional') else effective_intent,
                    "agent_id": resolved_agent_id,
                    "agent_ids": resolved_agent_ids,
                    "institutional_request": bool(institutional_request),
                    "link_all_agents": bool(link_all_agents),
                    "link_agent": bool(link_agent),
                    "file_id": f.id,
                    "filename": f.filename,
                    "size": int(f.size_bytes or 0),
                    "mime": f.mime_type,
                    "uploader_id": user.get("sub"),
                    "uploader_name": user.get("name"),
                    "uploader_email": user.get("email"),
                    "ts": ts,
                    "text": visible_text,
                }
                ev = Message(
                    id=new_id(),
                    org_slug=org,
                    thread_id=thread_id,
                    user_id=user.get("sub"),
                    user_name=who,
                    role="system",
                    content=visible_text + "\n\nORKIO_EVENT:" + json.dumps(payload, ensure_ascii=False),
                    created_at=ts,
                )
                db.add(ev)
                db.commit()
                try:
                    audit(db, org, user.get("sub"), "chat.file.uploaded", request_id="upload", path="/api/files/upload", status_code=200, latency_ms=0,
                          meta={"thread_id": thread_id, "file_id": f.id, "filename": f.filename, "uploader_email": user.get("email"), "ts": ts})
                except Exception:
                    logger.exception("AUDIT_UPLOAD_CHAT_FAILED")
            except Exception:
                logger.exception("UPLOAD_CHAT_EVENT_FAILED")
            else:
                logger.info("UPLOAD_CHAT_EVENT_CREATED_OK thread=%s file=%s", thread_id, f.filename)


        # Link file to agent knowledge based on selection
        try:
            # Institutional (admin): link to ALL agents in the org
            if is_institutional and is_admin_user:
                ensure_core_agents(db, org)
                all_agents = db.execute(select(Agent).where(Agent.org_slug == org)).scalars().all()
                for ag in all_agents:
                    existing = db.execute(
                        select(AgentKnowledge).where(
                            AgentKnowledge.org_slug == org,
                            AgentKnowledge.agent_id == ag.id,
                            AgentKnowledge.file_id == f.id,
                        )
                    ).scalar_one_or_none()
                    if not existing:
                        db.add(AgentKnowledge(id=new_id(), org_slug=org, agent_id=ag.id, file_id=f.id, created_at=now_ts()))
                db.commit()

            # Explicit multi-agent linking
            if resolved_agent_ids:
                for aid in resolved_agent_ids:
                    ag = db.get(Agent, aid)
                    if not ag or ag.org_slug != org:
                        continue
                    existing = db.execute(
                        select(AgentKnowledge).where(
                            AgentKnowledge.org_slug == org,
                            AgentKnowledge.agent_id == ag.id,
                            AgentKnowledge.file_id == f.id,
                        )
                    ).scalar_one_or_none()
                    if not existing:
                        db.add(AgentKnowledge(id=new_id(), org_slug=org, agent_id=ag.id, file_id=f.id, created_at=now_ts()))
                db.commit()

            # Single-agent link (legacy)
            if link_agent and resolved_agent_id:
                ag = db.get(Agent, resolved_agent_id)
                if ag and ag.org_slug == org:
                    existing = db.execute(
                        select(AgentKnowledge).where(
                            AgentKnowledge.org_slug == org,
                            AgentKnowledge.agent_id == ag.id,
                            AgentKnowledge.file_id == f.id,
                        )
                    ).scalar_one_or_none()
                    if not existing:
                        db.add(AgentKnowledge(id=new_id(), org_slug=org, agent_id=ag.id, file_id=f.id, created_at=now_ts()))
                    db.commit()
        except Exception:
            pass

        # Non-admin institutional request: create a pending approval record
        if create_request:
            try:
                db.add(FileRequest(
                    id=new_id(),
                    org_slug=org,
                    file_id=f.id,
                    requested_by_user_id=user.get("sub"),
                    requested_by_user_name=user.get("name"),
                    status="pending",
                    created_at=now_ts(),
                    resolved_at=None,
                    resolved_by_admin_id=None,
                ))
                db.commit()
            except Exception:
                pass

        extracted_chars = 0
        text_content = ""
        try:
            text_content, extracted_chars = extract_text(filename, raw)
            ft = FileText(id=new_id(), org_slug=org, file_id=f.id, text=text_content, extracted_chars=extracted_chars, created_at=now_ts())
            db.add(ft)

            # Chunking (deterministic)
            chunk_chars = int(os.getenv("RAG_CHUNK_CHARS", "1200"))
            overlap = int(os.getenv("RAG_CHUNK_OVERLAP", "200"))
            text_len = len(text_content)
            idx = 0
            pos = 0
            while pos < text_len:
                end = min(text_len, pos + chunk_chars)
                chunk = text_content[pos:end].strip()
                if chunk:
                    db.add(FileChunk(id=new_id(), org_slug=org, file_id=f.id, idx=idx, content=chunk, created_at=now_ts()))
                    idx += 1
                if end >= text_len:
                    break
                pos = max(0, end - overlap)

            db.commit()
        except Exception:
            f.extraction_failed = True
            db.add(f)
            db.commit()

        # If this is a thread-scoped upload (intent=chat), create a system message so the UI shows the attachment.
        try:
            if effective_intent == 'chat' and thread_id:
                m_up = Message(
                    id=new_id(),
                    org_slug=org,
                    thread_id=thread_id,
                    role="system",
                    content=f"📎 Arquivo anexado: {f.filename}",
                    agent_name="system",
                    created_at=now_ts(),
                )
                db.add(m_up)
                db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass

        # (Upload event is created immediately after file commit for thread uploads.)

        # Audit high-value event
        try:
            audit(db=db, org_slug=org, user_id=user.get("sub"), action="file.uploaded", request_id=new_id(), path="/api/files/upload", status_code=200, latency_ms=0, meta={"filename": f.filename, "size_bytes": f.size_bytes, "intent": effective_intent, "thread_id": thread_id})
        except Exception:
            pass

        return {"file_id": f.id, "filename": f.filename, "status": "stored", "extracted_chars": extracted_chars}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"upload_failed: {e.__class__.__name__}: {str(e)}")

@app.get("/api/files")
def list_files(x_org_slug: Optional[str] = Header(default=None), user=Depends(get_current_user), db: Session = Depends(get_db)):
    org = get_request_org(user, x_org_slug)
    rows = db.execute(select(File).where(File.org_slug == org).order_by(File.created_at.desc())).scalars().all()
    return [{
        "id": f.id,
        "filename": f.filename,
        "size_bytes": f.size_bytes,
        "extraction_failed": f.extraction_failed,
        "created_at": f.created_at,
        "origin": getattr(f, "origin", None),
        "thread_id": getattr(f, "thread_id", None),
        "uploader_name": getattr(f, "uploader_name", None),
        "uploader_email": getattr(f, "uploader_email", None),
    } for f in rows]


@app.post("/api/tools/manus/run")
def manus_run(inp: ManusRunIn, x_org_slug: Optional[str] = Header(default=None), user=Depends(get_current_user), db: Session = Depends(get_db)):
    """Optional connector for Manus (feature-flagged).

    Env:
      - MANUS_ENABLED=1
      - MANUS_URL=https://... (base url)
      - MANUS_API_KEY=...
    """
    org = get_request_org(user, x_org_slug)
    enabled = (os.getenv("MANUS_ENABLED", "").strip().lower() in ("1", "true", "yes"))
    if not enabled:
        raise HTTPException(status_code=501, detail="manus_not_enabled")

    url = (os.getenv("MANUS_URL", "").strip() or "").rstrip("/")
    key = (os.getenv("MANUS_API_KEY", "").strip() or "")
    if not url or not key:
        raise HTTPException(status_code=500, detail="manus_not_configured")

    ts = now_ts()
    task_preview = (inp.task or "").strip().replace("\n", " ")[:180]
    try:
        audit(db, org, user.get("sub"), "manus.run.requested", request_id="manus", path="/api/tools/manus/run", status_code=200, latency_ms=0,
              meta={"task_preview": task_preview, "ts": ts})
    except Exception:
        logger.exception("AUDIT_MANUS_REQUEST_FAILED")

    import urllib.request

    payload = {
        "task": inp.task,
        "context": inp.context or {},
        "org_slug": org,
        "requested_by": {
            "user_id": user.get("sub"),
            "name": user.get("name"),
            "email": user.get("email"),
            "role": user.get("role"),
        },
        "ts": ts,
    }

    req = urllib.request.Request(
        url + "/run",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
            "X-Org-Slug": org,
        },
        method="POST",
    )

    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read().decode("utf-8", errors="ignore")
            try:
                result = json.loads(raw) if raw else {}
            except Exception:
                result = {"raw": raw}
        latency_ms = int((time.time() - start) * 1000)
        try:
            audit(db, org, user.get("sub"), "manus.run.completed", request_id="manus", path="/api/tools/manus/run", status_code=200, latency_ms=latency_ms,
                  meta={"task_preview": task_preview, "ts": ts, "latency_ms": latency_ms})
        except Exception:
            logger.exception("AUDIT_MANUS_COMPLETE_FAILED")
        return {"ok": True, "result": result}
    except Exception as e:
        latency_ms = int((time.time() - start) * 1000)
        try:
            audit(db, org, user.get("sub"), "manus.run.failed", request_id="manus", path="/api/tools/manus/run", status_code=502, latency_ms=latency_ms,
                  meta={"task_preview": task_preview, "ts": ts, "latency_ms": latency_ms, "error": f"{e.__class__.__name__}: {str(e)}"})
        except Exception:
            logger.exception("AUDIT_MANUS_FAIL_FAILED")
        raise HTTPException(status_code=502, detail="manus_call_failed")

# --- Admin ---
@app.get("/api/admin/overview")
def admin_overview(_admin=Depends(require_admin_access), db: Session = Depends(get_db)):
    return {
        "tenants": db.execute(select(func.count(func.distinct(User.org_slug)))).scalar_one(),
        "users": db.execute(select(func.count(User.id))).scalar_one(),
        "threads": db.execute(select(func.count(Thread.id))).scalar_one(),
        "messages": db.execute(select(func.count(Message.id))).scalar_one(),
        "files": db.execute(select(func.count(File.id))).scalar_one(),
    }


@app.post("/api/admin/debug/write-test")
def admin_debug_write_test(_admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    admin = _admin if isinstance(_admin, dict) else {}
    org = get_org(x_org_slug)  # admin route: org from header (get_org), not JWT user
    now = now_ts()
    # 1) Insert a cost_event
    try:
        db.add(CostEvent(
            id=new_id(),
            org_slug=org,
            user_id=admin.get("sub"),
            thread_id=None,
            message_id=None,
            agent_id=None,
            provider="debug",
            model="debug",
            prompt_tokens=1,
            completion_tokens=1,
            total_tokens=2,
            cost_usd=0,
            usage_missing=False,
            meta=json.dumps({"debug": True}, ensure_ascii=False),
            created_at=now,
        ))
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("DEBUG_WRITE_COST_FAILED")
        raise HTTPException(status_code=500, detail="debug_write_cost_failed")

    # 2) Insert a system message event (thread optional)
    try:
        # if there is at least one thread, attach to most recent
        tid = db.execute(select(Thread.id).where(Thread.org_slug==org).order_by(Thread.created_at.desc())).scalars().first()
        if tid:
            payload = {"type":"file_upload","file_id":"debug","filename":"debug.txt","user_name":admin.get("name") or admin.get("email") or "admin","user_id":admin.get("sub"),"created_at":now,"ts":now}
            db.add(Message(
                id=new_id(),
                org_slug=org,
                thread_id=tid,
                user_id=admin.get("sub"),
                user_name=admin.get("name") or admin.get("email"),
                role="system",
                content="ORKIO_EVENT:"+json.dumps(payload, ensure_ascii=False),
                agent_id=None,
                agent_name=None,
                created_at=now,
            ))
            db.commit()
    except Exception:
        db.rollback()
        logger.exception("DEBUG_WRITE_EVENT_FAILED")
        raise HTTPException(status_code=500, detail="debug_write_event_failed")

    # 3) Return counts
    c = db.execute(select(func.count(CostEvent.id)).where(CostEvent.org_slug==org)).scalar_one()
    m = db.execute(select(func.count(Message.id)).where(Message.org_slug==org, Message.role=="system", Message.content.like("ORKIO_EVENT:%"))).scalar_one()
    return {"ok": True, "org_slug": org, "cost_events": int(c), "event_messages": int(m)}



@app.get("/api/admin/users")
def admin_users(status: str = "all", _admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)
    q = select(User).where(User.org_slug == org)
    if status == "pending":
        q = q.where(User.approved_at == None)  # noqa: E711
    elif status == "approved":
        q = q.where(User.approved_at != None)  # noqa: E711
    rows = db.execute(q.order_by(User.created_at.desc()).limit(500)).scalars().all()
    return [{
        "id": u.id,
        "org_slug": u.org_slug,
        "email": u.email,
        "name": u.name,
        "role": u.role,
        "created_at": u.created_at,
        "approved_at": getattr(u, "approved_at", None),
    } for u in rows]



@app.post("/api/admin/users/{user_id}/approve")
def admin_approve_user(
    user_id: str,
    _admin=Depends(require_admin_access),
    x_org_slug: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    org = get_org(x_org_slug)
    admin = _admin if isinstance(_admin, dict) else {}
    u = db.execute(select(User).where(User.id == user_id, User.org_slug == org)).scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u.approved_at = now_ts()
    db.add(u)
    db.commit()
    try:
        audit(
            db=db,
            org_slug=org,
            user_id=admin.get("sub"),
            action="admin.user.approve",
            request_id="admin",
            path=f"/api/admin/users/{user_id}/approve",
            status_code=200,
            latency_ms=0,
            meta={"user_id": u.id, "email": u.email},
        )
    except Exception:
        pass
    return {"ok": True, "id": u.id, "approved_at": u.approved_at}

@app.post("/api/admin/users/{user_id}/reject")
def admin_reject_user(
    user_id: str,
    _admin=Depends(require_admin_access),
    x_org_slug: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    org = get_org(x_org_slug)
    admin = _admin if isinstance(_admin, dict) else {}
    u = db.execute(select(User).where(User.id == user_id, User.org_slug == org)).scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    # Hard reject: delete user (they can re-register if needed)
    db.execute(delete(User).where(User.id == user_id, User.org_slug == org))
    db.commit()
    try:
        audit(
            db=db,
            org_slug=org,
            user_id=admin.get("sub"),
            action="admin.user.reject",
            request_id="admin",
            path=f"/api/admin/users/{user_id}/reject",
            status_code=200,
            latency_ms=0,
            meta={"user_id": u.id, "email": u.email},
        )
    except Exception:
        pass
    return {"ok": True, "id": user_id}

    # P1-4 FIX: rota duplicada admin_reject_user sem org/tenant check removida acima

@app.get("/api/admin/file-requests")
def admin_file_requests(status: str = "pending", _admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)
    q = select(FileRequest).where(FileRequest.org_slug == org)
    if status != "all":
        q = q.where(FileRequest.status == status)
    rows = db.execute(q.order_by(FileRequest.created_at.desc()).limit(400)).scalars().all()
    return [{
        "id": r.id,
        "org_slug": r.org_slug,
        "file_id": r.file_id,
        "requested_by_user_id": r.requested_by_user_id,
        "requested_by_user_name": r.requested_by_user_name,
        "status": r.status,
        "created_at": r.created_at,
        "resolved_at": r.resolved_at,
        "resolved_by_admin_id": r.resolved_by_admin_id,
    } for r in rows]

@app.post("/api/admin/file-requests/{req_id}/approve")
def admin_approve_file_request(req_id: str, _admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None), user=Depends(get_current_user), db: Session = Depends(get_db)):
    org = get_request_org(user, x_org_slug)
    r = db.execute(select(FileRequest).where(FileRequest.org_slug == org, FileRequest.id == req_id)).scalar_one_or_none()
    if not r:
        raise HTTPException(status_code=404, detail="Request not found")
    if r.status != "pending":
        return {"ok": True, "status": r.status}

    f = db.get(File, r.file_id)
    if not f or f.org_slug != org:
        raise HTTPException(status_code=404, detail="File not found")

    f.is_institutional = True
    f.origin = "institutional"
    db.add(f)

    ensure_core_agents(db, org)
    all_agents = db.execute(select(Agent).where(Agent.org_slug == org)).scalars().all()
    for ag in all_agents:
        existing = db.execute(
            select(AgentKnowledge).where(
                AgentKnowledge.org_slug == org,
                AgentKnowledge.agent_id == ag.id,
                AgentKnowledge.file_id == f.id,
            )
        ).scalar_one_or_none()
        if not existing:
            db.add(AgentKnowledge(id=new_id(), org_slug=org, agent_id=ag.id, file_id=f.id, created_at=now_ts()))

    r.status = "approved"
    r.resolved_at = now_ts()
    r.resolved_by_admin_id = user.get("sub")
    db.add(r)
    db.commit()
    return {"ok": True, "status": r.status}

@app.post("/api/admin/file-requests/{req_id}/reject")
def admin_reject_file_request(req_id: str, _admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None), user=Depends(get_current_user), db: Session = Depends(get_db)):
    org = get_request_org(user, x_org_slug)
    r = db.execute(select(FileRequest).where(FileRequest.org_slug == org, FileRequest.id == req_id)).scalar_one_or_none()
    if not r:
        raise HTTPException(status_code=404, detail="Request not found")
    if r.status != "pending":
        return {"ok": True, "status": r.status}

    r.status = "rejected"
    r.resolved_at = now_ts()
    r.resolved_by_admin_id = user.get("sub")
    db.add(r)
    db.commit()
    return {"ok": True, "status": r.status}

@app.get("/api/admin/files")
def admin_files(institutional_only: bool = False, _admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)
    q = select(File).where(File.org_slug == org)
    if institutional_only:
        q = q.where(File.is_institutional == True)
    rows = db.execute(q.order_by(File.created_at.desc()).limit(200)).scalars().all()
    return [{
        "id": f.id,
        "org_slug": f.org_slug,
        "filename": f.filename,
        "size_bytes": f.size_bytes,
        "extraction_failed": f.extraction_failed,
        "is_institutional": getattr(f, "is_institutional", False),
        "origin": getattr(f, "origin", None),
        "thread_id": getattr(f, "thread_id", None),
        "uploader_id": getattr(f, "uploader_id", None),
        "uploader_name": getattr(f, "uploader_name", None),
        "uploader_email": getattr(f, "uploader_email", None),
        "created_at": f.created_at,
    } for f in rows]



@app.get("/api/admin/costs")
def admin_costs(days: int = 7, _admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)
    days = max(1, min(int(days or 7), 90))
    since = now_ts() - (days * 86400)

    total_events = db.execute(select(func.count()).select_from(CostEvent).where(CostEvent.org_slug == org, CostEvent.created_at >= since)).scalar() or 0
    missing = db.execute(select(func.count()).select_from(CostEvent).where(CostEvent.org_slug == org, CostEvent.created_at >= since, CostEvent.usage_missing == True)).scalar() or 0

    rows = db.execute(
        select(
            CostEvent.agent_id,
            func.count().label("events"),
            func.sum(CostEvent.total_tokens).label("total_tokens"),
            func.sum(CostEvent.prompt_tokens).label("prompt_tokens"),
            func.sum(CostEvent.completion_tokens).label("completion_tokens"),
            func.sum(CostEvent.cost_usd).label("cost_usd"),
            func.sum(CostEvent.input_cost_usd).label("input_cost_usd"),
            func.sum(CostEvent.output_cost_usd).label("output_cost_usd"),
            func.sum(CostEvent.total_cost_usd).label("total_cost_usd"),
        ).where(
            CostEvent.org_slug == org,
            CostEvent.created_at >= since,
        ).group_by(CostEvent.agent_id)
    ).all()

    total = db.execute(
        select(
            func.sum(CostEvent.total_tokens),
            func.sum(CostEvent.prompt_tokens),
            func.sum(CostEvent.completion_tokens),
            func.sum(CostEvent.cost_usd),
            func.sum(CostEvent.input_cost_usd),
            func.sum(CostEvent.output_cost_usd),
            func.sum(CostEvent.total_cost_usd),
        ).where(CostEvent.org_slug == org, CostEvent.created_at >= since)
    ).first()

    agent_map = {a.id: a.name for a in db.execute(select(Agent).where(Agent.org_slug == org)).scalars().all()}
    per_agent = []
    for r in rows:
        aid = r[0]
        per_agent.append({
            "agent_id": aid,
            "agent_name": agent_map.get(aid, "N/A") if aid else "N/A",
            "events": int(r[1] or 0),
            "total_tokens": int(r[2] or 0),
            "prompt_tokens": int(r[3] or 0),
            "completion_tokens": int(r[4] or 0),
            "cost_usd": float(r[5] or 0),
            "input_cost_usd": float(r[6] or 0),
            "output_cost_usd": float(r[7] or 0),
            "total_cost_usd": float(r[8] or 0),
        })

    return {
        "org_slug": org,
        "days": days,
        "since": since,
        "events": int(total_events),
        "usage_missing_events": int(missing),
        "pricing_version": PRICING_VERSION,
        "total": {
            "total_tokens": int((total[0] or 0) if total else 0),
            "prompt_tokens": int((total[1] or 0) if total else 0),
            "completion_tokens": int((total[2] or 0) if total else 0),
            "cost_usd": float((total[3] or 0) if total else 0),
            "input_cost_usd": float((total[4] or 0) if total else 0),
            "output_cost_usd": float((total[5] or 0) if total else 0),
            "total_cost_usd": float((total[6] or 0) if total else 0),
        },
        "per_agent": sorted(per_agent, key=lambda x: x["events"], reverse=True),
    }
@app.post("/api/admin/files/upload")
async def admin_upload_file(file: UploadFile = UpFile(...), x_org_slug: Optional[str] = Header(default=None), admin=Depends(require_admin_access), db: Session = Depends(get_db)):
    """
    Upload institutional document (global) that can be linked to multiple agents.
    It is NOT auto-linked to any agent.
    """
    org = get_org(x_org_slug)
    filename = file.filename or "upload"
    raw = await file.read()
    if len(raw) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Arquivo muito grande (max 10MB)")

    f = File(
        id=new_id(),
        org_slug=org,
        thread_id=None,
        uploader_id=admin.get("sub"),
        uploader_name=admin.get("name") or "admin",
        uploader_email=admin.get("email"),
        filename=filename,
        original_filename=filename,
        origin="institutional",
        mime_type=file.content_type,
        size_bytes=len(raw),
        content=raw,
        extraction_failed=False,
        is_institutional=True,
        created_at=now_ts(),
    )
    db.add(f)
    db.commit()

    extracted_chars = 0
    text_content = ""
    try:
        text_content, extracted_chars = extract_text(filename, raw)
        ft = FileText(id=new_id(), org_slug=org, file_id=f.id, text=text_content, extracted_chars=extracted_chars, created_at=now_ts())
        db.add(ft)

        # Chunking (deterministic)
        chunk_chars = int(os.getenv("RAG_CHUNK_CHARS", "1200"))
        overlap = int(os.getenv("RAG_CHUNK_OVERLAP", "200"))
        text_len = len(text_content)
        idx = 0
        pos = 0
        while pos < text_len:
            end = min(text_len, pos + chunk_chars)
            chunk = text_content[pos:end].strip()
            if chunk:
                db.add(FileChunk(id=new_id(), org_slug=org, file_id=f.id, idx=idx, content=chunk, created_at=now_ts()))
                idx += 1
            if end >= text_len:
                break
            pos = max(0, end - overlap)

        db.commit()
    except Exception:
        f.extraction_failed = True
        db.add(f)
        db.commit()

    # PATCH0100_14 (Pilar B, Caso 2): Register upload in institutional thread
    try:
        inst_title = "📚 Documentos Institucionais"
        inst_thread = db.execute(
            select(Thread).where(Thread.org_slug == org, Thread.title == inst_title)
        ).scalar_one_or_none()
        if not inst_thread:
            inst_thread = Thread(id=new_id(), org_slug=org, title=inst_title, created_at=now_ts())
            db.add(inst_thread)
            db.commit()
            # Uploader becomes owner of institutional thread
            admin_uid = admin.get("sub")
            if admin_uid:
                _ensure_thread_owner(db, org, inst_thread.id, admin_uid)
        # Create DOC INSTITUCIONAL message
        ts = now_ts()
        who = admin.get("name") or "admin"
        adm_email = admin.get("email") or ""
        when_iso = time.strftime("%Y-%m-%d", time.gmtime(int(ts)))
        when_time = time.strftime("%H:%M", time.gmtime(int(ts)))
        size_kb = round(len(raw) / 1024, 1)
        visible_text = f"📎 Documento institucional anexado: {filename}"
        inst_payload = {
            "kind": "upload", "type": "file_upload", "scope": "institutional",
            "file_id": f.id, "filename": f.filename, "size_bytes": int(f.size_bytes or 0),
            "uploader_name": who, "uploader_email": adm_email,
            "uploaded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(ts))),
            "ts": ts, "text": visible_text,
        }
        ev = Message(
            id=new_id(), org_slug=org, thread_id=inst_thread.id,
            user_id=admin.get("sub"), user_name=who,
            role="system",
            content=visible_text + "\n\nORKIO_EVENT:" + json.dumps(inst_payload, ensure_ascii=False),
            created_at=ts,
        )
        db.add(ev)
        db.commit()
    except Exception:
        logger.exception("INSTITUTIONAL_THREAD_EVENT_FAILED")

    # audit
    try:
        audit(db, org_slug=org, user_id=None, action="admin_file_upload", request_id="admin", path="/api/admin/files/upload", status_code=200, latency_ms=0, meta={"file_id": f.id, "filename": f.filename, "is_institutional": True})
    except Exception:
        pass

    return {"file_id": f.id, "filename": f.filename, "status": "stored", "is_institutional": True, "extracted_chars": extracted_chars}
@app.get("/api/admin/costs/health")
def admin_costs_health(_admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)
    last = db.execute(select(CostEvent).where(CostEvent.org_slug == org).order_by(CostEvent.created_at.desc()).limit(1)).scalars().first()
    since = now_ts() - 86400
    cnt = db.execute(select(func.count()).select_from(CostEvent).where(CostEvent.org_slug == org, CostEvent.created_at >= since)).scalar()
    miss = db.execute(select(func.count()).select_from(CostEvent).where(CostEvent.org_slug == org, CostEvent.created_at >= since, CostEvent.usage_missing == True)).scalar()
    return {
        "ok": True,
        "org_slug": org,
        "count_24h": int(cnt or 0),
        "usage_missing_24h": int(miss or 0),
        "last_event_at": getattr(last, "created_at", None),
        "last_model": getattr(last, "model", None),
    }



@app.get("/api/admin/audit")
def admin_audit(_admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)
    rows = db.execute(select(AuditLog).where(AuditLog.org_slug == org).order_by(AuditLog.created_at.desc()).limit(200)).scalars().all()
    out = []
    for a in rows:
        try:
            meta = json.loads(a.meta) if a.meta else {}
        except Exception:
            meta = {}
        out.append(
            {
                "id": a.id,
                "org_slug": a.org_slug,
                "user_id": a.user_id,
                "action": a.action,
                "meta": meta,
                "request_id": a.request_id,
                "path": a.path,
                "status_code": a.status_code,
                "latency_ms": a.latency_ms,
                "created_at": a.created_at,
            }
        )
    return out
@app.get("/api/admin/audit/health")
def admin_audit_health(_admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)
    last = db.execute(select(AuditLog).where(AuditLog.org_slug == org).order_by(AuditLog.created_at.desc()).limit(1)).scalars().first()
    since = now_ts() - 86400
    cnt = db.execute(select(func.count()).select_from(AuditLog).where(AuditLog.org_slug == org, AuditLog.created_at >= since)).scalar()
    return {
        "ok": True,
        "org_slug": org,
        "count_24h": int(cnt or 0),
        "last_event_at": getattr(last, "created_at", None),
        "last_action": getattr(last, "action", None),
    }




class AgentIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    description: Optional[str] = Field(default=None, max_length=400)
    system_prompt: str = Field(default="", max_length=20000)
    model: Optional[str] = Field(default=None, max_length=80)
    embedding_model: Optional[str] = Field(default=None, max_length=80)
    temperature: Optional[float] = Field(default=None, ge=0, le=2)
    rag_enabled: bool = True
    rag_top_k: int = Field(default=6, ge=1, le=20)
    is_default: bool = False
    # PATCH0100_14 (Pilar D)
    voice_id: Optional[str] = Field(default=None, max_length=40)  # alloy|echo|fable|onyx|nova|shimmer
    avatar_url: Optional[str] = Field(default=None, max_length=1000)

class AgentLinkIn(BaseModel):
    file_id: str
    enabled: bool = True

class AgentToAgentLinkIn(BaseModel):
    target_agent_ids: List[str] = Field(default_factory=list)
    mode: str = Field(default="consult")  # consult|delegate

class DelegateIn(BaseModel):
    source_agent_id: str = Field(min_length=1)
    target_agent_id: str = Field(min_length=1)
    instruction: str = Field(min_length=1, max_length=8000)
    create_thread: bool = True
    thread_title: Optional[str] = None



@app.post("/api/agents/delegate")
def agent_delegate(inp: DelegateIn, x_org_slug: Optional[str] = Header(default=None), _admin=Depends(require_admin_access), db: Session = Depends(get_db)):
    """Send a one-way instruction from source agent to target agent. Requires AgentLink(mode='delegate') enabled."""
    org = get_org(x_org_slug)

    source_agent_id = (inp.source_agent_id or "").strip()
    target_agent_id = (inp.target_agent_id or "").strip()
    if not source_agent_id or not target_agent_id:
        raise HTTPException(status_code=400, detail="source_agent_id and target_agent_id required")

    src = db.execute(select(Agent).where(Agent.org_slug == org, Agent.id == source_agent_id)).scalar_one_or_none()
    if not src:
        raise HTTPException(status_code=404, detail="Source agent not found")
    tgt = db.execute(select(Agent).where(Agent.org_slug == org, Agent.id == target_agent_id)).scalar_one_or_none()
    if not tgt:
        raise HTTPException(status_code=404, detail="Target agent not found")

    link = db.execute(
        select(AgentLink).where(
            AgentLink.org_slug == org,
            AgentLink.source_agent_id == source_agent_id,
            AgentLink.target_agent_id == target_agent_id,
            AgentLink.enabled == True,
            AgentLink.mode == "delegate",
        )
    ).scalar_one_or_none()
    if not link:
        raise HTTPException(status_code=403, detail="No delegate link from source to target")

    tid = None
    if inp.create_thread:
        title = (inp.thread_title or f"Instrução de {source_agent_id}").strip()[:200]
        t = Thread(id=new_id(), org_slug=org, title=title, created_at=now_ts())
        db.add(t)
        db.commit()
        tid = t.id

    sys_msg = Message(id=new_id(), org_slug=org, thread_id=tid, role="system", content=f"[delegate] source_agent_id={source_agent_id}", created_at=now_ts())
    usr_msg = Message(id=new_id(), org_slug=org, thread_id=tid, role="user", content=inp.instruction, created_at=now_ts())
    db.add(sys_msg); db.add(usr_msg); db.commit()

    citations: List[Dict[str, Any]] = []
    if tgt and tgt.rag_enabled:
        agent_file_ids = get_agent_file_ids(db, org, [target_agent_id])
        citations = keyword_retrieve(db, org_slug=org, query=inp.instruction, top_k=int(tgt.rag_top_k or 6), file_ids=agent_file_ids)

    answer = _openai_answer(
        inp.instruction,
        citations,
        system_prompt=tgt.system_prompt if tgt else None,
        model_override=tgt.model if tgt else None,
        temperature=float(tgt.temperature) if (tgt and tgt.temperature is not None) else None,
    ) or "Recebido. Vou seguir as orientações."

    ass_msg = Message(id=new_id(), org_slug=org, thread_id=tid, role="assistant", content=answer, agent_id=tgt.id if tgt else None, agent_name=tgt.name if tgt else None, created_at=now_ts())
    db.add(ass_msg); db.commit()

    try:
        audit(db, org_slug=org, user_id=None, action="agent_delegate", request_id="delegate", path="/api/agents/delegate", status_code=200, latency_ms=0, meta={"source_agent_id": source_agent_id, "target_agent_id": target_agent_id})
    except Exception:
        pass

    return {"ok": True, "thread_id": tid, "answer": answer, "citations": citations}

@app.get("/api/agents")
def list_agents(x_org_slug: Optional[str] = Header(default=None), user=Depends(get_current_user), db: Session = Depends(get_db)):
    org = get_request_org(user, x_org_slug)
    ensure_core_agents(db, org)
    rows = db.execute(select(Agent).where(Agent.org_slug == org).order_by(Agent.updated_at.desc())).scalars().all()
    return [{"id": a.id, "name": a.name, "description": a.description, "rag_enabled": a.rag_enabled, "rag_top_k": a.rag_top_k, "model": a.model, "temperature": a.temperature, "is_default": a.is_default, "voice_id": getattr(a, 'voice_id', None), "avatar_url": getattr(a, 'avatar_url', None), "updated_at": a.updated_at} for a in rows]



@app.get("/api/admin/agents/{agent_id}/links")
def admin_get_agent_links(agent_id: str, _admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)
    rows = db.execute(
        select(AgentLink).where(
            AgentLink.org_slug == org,
            AgentLink.source_agent_id == agent_id,
            AgentLink.enabled == True,
        ).order_by(AgentLink.created_at.desc())
    ).scalars().all()
    return [{"id": r.id, "source_agent_id": r.source_agent_id, "target_agent_id": r.target_agent_id, "mode": r.mode, "enabled": r.enabled, "created_at": r.created_at} for r in rows]

@app.put("/api/admin/agents/{agent_id}/links")
def admin_put_agent_links(agent_id: str, inp: AgentToAgentLinkIn, _admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)
    # ensure agent exists
    src = db.execute(select(Agent).where(Agent.org_slug == org, Agent.id == agent_id)).scalar_one_or_none()
    if not src:
        raise HTTPException(status_code=404, detail="Agent not found")

    # disable existing links
    existing = db.execute(select(AgentLink).where(AgentLink.org_slug == org, AgentLink.source_agent_id == agent_id)).scalars().all()
    for e in existing:
        e.enabled = False
        db.add(e)

    # validate targets (same org)
    targets: List[str] = []
    if inp.target_agent_ids:
        targets = db.execute(select(Agent.id).where(Agent.org_slug == org, Agent.id.in_(inp.target_agent_ids))).scalars().all()

    mode = (inp.mode or "consult").strip() or "consult"
    count = 0
    for tid in targets:
        if tid == agent_id:
            continue
        db.add(AgentLink(id=new_id(), org_slug=org, source_agent_id=agent_id, target_agent_id=tid, mode=mode, enabled=True, created_at=now_ts()))
        count += 1

    db.commit()
    return {"ok": True, "count": count}

@app.get("/api/admin/agents")
def admin_agents(_admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    # Admin can list per-org (from header) or all if header omitted in single-tenant mode
    org = get_org(x_org_slug)
    rows = db.execute(select(Agent).where(Agent.org_slug == org).order_by(Agent.updated_at.desc()).limit(200)).scalars().all()
    return [{"id": a.id, "org_slug": a.org_slug, "name": a.name, "description": a.description, "system_prompt": a.system_prompt, "rag_enabled": a.rag_enabled, "rag_top_k": a.rag_top_k, "model": a.model, "embedding_model": a.embedding_model, "temperature": a.temperature, "is_default": a.is_default, "voice_id": getattr(a, 'voice_id', None), "avatar_url": getattr(a, 'avatar_url', None), "created_at": a.created_at, "updated_at": a.updated_at} for a in rows]

@app.post("/api/admin/agents")
def admin_create_agent(inp: AgentIn, _admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)
    ensure_core_agents(db, org)
    now = now_ts()
    # If setting as default, unset other defaults first
    if inp.is_default:
        db.execute(text("UPDATE agents SET is_default=0 WHERE org_slug=:org"), {"org": org})
    a = Agent(
        id=new_id(),
        org_slug=org,
        name=inp.name.strip(),
        description=inp.description,
        system_prompt=inp.system_prompt,
        model=inp.model,
        embedding_model=inp.embedding_model,
        temperature=str(inp.temperature) if inp.temperature is not None else None,
        rag_enabled=bool(inp.rag_enabled),
        rag_top_k=inp.rag_top_k,
        is_default=bool(inp.is_default),
        voice_id=inp.voice_id or "nova",
        avatar_url=inp.avatar_url,
        created_at=now,
        updated_at=now,
    )
    db.add(a)
    db.commit()
    return {"id": a.id}

@app.put("/api/admin/agents/{agent_id}")
def admin_update_agent(agent_id: str, inp: AgentIn, _admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)
    a = db.execute(select(Agent).where(Agent.org_slug == org, Agent.id == agent_id)).scalar_one_or_none()
    if not a:
        raise HTTPException(status_code=404, detail="Agent not found")
    # If setting as default, unset other defaults first
    if inp.is_default and not a.is_default:
        db.execute(text("UPDATE agents SET is_default=0 WHERE org_slug=:org"), {"org": org})
    a.name = inp.name.strip()
    a.description = inp.description
    a.system_prompt = inp.system_prompt
    a.model = inp.model
    a.embedding_model = inp.embedding_model
    a.temperature = str(inp.temperature) if inp.temperature is not None else None
    a.rag_enabled = bool(inp.rag_enabled)
    a.rag_top_k = inp.rag_top_k
    a.is_default = bool(inp.is_default)
    a.voice_id = inp.voice_id or getattr(a, 'voice_id', None) or "nova"
    a.avatar_url = inp.avatar_url if inp.avatar_url is not None else getattr(a, 'avatar_url', None)
    a.updated_at = now_ts()
    db.add(a)
    db.commit()
    return {"ok": True}

@app.delete("/api/admin/agents/{agent_id}")
def admin_delete_agent(agent_id: str, _admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)
    a = db.execute(select(Agent).where(Agent.org_slug == org, Agent.id == agent_id)).scalar_one_or_none()
    if not a:
        raise HTTPException(status_code=404, detail="Agent not found")
    db.execute(text("DELETE FROM agent_knowledge WHERE org_slug=:org AND agent_id=:aid"), {"org": org, "aid": agent_id})
    db.delete(a)
    db.commit()
    return {"ok": True}

@app.get("/api/admin/agents/{agent_id}/knowledge")
def admin_agent_knowledge(agent_id: str, _admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)
    rows = db.execute(select(AgentKnowledge).where(AgentKnowledge.org_slug == org, AgentKnowledge.agent_id == agent_id).order_by(AgentKnowledge.created_at.desc())).scalars().all()
    return [{"id": r.id, "file_id": r.file_id, "enabled": r.enabled, "created_at": r.created_at} for r in rows]

@app.post("/api/admin/agents/{agent_id}/knowledge")
def admin_add_agent_knowledge(agent_id: str, inp: AgentLinkIn, _admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)
    # ensure agent exists
    a = db.execute(select(Agent).where(Agent.org_slug == org, Agent.id == agent_id)).scalar_one_or_none()
    if not a:
        raise HTTPException(status_code=404, detail="Agent not found")
    # upsert
    existing = db.execute(select(AgentKnowledge).where(AgentKnowledge.org_slug == org, AgentKnowledge.agent_id == agent_id, AgentKnowledge.file_id == inp.file_id)).scalar_one_or_none()
    if existing:
        existing.enabled = bool(inp.enabled)
        db.add(existing)
        db.commit()
        return {"id": existing.id}
    r = AgentKnowledge(id=new_id(), org_slug=org, agent_id=agent_id, file_id=inp.file_id, enabled=bool(inp.enabled), created_at=now_ts())
    db.add(r)
    db.commit()
    return {"id": r.id}

@app.delete("/api/admin/agents/{agent_id}/knowledge/{link_id}")
def admin_remove_agent_knowledge(agent_id: str, link_id: str, _admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)
    r = db.execute(select(AgentKnowledge).where(AgentKnowledge.org_slug == org, AgentKnowledge.agent_id == agent_id, AgentKnowledge.id == link_id)).scalar_one_or_none()
    if not r:
        raise HTTPException(status_code=404, detail="Link not found")
    db.delete(r)
    db.commit()
    return {"ok": True}
@app.get("/api/admin/pending_users")
def admin_pending_users(_admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    org = get_org(x_org_slug)
    rows = db.execute(select(User).where(User.org_slug == org, User.approved_at == None).order_by(User.created_at.desc()).limit(500)).scalars().all()
    return [{"id": u.id, "org_slug": u.org_slug, "name": u.name, "email": u.email, "role": u.role, "created_at": u.created_at} for u in rows]


@app.get("/api/admin/approvals/meta")
def admin_approvals_meta(_admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None)):
    org = get_org(x_org_slug)
    return {"ok": True, "org_slug": org}

@app.get("/api/admin/approvals")
def admin_approvals(_admin=Depends(require_admin_access), x_org_slug: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    # Backwards-compatible alias
    return admin_pending_users(_admin=_admin, x_org_slug=x_org_slug, db=db)


# ================================
# PATCH0100_13 — Text-to-Speech (TTS) Endpoint
# ================================

class TTSIn(BaseModel):
    text: str = Field(min_length=1, max_length=4096)
    voice: Optional[str] = "nova"  # alloy, echo, fable, onyx, nova, shimmer
    speed: float = 1.0
    agent_id: Optional[str] = None  # resolve voice from agent config
    message_id: Optional[str] = None  # STAB: resolve agent (and voice) from persisted message


@app.post("/api/chat/stream")
async def chat_stream(
    inp: ChatIn,
    request: Request,
    x_org_slug: Optional[str] = Header(default=None),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # PATCH0113: admission control (Summit)
    await _stream_acquire(request)
    """
    SSE streaming endpoint (POST).

    Summit throughput optimization:
    - Make handler async and run blocking LLM call in a thread (asyncio.to_thread), freeing the event loop.
    - Add keepalive heartbeats while waiting for the LLM.
    - Add disconnect checks + DB rollbacks to prevent "stream não finaliza" and session contamination.
    """
    import time
    from starlette.responses import StreamingResponse

    # STAB: resolve_org — tenant do JWT
    org = _resolve_org(user, x_org_slug)
    uid = user.get("sub")

    # Input normalization
    message = (inp.message or "").strip()
    if not message:
        raise HTTPException(400, "message required")

    tenant = (inp.tenant or org or "").strip() or org
    if tenant != org:
        # Guard: tenant from payload must not override JWT tenant
        tenant = org

    agent_id = inp.agent_id
    top_k = int(inp.top_k or 6)
    trace_id = getattr(inp, "trace_id", None) or new_id()
    client_message_id = getattr(inp, "client_message_id", None)

    # Thread creation / validation (commit here stays; any error must rollback + abort)
    tid = (inp.thread_id or "").strip() or None
    try:
        if not tid:
            t = Thread(id=new_id(), org_slug=org, title="Chat")
            db.add(t)
            db.commit()
            tid = t.id
        else:
            t = db.execute(
                select(Thread).where(Thread.id == tid, Thread.org_slug == org)
            ).scalar_one_or_none()
            if not t:
                raise HTTPException(404, "thread not found")

        # ACL
        if user.get("role") != "admin":
            _require_thread_member(db, org, tid, uid)
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        raise

    # Resolve target agents
    target_agents: List[Agent] = []
    if agent_id:
        a = db.execute(
            select(Agent).where(Agent.id == agent_id, Agent.org_slug == org)
        ).scalar_one_or_none()
        if not a:
            raise HTTPException(404, "agent not found")
        target_agents = [a]
    else:
        # default: pick active agents ordered by created_at
        target_agents = list(
            db.execute(
                select(Agent)
                .where(Agent.org_slug == org, Agent.active == True)
                .order_by(Agent.created_at.asc())
            ).scalars().all()
        )

    if not target_agents:
        raise HTTPException(400, "no agents configured")

    # Persist user message once (idempotent via client_message_id if provided)
    try:
        m_user, created = _get_or_create_user_message(
            db,
            org,
            tid,
            user,
            message,
            client_message_id,
        )
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        raise

    # History for context
    prev = list(
        db.execute(
            select(Message)
            .where(Message.org_slug == org, Message.thread_id == tid)
            .order_by(Message.created_at.asc())
            .limit(64)
        ).scalars().all()
    )

    def sse_event(ev: str, data: Dict[str, Any]) -> str:
        return f"event: {ev}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"

    async def gen():
        # First status quickly
        try:
            yield sse_event("status", {"phase": "running", "status": "Gerando resposta...", "thread_id": tid, "trace_id": trace_id})
        except Exception:
            return

        # Keepalive ticker
        KEEPALIVE_SECS = int(os.getenv("SSE_KEEPALIVE_SECONDS", "15") or 15)
        LLM_WAIT_POLL = 1.0

        try:
            for ag in target_agents:
                if await request.is_disconnected():
                    return

                # per-agent status
                yield sse_event("status", {"phase": "agent", "agent_id": ag.id, "agent_name": ag.name, "agent": ag.name, "status": f"Executando @{ag.name}...", "trace_id": trace_id})

                # Build context/prompt and run blocking LLM call in a background thread (major throughput win)
                agent_file_ids = getattr(ag, "file_ids", None) or []
                rag_top_k = int(getattr(ag, "rag_top_k", 0) or 0) or 6
                effective_top_k = int(top_k or 0) if top_k else rag_top_k
                try:
                    citations = keyword_retrieve(db, org, message, file_ids=agent_file_ids, top_k=effective_top_k)
                except Exception:
                    citations = []
                system_prompt = (getattr(ag, "system_prompt", None) or "").strip()
                model_override = getattr(ag, "model", None) or None
                temperature = float(getattr(ag, "temperature", 0.2) or 0.2)

                llm_task = asyncio.create_task(
                    asyncio.to_thread(
                        _openai_answer,
                        message,
                        citations,
                        prev,
                        system_prompt,
                        model_override,
                        temperature,
                    )
                )

                last_keepalive = time.monotonic()
                started_monotonic = time.monotonic()
                # PATCH0112: compute once; 0 disables
                try:
                    max_stream_seconds = float(os.getenv("MAX_STREAM_SECONDS", "0") or "0")
                except Exception:
                    max_stream_seconds = 0.0
                while not llm_task.done():
                    if max_stream_seconds and (time.monotonic() - started_monotonic) > max_stream_seconds:
                        # Emit timeout + done, cancel task and end generator without awaiting llm_task.
                        try:
                            yield sse_event("error", {"code": "TIMEOUT", "message": "Stream excedeu tempo máximo."})
                            yield sse_event("done", {"done": True})
                        except Exception:
                            pass
                        try:
                            llm_task.cancel()
                        except Exception:
                            pass
                        return
                    if await request.is_disconnected():
                        try:
                            llm_task.cancel()
                        except Exception:
                            pass
                        return
                    now = time.monotonic()
                    if now - last_keepalive >= KEEPALIVE_SECS:
                        last_keepalive = now
                        try:
                            yield sse_event("keepalive", {"ts": int(time.time()), "trace_id": trace_id})
                        except Exception:
                            return
                    await asyncio.sleep(LLM_WAIT_POLL)

                ans_obj = await llm_task
                if await request.is_disconnected():
                    return

                if (not ans_obj) or (isinstance(ans_obj, dict) and ans_obj.get("code") and not (ans_obj.get("text") or "").strip()):
                    # agent error: emit
                    code = (ans_obj.get("code") if isinstance(ans_obj, dict) else None)
                    msg = (ans_obj.get("error") if isinstance(ans_obj, dict) else None) or "LLM error"
                    # If server is busy, tell frontend to retry and end stream early
                    if code == "SERVER_BUSY":
                        try:
                            yield sse_event("error", {"code": "SERVER_BUSY", "message": msg or "SERVER_BUSY", "error": msg, "trace_id": trace_id})
                            yield sse_event("done", {"done": True, "thread_id": tid, "trace_id": trace_id})
                        except Exception:
                            return
                        return
                    # otherwise, continue to next agent

                    try:
                        yield sse_event("error", {"agent_id": ag.id, "code": code or "LLM_ERROR", "message": msg, "error": msg, "trace_id": trace_id})
                        yield sse_event("agent_done", {"done": True, "agent_id": ag.id, "trace_id": trace_id})
                    except Exception:
                        return
                    continue

                ans = (ans_obj.get("text") or "").strip()

                # Persist assistant message (DB path can fail; must rollback)
                try:
                    m_ass = Message(
                        id=new_id(),
                        org_slug=org,
                        thread_id=tid,
                        role="assistant",
                        content=ans,
                        agent_id=ag.id,
                    )
                    db.add(m_ass)
                    db.commit()
                    try:
                        _track_cost(db, org, tid, m_ass.id, ans_obj.get("usage"), model=ans_obj.get("model"))
                    except Exception:
                        # tracking failure should not break stream, but must rollback to keep Session usable
                        try:
                            db.rollback()
                        except Exception:
                            pass
                except Exception as db_err:
                    try:
                        db.rollback()
                    except Exception:
                        pass
                    try:
                        yield sse_event("error", {"agent_id": ag.id, "message": str(db_err), "error": str(db_err), "trace_id": trace_id})
                        yield sse_event("agent_done", {"done": True, "agent_id": ag.id, "trace_id": trace_id})
                    except Exception:
                        return
                    continue

                # Emit in chunks (but answer is ready)
                step = 140
                for i in range(0, len(ans), step):
                    if await request.is_disconnected():
                        return
                    chunk = ans[i : i + step]
                    try:
                        yield sse_event(
                            "chunk",
                            {
                                "agent_id": ag.id,
                                "agent_name": ag.name,
                                "content": chunk,
                                "delta": chunk,
                                "thread_id": tid,
                                "trace_id": trace_id,
                            },
                        )
                    except Exception:
                        return

                try:
                    yield sse_event("agent_done", {"done": True, "agent_id": ag.id, "thread_id": tid, "trace_id": trace_id})
                except Exception:
                    return

            # done global
            try:
                yield sse_event("done", {"done": True, "thread_id": tid, "trace_id": trace_id})
            except Exception:
                return

        except Exception as fatal_err:
            # Ensure DB session is not poisoned
            try:
                db.rollback()
            except Exception:
                pass
            try:
                yield sse_event("error", {"message": str(fatal_err), "error": str(fatal_err), "trace_id": trace_id})
                yield sse_event("done", {"done": True, "thread_id": tid, "trace_id": trace_id})
            except Exception:
                return

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "X-Trace-Id": trace_id,
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
            background=BackgroundTask(_bg_release_stream, request),
)

@app.post("/api/tts")
async def tts_endpoint(
    inp: TTSIn,
    x_org_slug: Optional[str] = Header(default=None),
    x_trace_id: Optional[str] = Header(default=None),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """V2V-PATCH: Generate speech audio from text (OpenAI TTS).
    Returns audio/mpeg. Resolves voice: message_id → agent_id → inp.voice → nova.
    Emits structured logs: v2v_tts_ok / v2v_tts_fail."""
    trace_id = x_trace_id or new_id()
    if OpenAI is None:
        raise HTTPException(status_code=503, detail="OpenAI SDK not available")
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise HTTPException(status_code=503, detail="OPENAI_API_KEY not configured")

    # Resolve voice: message_id → agent_id → inp.voice → nova
    voice = inp.voice or "nova"
    org = get_request_org(user, x_org_slug)
    _VALID_VOICES = ("alloy","ash","ballad","coral","echo","fable","onyx","nova","sage","shimmer","verse")
    _VOICE_MAP = {"cedar": "nova", "marin": "alloy"}
    resolved_via = "default"
    fallback_used = False
    try:
        if inp.message_id:
            msg = db.execute(select(Message).where(
                Message.org_slug == org, Message.id == inp.message_id
            )).scalar_one_or_none()
            if msg and msg.agent_id:
                agent = db.execute(select(Agent).where(
                    Agent.org_slug == org, Agent.id == msg.agent_id
                )).scalar_one_or_none()
                if agent and getattr(agent, "voice_id", None):
                    voice = agent.voice_id
                    resolved_via = f"message_id→agent:{agent.name}"
        elif inp.agent_id:
            agent = db.execute(select(Agent).where(
                Agent.org_slug == org, Agent.id == inp.agent_id
            )).scalar_one_or_none()
            if agent and getattr(agent, "voice_id", None):
                voice = agent.voice_id
                resolved_via = f"agent_id:{agent.name}"
        elif inp.voice and inp.voice in _VALID_VOICES:
            resolved_via = "inp.voice"
    except Exception:
        logger.exception("TTS_VOICE_RESOLVE_FAILED trace_id=%s", trace_id)

    voice = _VOICE_MAP.get((voice or "").strip().lower(), voice)
    voice = voice if voice in _VALID_VOICES else "nova"
    speed = max(0.25, min(4.0, inp.speed))

    tts_model = os.getenv("OPENAI_TTS_MODEL", "gpt-4o-mini-tts").strip() or "gpt-4o-mini-tts"
    logger.info(
        "v2v_play_start trace_id=%s org=%s voice=%s resolved_via=%s chars=%d model=%s",
        trace_id, org, voice, resolved_via, len(inp.text), tts_model,
    )

    try:
        client = OpenAI(api_key=api_key)
        response = client.audio.speech.create(
            model=tts_model,
            voice=voice,
            input=inp.text[:4096],
            speed=speed,
            response_format="mp3",
        )
        from fastapi.responses import StreamingResponse
        import io
        audio_bytes = _read_audio_bytes(response)
        logger.info(
            "v2v_tts_ok trace_id=%s org=%s voice=%s bytes=%d",
            trace_id, org, voice, len(audio_bytes),
        )
        return StreamingResponse(
            io.BytesIO(audio_bytes),
            media_type="audio/mpeg",
            headers={
                "Content-Disposition": "inline; filename=tts.mp3",
                "Cache-Control": "no-cache",
                "X-Trace-Id": trace_id,
                "X-V2V-Voice": voice,
                "X-V2V-Resolved-Via": resolved_via,
            },
        )
    except Exception as e:
        logger.warning("v2v_tts_fallback trace_id=%s original_model=%s original_voice=%s fallback_model=%s fallback_voice=%s error=%s", trace_id, tts_model, voice, "gpt-4o-mini-tts", "nova", str(e))
        try:
            response = client.audio.speech.create(
                model="gpt-4o-mini-tts",
                voice="nova",
                input=inp.text[:4096],
                speed=speed,
                response_format="mp3",
            )
            from fastapi.responses import StreamingResponse
            import io
            audio_bytes = _read_audio_bytes(response)
            logger.info("v2v_tts_ok trace_id=%s org=%s voice=%s bytes=%d fallback_used=%s", trace_id, org, "nova", len(audio_bytes), True)
            return StreamingResponse(
                io.BytesIO(audio_bytes),
                media_type="audio/mpeg",
                headers={
                    "Content-Disposition": "inline; filename=tts.mp3",
                    "Cache-Control": "no-cache",
                    "X-Trace-Id": trace_id,
                    "X-V2V-Voice": "nova",
                    "X-V2V-Resolved-Via": resolved_via,
                    "X-V2V-Fallback-Used": "true",
                },
            )
        except Exception as e2:
            logger.exception("v2v_tts_fail trace_id=%s model=%s voice=%s fallback_used=%s error=%s", trace_id, tts_model, voice, True, str(e2))
            raise HTTPException(status_code=502, detail=f"TTS generation failed: {str(e2)} (check OPENAI_TTS_MODEL/voice/key)")


# Public TTS for landing page (rate-limited by text length)
@app.post("/api/public/tts")
async def public_tts_endpoint(inp: TTSIn, request: Request):
    """Public TTS endpoint (no auth) — limited to 500 chars for landing/demo."""
    if len(inp.text) > 500:
        raise HTTPException(status_code=400, detail="Public TTS limited to 500 characters")
    # Rate limit: máximo PUBLIC_TTS_MAX_PER_MINUTE chamadas/IP/minuto
    _ip = request.client.host if request.client else "unknown"
    _now = time.time()
    with _public_tts_lock:
        calls = _public_tts_calls.get(_ip, [])
        calls = [t for t in calls if _now - t < 60]
        if len(calls) >= _PUBLIC_TTS_MAX_PER_MINUTE:
            # Atualizar mesmo no 429 para não vazar entry vazia
            _public_tts_calls[_ip] = calls
            raise HTTPException(status_code=429, detail="Too many TTS requests. Try again in a minute.")
        calls.append(_now)
        _public_tts_calls[_ip] = calls
        # F-08 FIX: eviction periódica — remover IPs com janela expirada para evitar memory leak
        # Executa 1/50 das chamadas (heurística barata, sem overhead de timer separado)
        if len(_public_tts_calls) > 200:
            _stale = [ip for ip, ts_list in _public_tts_calls.items()
                      if not ts_list or (_now - max(ts_list)) > 120]
            for ip in _stale:
                del _public_tts_calls[ip]
    if OpenAI is None:
        raise HTTPException(status_code=503, detail="OpenAI SDK not available")
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise HTTPException(status_code=503, detail="OPENAI_API_KEY not configured")

    voice = inp.voice if inp.voice in ("alloy", "echo", "fable", "onyx", "nova", "shimmer") else "nova"
    try:
        client = OpenAI(api_key=api_key)
        response = client.audio.speech.create(
            model=os.getenv("OPENAI_TTS_MODEL", "gpt-4o-mini-tts").strip() or "gpt-4o-mini-tts",
            voice=voice,
            input=inp.text[:500],
            speed=max(0.25, min(4.0, inp.speed)),
            response_format="mp3",
        )
        from fastapi.responses import StreamingResponse
        import io
        return StreamingResponse(
            io.BytesIO(response.content),
            media_type="audio/mpeg",
            headers={"Content-Disposition": "inline; filename=tts.mp3", "Cache-Control": "no-cache"},
        )
    except Exception as e:
        logger.exception("PUBLIC_TTS_FAILED")
        raise HTTPException(status_code=500, detail=f"TTS failed: {str(e)}")


# Speech-to-Text (STT) endpoint using Whisper

def _normalize_stt_text(text: str) -> str:
    s = (text or "").strip()
    if not s:
        return ""
    s = re.sub(r"\s+", " ", s).strip()
    s = s[:1].upper() + s[1:] if s else s
    if re.search(r"[.!?…]$", s):
        return s
    lower = s.lower()
    question_starters = (
        "quem", "que", "qual", "quais", "quando", "onde", "como", "por que",
        "porque", "quanto", "quantos", "pode", "poderia", "devo", "será", "sera",
        "você", "voce", "há", "ha", "tem", "existe"
    )
    first = lower.split(" ", 1)[0]
    is_question = (
        lower.startswith(question_starters)
        or first in question_starters
        or lower.endswith(" né")
        or lower.endswith(" nao")
        or lower.endswith(" não")
    )
    # Avoid forcing punctuation on very short fragments that are often interim speech
    if len(s.split()) <= 2 and not is_question:
        return s
    return s + ("?" if is_question else ".")

@app.post("/api/stt")
async def stt_endpoint(
    file: UploadFile = UpFile(...),
    language: Optional[str] = Form(default=None),
    x_org_slug: Optional[str] = Header(default=None),
    x_trace_id: Optional[str] = Header(default=None),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """V2V-PATCH: Transcribe audio to text (Whisper).
    Accepts audio/webm, mp3, wav, ogg, m4a. Returns {text, language, trace_id}.
    Emits structured logs: v2v_record_received, v2v_stt_ok / v2v_stt_fail."""
    trace_id = x_trace_id or new_id()
    org = _resolve_org(user, x_org_slug)

    allowed_types = {"audio/webm", "audio/mpeg", "audio/mp3", "audio/wav",
                     "audio/ogg", "audio/m4a", "audio/mp4", "video/webm"}
    ct = (file.content_type or "").lower()
    fname = (file.filename or "audio.webm").lower()

    logger.info(
        "v2v_record_received trace_id=%s org=%s content_type=%s filename=%s",
        trace_id, org, ct, fname,
    )

    if OpenAI is None:
        logger.warning("v2v_stt_fail trace_id=%s reason=sdk_unavailable", trace_id)
        raise HTTPException(status_code=503, detail="OpenAI SDK not available")
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        logger.warning("v2v_stt_fail trace_id=%s reason=no_api_key", trace_id)
        raise HTTPException(status_code=503, detail="OPENAI_API_KEY not configured")

    if ct not in allowed_types and not any(fname.endswith(ext) for ext in [".webm", ".mp3", ".wav", ".ogg", ".m4a", ".mp4"]):
        logger.warning("v2v_stt_fail trace_id=%s reason=bad_format ct=%s", trace_id, ct)
        raise HTTPException(status_code=400, detail=f"Unsupported audio format: {ct}. Use webm, mp3, wav, ogg or m4a.")

    content = await file.read()
    if len(content) > 25 * 1024 * 1024:
        logger.warning("v2v_stt_fail trace_id=%s reason=file_too_large bytes=%d", trace_id, len(content))
        raise HTTPException(status_code=400, detail="Audio file too large (max 25MB)")

    if len(content) < 100:
        logger.warning("v2v_stt_fail trace_id=%s reason=file_too_small bytes=%d", trace_id, len(content))
        raise HTTPException(status_code=400, detail="Audio file too small — recording may have failed.")

    try:
        import tempfile
        suffix = "." + (fname.rsplit(".", 1)[-1] if "." in fname else "webm")
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            client = OpenAI(api_key=api_key)
            requested_language = resolve_stt_language(language)
            with open(tmp_path, "rb") as audio_file:
                transcribe_kwargs = {
                    "model": os.getenv("OPENAI_STT_MODEL","gpt-4o-mini-transcribe").strip() or "whisper-1",
                    "file": audio_file,
                }
                if requested_language:
                    transcribe_kwargs["language"] = requested_language
                transcript = client.audio.transcriptions.create(**transcribe_kwargs)
            raw_text = (transcript.text or "").strip()
            text = _normalize_stt_text(raw_text)
            logger.info(
                "v2v_stt_ok trace_id=%s org=%s chars=%d preview=%r",
                trace_id, org, len(text), text[:60],
            )
            return {"text": text, "raw_text": raw_text, "language": (requested_language or "auto"), "trace_id": trace_id}
        finally:
            try:
                import os as _os
                _os.unlink(tmp_path)
            except Exception:
                pass
    except Exception as e:
        logger.exception("v2v_stt_fail trace_id=%s error=%s", trace_id, str(e))
        raise HTTPException(status_code=500, detail=f"Transcription failed: {str(e)}")


# ==========================
# Realtime/WebRTC (V2V) support
# ==========================
class RealtimeClientSecretReq(BaseModel):
    # Request an ephemeral client secret for the OpenAI Realtime API (WebRTC).
    agent_id: Optional[str] = None
    voice: str = Field(default="cedar", description="Realtime voice id (e.g. nova, alloy, echo).")
    model: str = Field(default="gpt-realtime-mini", description="Realtime model name.")
    ttl_seconds: int = Field(default=600, ge=10, le=7200, description="Client secret TTL in seconds.")
    mode: Optional[str] = Field(default=None, description="platform|summit")
    response_profile: Optional[str] = Field(default=None, description="default|stage")
    language_profile: Optional[str] = Field(default=None, description="auto|pt-BR|en")


class RealtimeStartReq(BaseModel):
    agent_id: Optional[str] = None
    thread_id: Optional[str] = None
    voice: str = Field(default="cedar")
    model: str = Field(default="gpt-realtime-mini")
    ttl_seconds: int = Field(default=600, ge=10, le=7200)
    mode: Optional[str] = Field(default=None, description="platform|summit")
    response_profile: Optional[str] = Field(default=None, description="default|stage")
    language_profile: Optional[str] = Field(default=None, description="auto|pt-BR|en")

class RealtimeEventIn(BaseModel):
    session_id: str
    event_type: str
    client_event_id: Optional[str] = None  # idempotency key per event (frontend-generated)
    role: str = Field(description="user|assistant|system")
    content: Optional[str] = None
    created_at: Optional[int] = None  # epoch ms; server will default to now
    is_final: Optional[bool] = None
    meta: Optional[Dict[str, Any]] = None

class RealtimeEndReq(BaseModel):
    session_id: str
    ended_at: Optional[int] = None  # epoch ms
    meta: Optional[Dict[str, Any]] = None



# =========================
# Realtime Voice Normalization
# =========================
# The OpenAI Realtime API supports a restricted set of voice ids.
# We normalize any legacy/invalid voice ids to a safe default ("cedar"),
# and map older Orkio voice ids (e.g. "nova") into supported ones.

REALTIME_VOICE_SUPPORTED = {
    "alloy", "ash", "ballad", "coral",
    "echo", "sage", "shimmer", "verse",
    "marin", "cedar",
}

REALTIME_VOICE_ALIASES = {
    # legacy -> supported
    "nova": "cedar",
    "onyx": "echo",
    "fable": "sage",
    "shimmer": "shimmer",
    "echo": "echo",
    "alloy": "alloy",
}

def normalize_realtime_voice(voice: str | None, default: str = "cedar") -> str:
    if not voice:
        return default
    v = str(voice).strip().lower()
    if v in REALTIME_VOICE_SUPPORTED:
        return v
    if v in REALTIME_VOICE_ALIASES:
        return REALTIME_VOICE_ALIASES[v]
    return default

@app.post("/api/realtime/client_secret")
async def realtime_client_secret(
    body: RealtimeClientSecretReq,
    x_org_slug: Optional[str] = Header(default=None),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Mint a short-lived Realtime client secret for browser WebRTC connections.
    if OpenAI is None:
        raise HTTPException(status_code=503, detail="OpenAI SDK not available")

    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise HTTPException(status_code=503, detail="OPENAI_API_KEY not configured")

    org = _resolve_org(user, x_org_slug)

    mode = normalize_mode(body.mode)
    response_profile = normalize_response_profile(body.response_profile)
    language_profile = normalize_language_profile(body.language_profile)
    summit_cfg = get_summit_runtime_config(
        mode=mode,
        response_profile=response_profile,
        language_profile=language_profile,
    )

    # Optional: inject agent instructions as session prompt (keeps behavior aligned with Orkio agents)
    agent_system_prompt = None
    agent_voice = None
    if body.agent_id is not None:
        agent = db.execute(select(Agent).where(Agent.id == body.agent_id, Agent.org_slug == org)).scalar_one_or_none()
        if agent:
            agent_system_prompt = (agent.system_prompt or "").strip()[:8000] or None
            agent_voice = ((getattr(agent, "voice_id", None) or "") or "").strip() or None

    instructions = build_summit_instructions(
        mode=mode,
        agent_instructions=agent_system_prompt,
        language_profile=summit_cfg.get("language_profile"),
        response_profile=summit_cfg.get("response_profile"),
    )

    # Choose voice: explicit > agent default > fallback
    voice_raw = body.voice or agent_voice or os.getenv("OPENAI_REALTIME_VOICE_DEFAULT", "cedar")

    # Normalize to supported voices to avoid Realtime mint failures
    voice = normalize_realtime_voice(voice_raw, default=os.getenv("OPENAI_REALTIME_VOICE_DEFAULT", "cedar"))
    resolved_language = resolve_stt_language(summit_cfg.get("transcription_language"))
    session_cfg: Dict[str, Any] = {
        "type": "realtime",
        "model": body.model,
        "audio": {
            "output": {"voice": voice},
            # Let the server detect turns for lowest-latency voice UX
            "input": {
                "turn_detection": {"type": "server_vad", "create_response": True},
                # Optional transcription for UI captions / logs
                "transcription": {
                    **({"language": resolved_language} if resolved_language else {}),
                    "model": os.getenv("OPENAI_REALTIME_TRANSCRIBE_MODEL", "gpt-4o-mini-transcribe"),
                },
            },
        },
    }
    if instructions:
        session_cfg["instructions"] = instructions

    payload = {
        "expires_after": {"anchor": "created_at", "seconds": body.ttl_seconds},
        "session": session_cfg,
    }

    # Prefer SDK (if present), fallback to direct REST call.
    try:
        client = OpenAI(api_key=api_key)
        secret_obj = client.realtime.client_secrets.create(**payload)  # type: ignore[attr-defined]
        value = getattr(secret_obj, "value", None) or (secret_obj.get("value") if isinstance(secret_obj, dict) else None)
        session = getattr(secret_obj, "session", None) or (secret_obj.get("session") if isinstance(secret_obj, dict) else None)
        if not value:
            raise RuntimeError("Realtime client secret missing in SDK response")
        return {"value": value, "session": session}
    except Exception as sdk_err:
        try:
            import urllib.request, json as _json

            req = urllib.request.Request(
                "https://api.openai.com/v1/realtime/client_secrets",
                data=_json.dumps(payload).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = _json.loads(resp.read().decode("utf-8"))
            if not data.get("value"):
                raise RuntimeError("Realtime client secret missing in REST response")
            return {"value": data["value"], "session": data.get("session"), "sdk_fallback": True}
        except Exception as rest_err:
            logger.exception("realtime_client_secret_failed org=%s sdk_err=%s rest_err=%s", org, sdk_err, rest_err)
            raise HTTPException(status_code=502, detail="Failed to mint Realtime client secret")


@app.post("/api/realtime/start")
async def realtime_start(
    body: RealtimeStartReq,
    x_org_slug: Optional[str] = Header(default=None),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Start a Realtime/WebRTC session bound to an Orkio agent and thread, returning:
    - session_id (for audit / event logging)
    - thread_id (created if missing)
    - client_secret value for browser WebRTC connection
    This ensures the realtime voice is never a generic assistant.
    """
    org = _resolve_org(user, x_org_slug)
    uid = user.get("sub")
    uname = user.get("name")

    # Resolve thread
    tid = body.thread_id
    if not tid:
        t = Thread(id=new_id(), org_slug=org, title="Realtime", created_at=now_ts())
        db.add(t)
        db.commit()
        tid = t.id
        _ensure_thread_owner(db, org, tid, uid)
    else:
        if user.get("role") != "admin":
            _require_thread_member(db, org, tid, uid)

    mode = normalize_mode(body.mode)
    response_profile = normalize_response_profile(body.response_profile)
    language_profile = normalize_language_profile(body.language_profile)
    summit_cfg = get_summit_runtime_config(
        mode=mode,
        response_profile=response_profile,
        language_profile=language_profile,
    )

    agent_id = body.agent_id
    agent_name = None
    agent_voice = None
    if agent_id is not None:
        agent = db.execute(select(Agent).where(Agent.id == agent_id, Agent.org_slug == org)).scalar_one_or_none()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found for this tenant")
        agent_name = agent.name
        agent_voice = ((getattr(agent, "voice_id", None) or "") or "").strip() or None

    voice = body.voice or agent_voice or os.getenv("OPENAI_TTS_VOICE_DEFAULT", "nova")

    # Create session record
    sid = str(uuid.uuid4())
    rs = RealtimeSession(
        id=sid,
        org_slug=org,
        thread_id=tid,
        agent_id=str(agent_id) if agent_id is not None else None,
        agent_name=agent_name,
        user_id=uid,
        user_name=uname,
        model=body.model,
        voice=voice,
        started_at=now_ts(),
        meta=json.dumps({
            "ttl_seconds": body.ttl_seconds,
            "mode": summit_cfg.get("mode"),
            "response_profile": summit_cfg.get("response_profile"),
            "language_profile": summit_cfg.get("language_profile"),
            "transcription_language": summit_cfg.get("transcription_language"),
            "stage_guidance": summit_cfg.get("stage_guidance"),
        }, ensure_ascii=False),
    )
    db.add(rs)
    db.commit()

    # Mint client secret using the same logic as /client_secret, but ensure instructions are injected.
    r = await realtime_client_secret(
        RealtimeClientSecretReq(
            agent_id=agent_id,
            voice=voice,
            model=body.model,
            ttl_seconds=body.ttl_seconds,
            mode=summit_cfg.get("mode"),
            response_profile=summit_cfg.get("response_profile"),
            language_profile=summit_cfg.get("language_profile"),
        ),
        x_org_slug=x_org_slug,
        user=user,
        db=db,
    )

    # Audit
    _audit(db, org, uid, action="realtime.session.start", meta={
        "session_id": sid,
        "thread_id": tid,
        "agent_id": agent_id,
        "model": body.model,
        "voice": voice,
        "mode": summit_cfg.get("mode"),
        "response_profile": summit_cfg.get("response_profile"),
        "language_profile": summit_cfg.get("language_profile"),
    })

    return {
        "ok": True,
        "session_id": sid,
        "thread_id": tid,
        "agent": {"id": agent_id, "name": agent_name},
        "client_secret": {"value": r.get("value")},
        "client_secret_value": r.get("value"),
        "realtime_session": r.get("session"),
        "summit_config": summit_cfg,
    }


@app.post("/api/realtime/event")
def realtime_event(
    body: RealtimeEventIn,
    background_tasks: BackgroundTasks,
    x_org_slug: Optional[str] = Header(default=None),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Persist realtime transcript/response events for auditability.
    Frontend should POST here for:
      - transcript deltas/finals (role=user)
      - response deltas/finals (role=assistant)
    If is_final=True, we also persist a Message into the thread timeline.
    """
    org = _resolve_org(user, x_org_slug)
    uid = user.get("sub")

    rs = db.execute(select(RealtimeSession).where(RealtimeSession.id == body.session_id, RealtimeSession.org_slug == org)).scalar_one_or_none()
    if not rs:
        raise HTTPException(status_code=404, detail="Realtime session not found")

    # Membership check (admin bypass)
    if user.get("role") != "admin":
        _require_thread_member(db, org, rs.thread_id, uid)

    ts = int(body.created_at or now_ts())
    agent_id = rs.agent_id if body.role != "user" else None
    agent_name = rs.agent_name if body.role != "user" else None

    ev = RealtimeEvent(
        id=new_id(),
        org_slug=org,
        session_id=rs.id,
        thread_id=rs.thread_id,
        role=body.role,
        agent_id=agent_id,
        agent_name=agent_name,
        event_type=body.event_type,
        content=(body.content or ""),
        created_at=ts,
        meta=json.dumps(body.meta or {}),
    )
    db.add(ev)

    # Also write to thread messages on final events
    if body.is_final and body.content:
        if body.role == "user":
            m = Message(
                id=new_id(),
                org_slug=org,
                thread_id=rs.thread_id,
                user_id=rs.user_id,
                user_name=rs.user_name,
                role="user",
                content=body.content,
                created_at=ts,
            )
        else:
            m = Message(
                id=new_id(),
                org_slug=org,
                thread_id=rs.thread_id,
                user_id=None,
                user_name=None,
                role="assistant",
                content=body.content,
                agent_id=agent_id,
                agent_name=agent_name,
                created_at=ts,
            )
        db.add(m)

    _audit(db, org, uid, action="realtime.event", meta={"session_id": rs.id, "thread_id": rs.thread_id, "event_type": body.event_type, "role": body.role, "is_final": bool(body.is_final)})

    db.commit()
    try:
        # Pontuação assíncrona somente para transcript.final
        if body.is_final and (body.event_type or "").strip() == "transcript.final":
            background_tasks.add_task(punctuate_realtime_events, org, [ev.id])
    except Exception:
        pass
    return {"ok": True}



class RealtimeEventsBatchReq(BaseModel):
    session_id: str
    events: List[RealtimeEventIn]


@app.post("/api/realtime/events:batch")
def realtime_events_batch(
    body: RealtimeEventsBatchReq,
    background_tasks: BackgroundTasks,
    x_org_slug: Optional[str] = Header(default=None),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Persist a batch of realtime events for auditability.
    This is the preferred path for WebRTC clients to avoid per-event HTTP overhead.
    For each event with is_final=True, we also persist a Message into the thread timeline.
    """
    org = _resolve_org(user, x_org_slug)
    uid = user.get("sub")

    rs = db.execute(select(RealtimeSession).where(RealtimeSession.id == body.session_id, RealtimeSession.org_slug == org)).scalar_one_or_none()
    if not rs:
        raise HTTPException(status_code=404, detail="Realtime session not found")

    if user.get("role") != "admin":
        _require_thread_member(db, org, rs.thread_id, uid)

    now = int(now_ts())
    ev_rows: List[RealtimeEvent] = []
    msg_rows: List[Message] = []
    punct_ids: List[str] = []

    for item in body.events:
        ts = int(item.created_at or now)
        agent_id = rs.agent_id if item.role != "user" else None
        agent_name = rs.agent_name if item.role != "user" else None

        client_eid = (getattr(item, "client_event_id", None) or "").strip() or None
        if client_eid:
            # Idempotency: if this event was already persisted for this org+session+client_event_id, skip it.
            try:
                existing_eid = db.execute(
                    select(RealtimeEvent.id)
                    .where(
                        RealtimeEvent.org_slug == org,
                        RealtimeEvent.session_id == rs.id,
                        RealtimeEvent.client_event_id == client_eid,
                    )
                    .limit(1)
                ).scalar_one_or_none()
                if existing_eid:
                    continue
            except Exception:
                # If lookup fails, fall through and attempt insert.
                pass

        eid = new_id()
        ev_rows.append(
            RealtimeEvent(
                id=eid,
                org_slug=org,
                session_id=rs.id,
                thread_id=rs.thread_id,
                role=item.role,
                agent_id=agent_id,
                agent_name=agent_name,
                event_type=item.event_type,
                content=item.content,
                created_at=ts,
                client_event_id=client_eid,
                meta=json.dumps(item.meta or {}, ensure_ascii=False) if item.meta is not None else None,
            )
        )

        try:
            if item.is_final and (item.event_type or "").strip() == "transcript.final":
                punct_ids.append(eid)
        except Exception:
            pass

        if item.is_final and (item.content or "").strip():
            role = "user" if item.role == "user" else "assistant"
            msg_rows.append(
                Message(
                    id=new_id(),
                    org_slug=org,
                    thread_id=rs.thread_id,
                    user_id=rs.user_id if role == "user" else None,
                    user_name=rs.user_name if role == "user" else None,
                    role=role,
                    content=item.content,
                    agent_id=rs.agent_id if role != "user" else None,
                    agent_name=rs.agent_name if role != "user" else None,
                    created_at=ts,
                )
            )

    if ev_rows:
        db.add_all(ev_rows)
    if msg_rows:
        db.add_all(msg_rows)

    db.commit()
    try:
        if punct_ids:
            background_tasks.add_task(punctuate_realtime_events, org, punct_ids)
    except Exception:
        pass
    return {"inserted_events": len(ev_rows), "inserted_messages": len(msg_rows)}


@app.post("/api/realtime/end")
def realtime_end(
    body: RealtimeEndReq,
    x_org_slug: Optional[str] = Header(default=None),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org = _resolve_org(user, x_org_slug)
    uid = user.get("sub")

    rs = db.execute(select(RealtimeSession).where(RealtimeSession.id == body.session_id, RealtimeSession.org_slug == org)).scalar_one_or_none()
    if not rs:
        raise HTTPException(status_code=404, detail="Realtime session not found")

    if user.get("role") != "admin":
        _require_thread_member(db, org, rs.thread_id, uid)

    rs.ended_at = int(body.ended_at or now_ts())
    # merge meta
    try:
        cur = json.loads(rs.meta) if rs.meta else {}
    except Exception:
        cur = {}
    if body.meta:
        cur.update(body.meta)
    rs.meta = json.dumps(cur)

    _audit(db, org, uid, action="realtime.session.end", meta={"session_id": rs.id, "thread_id": rs.thread_id})

    db.commit()
    return {"ok": True}



@app.get("/api/realtime/sessions/{session_id}")
def realtime_get_session(
    session_id: str,
    finals_only: bool = True,
    x_org_slug: Optional[str] = Header(default=None),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Fetch a realtime session and its persisted events.
    - finals_only=True returns only *.final events (recommended for UI/audit).
    Best-effort, never depends on audit helpers.
    """
    org = _resolve_org(user, x_org_slug)
    uid = user.get("sub")

    rs = db.execute(select(RealtimeSession).where(RealtimeSession.id == session_id, RealtimeSession.org_slug == org)).scalar_one_or_none()
    if not rs:
        raise HTTPException(status_code=404, detail="Realtime session not found")

    if user.get("role") != "admin":
        _require_thread_member(db, org, rs.thread_id, uid)

    q = select(RealtimeEvent).where(RealtimeEvent.org_slug == org, RealtimeEvent.session_id == session_id)
    if finals_only:
        q = q.where(RealtimeEvent.event_type.like("%.final"))
    q = q.order_by(RealtimeEvent.created_at.asc())
    evs = db.execute(q).scalars().all()

    def _ev_to_dict(ev: RealtimeEvent) -> dict:
        return {
            "id": ev.id,
            "session_id": ev.session_id,
            "thread_id": ev.thread_id,
            "role": ev.role,
            "agent_id": ev.agent_id,
            "agent_name": ev.agent_name,
            "event_type": ev.event_type,
            "content": ev.content,
            "transcript_punct": getattr(ev, "transcript_punct", None),
            "created_at": ev.created_at,
            "is_final": bool(getattr(ev, "is_final", False)),
            "meta": ev.meta,
        }

    try:
        meta = json.loads(rs.meta) if rs.meta else {}
    except Exception:
        meta = {}

    # Simple status flags for UI polling
    punct_total = 0
    punct_ready = 0
    out_events = []
    for ev in evs:
        d = _ev_to_dict(ev)
        if finals_only and (ev.event_type or "").endswith(".final") and (ev.content or "").strip():
            punct_total += 1
            if (getattr(ev, "transcript_punct", None) or "").strip():
                punct_ready += 1
        out_events.append(d)

    return {
        "session": {
            "id": rs.id,
            "thread_id": rs.thread_id,
            "agent_id": rs.agent_id,
            "agent_name": rs.agent_name,
            "user_id": rs.user_id,
            "user_name": rs.user_name,
            "model": rs.model,
            "voice": rs.voice,
            "started_at": rs.started_at,
            "ended_at": rs.ended_at,
            "meta": meta,
        },
        "events": out_events,
        "punct": {"total": punct_total, "ready": punct_ready, "done": (punct_total > 0 and punct_ready == punct_total)},
    }






class SummitSessionReviewReq(BaseModel):
    clarity: Optional[int] = Field(default=None, ge=1, le=5)
    naturalness: Optional[int] = Field(default=None, ge=1, le=5)
    institutional_fit: Optional[int] = Field(default=None, ge=1, le=5)
    notes: Optional[str] = Field(default=None, max_length=1000)


@app.get("/api/summit/config")
def summit_get_config():
    cfg = get_summit_runtime_config(
        mode=os.getenv("ORKIO_RUNTIME_MODE", "summit"),
        response_profile=os.getenv("SUMMIT_RESPONSE_PROFILE", "stage"),
        language_profile=os.getenv("SUMMIT_LANGUAGE_PROFILE", "pt-BR"),
    )
    return {"ok": True, "config": cfg}


@app.get("/api/realtime/sessions/{session_id}/score")
def realtime_get_session_score(
    session_id: str,
    x_org_slug: Optional[str] = Header(default=None),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org = _resolve_org(user, x_org_slug)
    uid = user.get("sub")

    rs = db.execute(select(RealtimeSession).where(RealtimeSession.id == session_id, RealtimeSession.org_slug == org)).scalar_one_or_none()
    if not rs:
        raise HTTPException(status_code=404, detail="Realtime session not found")
    if user.get("role") != "admin":
        _require_thread_member(db, org, rs.thread_id, uid)

    evs = db.execute(
        select(RealtimeEvent)
        .where(RealtimeEvent.org_slug == org, RealtimeEvent.session_id == session_id)
        .order_by(RealtimeEvent.created_at.asc(), RealtimeEvent.id.asc())
    ).scalars().all()
    try:
        meta = json.loads(rs.meta) if rs.meta else {}
    except Exception:
        meta = {}
    score = assess_realtime_session(evs, meta)
    return {"ok": True, "session_id": session_id, "score": score}


@app.post("/api/realtime/sessions/{session_id}/review")
def realtime_submit_session_review(
    session_id: str,
    body: SummitSessionReviewReq,
    x_org_slug: Optional[str] = Header(default=None),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org = _resolve_org(user, x_org_slug)
    uid = user.get("sub")

    rs = db.execute(select(RealtimeSession).where(RealtimeSession.id == session_id, RealtimeSession.org_slug == org)).scalar_one_or_none()
    if not rs:
        raise HTTPException(status_code=404, detail="Realtime session not found")
    if user.get("role") != "admin":
        _require_thread_member(db, org, rs.thread_id, uid)

    try:
        meta = json.loads(rs.meta) if rs.meta else {}
    except Exception:
        meta = {}
    review = {
        "clarity": body.clarity,
        "naturalness": body.naturalness,
        "institutional_fit": body.institutional_fit,
        "notes": (body.notes or "").strip() or None,
        "reviewed_at": now_ts(),
        "reviewed_by": uid,
    }
    rs.meta = json.dumps(merge_human_review(meta, review), ensure_ascii=False)
    _audit(db, org, uid, action="summit.session.review", meta={"session_id": session_id, **{k: v for k, v in review.items() if v is not None and k != "notes"}})
    db.commit()
    return {"ok": True, "session_id": session_id, "review": review}


def _build_executive_report_from_messages(
    org: str,
    rs: RealtimeSession,
    messages: List[Message],
) -> str:
    """Build a summit-friendly executive report from persisted thread messages."""
    def _clean(v: Optional[str]) -> str:
        return (v or "").replace("\r\n", "\n").replace("\r", "\n").strip()

    cleaned = []
    for m in messages:
        body = _clean(getattr(m, "content", None))
        if not body:
            continue
        if body == "⌛ Preparando resposta...":
            continue
        role = (getattr(m, "role", "") or "").lower()
        speaker = "User" if role == "user" else (_clean(getattr(m, "agent_name", None)) or "Orkio")
        cleaned.append({"speaker": speaker, "role": role, "content": body, "created_at": getattr(m, "created_at", None)})

    header = [
        "ORKIO AI EXECUTIVE REPORT",
        f"session_id: {rs.id}",
        f"thread_id: {rs.thread_id}",
        f"agent_name: {rs.agent_name or ''}",
        f"started_at: {rs.started_at or ''}",
        f"ended_at: {rs.ended_at or ''}",
        "",
    ]
    if not cleaned:
        return "\n".join(header + ["[info] No persisted conversation messages were found for this session yet.", ""]) 

    transcript_lines = []
    for item in cleaned:
        transcript_lines.append(f"{item['speaker']}: {item['content']}")
    transcript = "\n".join(transcript_lines)

    summary_prompt = (
        "You are generating an executive meeting report from an AI board conversation. "
        "Write in professional English for founders and investors. "
        "Use this exact structure:\n"
        "SESSION SUMMARY\n"
        "KEY DISCUSSION\n"
        "EXECUTIVE INSIGHTS\n"
        "STRATEGIC RECOMMENDATIONS\n"
        "NEXT STEPS\n\n"
        "Be faithful to the conversation. Do not invent facts. Keep it concise but polished."
    )

    report_body = ""
    try:
        report_model = (os.getenv("EXEC_REPORT_MODEL", "").strip() or "gpt-4o")
        ans = _openai_answer(
            user_message=f"Conversation transcript:\n\n{transcript}",
            context_chunks=[],
            history=None,
            system_prompt=summary_prompt,
            model_override=report_model,
            temperature=0.3,
        )
        if isinstance(ans, dict):
            report_body = (ans.get("text") or "").strip()
    except Exception:
        report_body = ""

    if not report_body:
        # deterministic fallback
        insights = []
        next_steps = []
        for item in cleaned:
            if item["role"] == "assistant":
                if len(insights) < 3:
                    insights.append(item["content"])
                if len(next_steps) < 3 and any(k in item["content"].lower() for k in ["recommend", "next", "should", "priorit", "focus"]):
                    next_steps.append(item["content"])
        if not insights:
            insights = [cleaned[-1]["content"]]
        if not next_steps:
            next_steps = ["Review the discussion and confirm the highest-priority action."]
        report_body = (
            "SESSION SUMMARY\n"
            "Strategic conversation between the user and the Orkio executive board.\n\n"
            "KEY DISCUSSION\n"
            + "\n".join(transcript_lines)
            + "\n\nEXECUTIVE INSIGHTS\n- "
            + "\n- ".join(insights[:3])
            + "\n\nSTRATEGIC RECOMMENDATIONS\n- "
            + "\n- ".join(insights[:3])
            + "\n\nNEXT STEPS\n- "
            + "\n- ".join(next_steps[:3])
        )

    return "\n".join(header + ["CONVERSATION", transcript, "", report_body.strip(), ""])

@app.get("/api/realtime/sessions/{session_id}/ata.txt")
def realtime_get_session_ata(
    session_id: str,
    x_org_slug: Optional[str] = Header(default=None),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export a summit-friendly executive report for a realtime session."""
    org = _resolve_org(user, x_org_slug)
    uid = user.get("sub")

    rs = db.execute(
        select(RealtimeSession).where(
            RealtimeSession.id == session_id,
            RealtimeSession.org_slug == org,
        )
    ).scalar_one_or_none()
    if not rs:
        raise HTTPException(status_code=404, detail="Realtime session not found")

    if user.get("role") != "admin":
        _require_thread_member(db, org, rs.thread_id, uid)

    msgs = db.execute(
        select(Message)
        .where(
            Message.org_slug == org,
            Message.thread_id == rs.thread_id,
        )
        .order_by(Message.created_at.asc(), Message.id.asc())
    ).scalars().all()

    payload = _build_executive_report_from_messages(org, rs, msgs).strip() + "\n"
    filename = f"orkio-ata-{rs.id}.txt"
    return Response(
        content=payload.encode("utf-8"),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ═══════════════════════════════════════════════════════════════════════
# PATCH0100_28 — Summit Hardening + Legal Compliance endpoints
# ═══════════════════════════════════════════════════════════════════════

# ── OTP 2FA endpoints ──────────────────────────────────────────────────

@app.post("/api/auth/otp/request")
def otp_request(inp: OtpRequestIn, request: Request = None, db: Session = Depends(get_db)):
    """Request an OTP code sent to email. Rate-limited."""
    ip = (request.client.host if request and request.client else "unknown")
    if not _rate_limit_check(_rl_otp_lock, _rl_otp_calls, ip, _OTP_MAX_PER_MINUTE):
        raise HTTPException(status_code=429, detail="Muitas tentativas. Aguarde 1 minuto.")

    org = (inp.tenant or default_tenant()).strip()
    # In Summit mode, OTP must be issued only after password verification (via /api/auth/login)
    if SUMMIT_MODE:
        raise HTTPException(status_code=403, detail="Use o login com senha para receber o código de verificação.")

    email = inp.email.lower().strip()
    u = db.execute(select(User).where(User.org_slug == org, User.email == email)).scalar_one_or_none()
    if not u:
        # Don't reveal if user exists
        return {"ok": True, "message": "Se o email estiver cadastrado, você receberá o código."}

    # Generate 6-digit OTP
    import random
    otp_plain = f"{random.randint(0, 999999):06d}"
    otp_hash = hashlib.sha256(otp_plain.encode()).hexdigest()
    expires = now_ts() + 600  # 10 minutes

    # Invalidate old OTPs
    try:
        db.execute(
            text("UPDATE otp_codes SET verified = TRUE WHERE user_id = :uid AND verified = FALSE"),
            {"uid": u.id}
        )
    except Exception:
        pass

    db.add(OtpCode(
        id=new_id(), user_id=u.id, code_hash=otp_hash,
        expires_at=expires, created_at=now_ts(),
    ))
    db.commit()

    # Send email (best-effort)
    _send_otp_email(email, otp_plain)

    try:
        audit(db, org, u.id, "otp.requested", request_id="otp", path="/api/auth/otp/request",
              status_code=200, latency_ms=0, meta={"email": email})
    except Exception:
        pass

    return {"ok": True, "message": "Se o email estiver cadastrado, você receberá o código."}


@app.post("/api/auth/otp/verify")
def otp_verify(inp: OtpVerifyIn, request: Request = None, db: Session = Depends(get_db)):
    """Verify OTP code and return JWT token (passwordless login)."""
    ip = (request.client.host if request and request.client else "unknown")
    if not _rate_limit_check(_rl_otp_lock, _rl_otp_calls, ip, _OTP_MAX_PER_MINUTE):
        raise HTTPException(status_code=429, detail="Muitas tentativas. Aguarde 1 minuto.")

    org = (inp.tenant or default_tenant()).strip()
    # In Summit mode, passwordless OTP verify is disabled. Use /api/auth/login/verify-otp.
    if SUMMIT_MODE:
        raise HTTPException(status_code=403, detail="Fluxo de verificação inválido. Use a verificação do login.")

    email = inp.email.lower().strip()
    u = db.execute(select(User).where(User.org_slug == org, User.email == email)).scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=401, detail="Código inválido ou expirado.")

    code_hash = hashlib.sha256(inp.code.strip().encode()).hexdigest()
    otp = db.execute(
        select(OtpCode).where(
            OtpCode.user_id == u.id,
            OtpCode.code_hash == code_hash,
            OtpCode.verified == False,
            OtpCode.expires_at > now_ts(),
        )
    ).scalar_one_or_none()

    if not otp:
        # Increment attempts on latest OTP
        latest = db.execute(
            select(OtpCode).where(OtpCode.user_id == u.id, OtpCode.verified == False)
            .order_by(OtpCode.created_at.desc()).limit(1)
        ).scalar_one_or_none()
        if latest:
            latest.attempts = (latest.attempts or 0) + 1
            if latest.attempts >= 5:
                latest.verified = True  # Lock out
            db.add(latest)
            db.commit()
        raise HTTPException(status_code=401, detail="Código inválido ou expirado.")

    # Mark as verified
    otp.verified = True
    db.add(otp)
    db.commit()

    usage_tier = getattr(u, "usage_tier", "summit_standard") or "summit_standard"
    try:
        if _ensure_admin_user_state(u):
            db.add(u)
            db.commit()
    except Exception:
        logger.exception("ADMIN_SYNC_FAILED otp_verify user_id=%s", getattr(u, "id", None))
    token = mint_token({"sub": u.id, "org": org, "email": u.email, "name": u.name, "role": u.role, "approved_at": getattr(u, "approved_at", None), "usage_tier": usage_tier})

    _create_user_session(db, u.id, org, ip, getattr(u, "signup_code_label", None), usage_tier)

    try:
        audit(db, org, u.id, "otp.verified", request_id="otp", path="/api/auth/otp/verify",
              status_code=200, latency_ms=0, meta={"email": email})
    except Exception:
        pass

    return {"access_token": token, "token_type": "bearer", "user": {"id": u.id, "email": u.email, "name": u.name, "role": u.role, "approved_at": getattr(u, "approved_at", None), "usage_tier": usage_tier}}
@app.post("/api/auth/login/verify-otp")
def login_verify_otp(inp: OtpVerifyIn, request: Request = None, db: Session = Depends(get_db)):
    """Verify OTP code (issued after password login) and return JWT token."""
    ip = (request.client.host if request and request.client else "unknown")
    if not _rate_limit_check(_rl_otp_lock, _rl_otp_calls, ip, _OTP_MAX_PER_MINUTE):
        raise HTTPException(status_code=429, detail="Muitas tentativas. Aguarde 1 minuto.")

    org = (inp.tenant or default_tenant()).strip()
    email = inp.email.lower().strip()
    u = db.execute(select(User).where(User.org_slug == org, User.email == email)).scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=401, detail="Código inválido ou expirado.")

    # Summit access window enforcement (standard users only)
    usage_tier = getattr(u, "usage_tier", "summit_standard") or "summit_standard"
    if _summit_access_expired({"role": u.role, "usage_tier": usage_tier}):
        raise HTTPException(status_code=403, detail="Acesso ao Summit encerrado.")

    code_hash = hashlib.sha256(inp.code.strip().encode()).hexdigest()
    otp = db.execute(
        select(OtpCode).where(
            OtpCode.user_id == u.id,
            OtpCode.code_hash == code_hash,
            OtpCode.verified == False,
            OtpCode.expires_at > now_ts(),
        )
    ).scalar_one_or_none()

    if not otp:
        # Increment attempts on latest OTP
        latest = db.execute(
            select(OtpCode).where(OtpCode.user_id == u.id, OtpCode.verified == False)
            .order_by(OtpCode.created_at.desc()).limit(1)
        ).scalar_one_or_none()
        if latest:
            latest.attempts = (latest.attempts or 0) + 1
            if latest.attempts >= 5:
                latest.verified = True  # Lock out
            db.add(latest)
            db.commit()
        raise HTTPException(status_code=401, detail="Código inválido ou expirado.")

    # Mark as verified
    otp.verified = True
    db.add(otp)
    db.commit()

    token = mint_token({"sub": u.id, "org": org, "email": u.email, "name": u.name, "role": u.role, "approved_at": getattr(u, "approved_at", None), "usage_tier": usage_tier})

    _create_user_session(db, u.id, org, ip, getattr(u, "signup_code_label", None), usage_tier)

    try:
        audit(db, org, u.id, "login.otp_verified", request_id="login", path="/api/auth/login/verify-otp",
              status_code=200, latency_ms=0, meta={"email": email, "summit_mode": SUMMIT_MODE})
    except Exception:
        pass

    return {"access_token": token, "token_type": "bearer", "user": {"id": u.id, "email": u.email, "name": u.name, "role": u.role, "approved_at": getattr(u, "approved_at", None), "usage_tier": usage_tier}}


# ── Contact / LGPD endpoints ──────────────────────────────────────────

@app.post("/api/public/contact")
@app.post("/api/contact")
def public_contact(inp: ContactIn, request: Request = None, db: Session = Depends(get_db)):
    """Public contact form — stores request + consent records for LGPD compliance."""
    ip = (request.client.host if request and request.client else "unknown")
    ua = (request.headers.get("user-agent", "") if request else "")

    if not inp.consent_terms:
        raise HTTPException(status_code=400, detail="Você precisa aceitar os Termos de Uso.")

    cr = ContactRequest(
        id=new_id(),
        full_name=inp.full_name.strip(),
        email=inp.email.lower().strip(),
        whatsapp=(inp.whatsapp or "").strip() or None,
        subject=inp.subject.strip(),
        message=inp.message.strip(),
        privacy_request_type=inp.privacy_request_type,
        consent_terms=inp.consent_terms,
        consent_marketing=inp.consent_marketing,
        ip_address=ip,
        user_agent=ua,
        terms_version=inp.terms_version or TERMS_VERSION,
        retention_until=now_ts() + (5 * 365 * 86400),  # 5 years
        created_at=now_ts(),
    )
    db.add(cr)
    db.commit()

    # Record marketing consent if given
    if inp.consent_marketing:
        try:
            db.add(MarketingConsent(
                id=new_id(), contact_id=cr.id, channel="email",
                opt_in_date=now_ts(), ip=ip, source="contact_form", created_at=now_ts(),
            ))
            db.commit()
        except Exception:
            logger.exception("MARKETING_CONSENT_CONTACT_FAILED")

    try:
        audit(db, "public", None, "contact.submitted", request_id="contact", path="/api/public/contact",
              status_code=200, latency_ms=0, meta={"email": inp.email, "subject": inp.subject, "privacy_request_type": inp.privacy_request_type})
    except Exception:
        pass


    # Email automation (internal + user confirmation)
    try:
        subj = f"[ORKIO] New Contact – {inp.subject}"
        if (inp.subject or "").strip().lower() == "data privacy request" and inp.privacy_request_type:
            subj = f"[ORKIO – PRIVACY] Request – {inp.privacy_request_type}"
        internal_text = (
            f"New contact request\n\n"
            f"Name: {inp.full_name}\n"
            f"Email: {inp.email}\n"
            f"WhatsApp: {inp.whatsapp or ''}\n"
            f"Subject: {inp.subject}\n"
            f"Privacy request type: {inp.privacy_request_type or ''}\n"
            f"Consent terms: {inp.consent_terms}\n"
            f"Consent marketing: {inp.consent_marketing}\n"
            f"IP: {ip}\n"
            f"User-Agent: {ua}\n"
            f"Terms version: {cr.terms_version}\n"
            f"Created at (UTC ts): {cr.created_at}\n\n"
            f"Message:\n{inp.message}\n"
        )
        _send_resend_email(RESEND_INTERNAL_TO, subj, internal_text)

        user_subject = "We received your message – Orkio"
        user_text = (
            f"Hello {inp.full_name},\n"
            f"We have received your request and will respond within 3 business days.\n"
            f"If this is a data privacy request, the legal response timeframe may be up to 15 days.\n"
            f"Thank you,\n"
            f"Orkio Team\n"
        )
        _send_resend_email(inp.email, user_subject, user_text)
    except Exception:
        logger.exception("CONTACT_EMAIL_AUTOMATION_FAILED")

    return {"ok": True, "id": cr.id, "message": "We received your message and will respond within 3 business days. If this is a data privacy request, the legal response timeframe may be up to 15 days."}


@app.get("/api/public/legal/terms-version")
def get_terms_version():
    """Return current terms version for frontend to check if user needs to re-accept."""
    return {"version": TERMS_VERSION}


@app.post("/api/auth/accept-terms")
def accept_terms(request: Request = None, user=Depends(get_current_user), db: Session = Depends(get_db)):
    """Record terms acceptance for authenticated user."""
    uid = user.get("sub")
    ip = (request.client.host if request and request.client else "unknown")
    ua = (request.headers.get("user-agent", "") if request else "")

    u = db.execute(select(User).where(User.id == uid)).scalar_one_or_none()
    if u:
        u.terms_accepted_at = now_ts()
        u.terms_version = TERMS_VERSION
        db.add(u)
        db.commit()

    db.add(TermsAcceptance(
        id=new_id(), user_id=uid, terms_version=TERMS_VERSION,
        accepted_at=now_ts(), ip_address=ip, user_agent=ua,
    ))
    db.commit()

    return {"ok": True, "version": TERMS_VERSION}

# ── Me / Profile endpoints (v29 stable) ────────────────────────────────

class MeOut(BaseModel):
    id: str
    org_slug: str
    email: str
    name: str
    role: str
    approved_at: Optional[int] = None
    usage_tier: Optional[str] = None
    terms_accepted_at: Optional[int] = None
    terms_version: Optional[str] = None
    marketing_consent: Optional[bool] = False

@app.get("/api/me", response_model=MeOut)
def get_me(user=Depends(get_current_user), db: Session = Depends(get_db)):
    uid = user.get("sub")
    u = db.execute(select(User).where(User.id == uid)).scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return MeOut(
        id=u.id,
        org_slug=u.org_slug,
        email=u.email,
        name=u.name,
        role=u.role,
        approved_at=u.approved_at,
        usage_tier=u.usage_tier,
        terms_accepted_at=u.terms_accepted_at,
        terms_version=u.terms_version,
        marketing_consent=bool(u.marketing_consent),
    )

class AcceptTermsIn(BaseModel):
    accepted: bool = True
    terms_version: Optional[str] = None
    marketing_consent: Optional[bool] = None

@app.post("/api/me/accept-terms")
@app.patch("/api/me/accept-terms")
def me_accept_terms(inp: AcceptTermsIn, request: Request, user=Depends(get_current_user), db: Session = Depends(get_db)):
    """Unified contract used by the web app. Records Terms acceptance for the authenticated user."""
    if not inp.accepted:
        raise HTTPException(status_code=400, detail="Acceptance is required")
    uid = user.get("sub")
    ip = (request.client.host if request and request.client else "unknown")
    ua = (request.headers.get("user-agent", "") if request else "")

    u = db.execute(select(User).where(User.id == uid)).scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=401, detail="Not authenticated")

    u.terms_accepted_at = now_ts()
    u.terms_version = (inp.terms_version or TERMS_VERSION)
    if inp.marketing_consent is not None:
        u.marketing_consent = bool(inp.marketing_consent)

    db.add(u)
    # Write acceptance log (immutable audit trail)
    db.add(TermsAcceptance(
        id=new_id(), user_id=uid, terms_version=u.terms_version or TERMS_VERSION,
        accepted_at=now_ts(), ip_address=ip, user_agent=ua,
    ))
    db.commit()
    return {"ok": True, "terms_version": u.terms_version}

class PrivacyPrefsIn(BaseModel):
    marketing_consent: bool = False

@app.get("/api/me/privacy")
def me_privacy(user=Depends(get_current_user), db: Session = Depends(get_db)):
    uid = user.get("sub")
    u = db.execute(select(User).where(User.id == uid)).scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"marketing_consent": bool(u.marketing_consent), "terms_version": (u.terms_version or TERMS_VERSION), "terms_accepted_at": u.terms_accepted_at}

@app.put("/api/me/privacy")
def me_privacy_put(inp: PrivacyPrefsIn, request: Request, user=Depends(get_current_user), db: Session = Depends(get_db)):
    uid = user.get("sub")
    ip = (request.client.host if request and request.client else "unknown")
    u = db.execute(select(User).where(User.id == uid)).scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=401, detail="Not authenticated")
    u.marketing_consent = bool(inp.marketing_consent)
    db.add(u)
    db.commit()

    # Consent trail
    try:
        if inp.marketing_consent:
            db.add(MarketingConsent(
                id=new_id(), user_id=uid, channel="email", opt_in_date=now_ts(),
                ip=ip, source="privacy_settings", created_at=now_ts(),
            ))
        else:
            # Log opt-out for both channels
            db.add(MarketingConsent(
                id=new_id(), user_id=uid, channel="email", opt_out_date=now_ts(),
                ip=ip, source="privacy_settings", created_at=now_ts(),
            ))
            db.add(MarketingConsent(
                id=new_id(), user_id=uid, channel="whatsapp", opt_out_date=now_ts(),
                ip=ip, source="privacy_settings", created_at=now_ts(),
            ))
        db.commit()
    except Exception:
        logger.exception("MARKETING_CONSENT_PRIVACY_SETTINGS_FAILED")

    return {"ok": True, "marketing_consent": bool(u.marketing_consent)}




# ── Summit Admin endpoints ─────────────────────────────────────────────

@app.get("/api/admin/summit/config")
def admin_summit_config(admin=Depends(require_admin_access)):
    """Return current Summit configuration."""
    return {
        "summit_mode": SUMMIT_MODE,
        "summit_expires_at": SUMMIT_EXPIRES_AT,
        "turnstile_configured": bool(TURNSTILE_SECRET),
        "msg_max_chars": MSG_MAX_CHARS,
        "terms_version": TERMS_VERSION,
        "std_max_tokens_per_req": SUMMIT_STD_MAX_TOKENS_PER_REQ,
        "std_realtime_max_min_day": SUMMIT_STD_REALTIME_MAX_MIN_DAY,
        "version": APP_VERSION,
    }


@app.post("/api/admin/summit/codes")
def admin_create_code(inp: SignupCodeIn, admin=Depends(require_admin_access), db: Session = Depends(get_db)):
    """Create a new signup access code. Stores only SHA-256 hash; optionally accepts plain_code."""
    import random, string
    raw_code = (inp.plain_code or "").strip().upper()
    plain_code = raw_code or "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
    code_hash = hashlib.sha256(plain_code.strip().upper().encode()).hexdigest()
    expires_at = (now_ts() + inp.expires_days * 86400) if inp.expires_days else None

    admin_id = admin.get("sub", "admin_key")
    org = admin.get("org", default_tenant())

    existing = db.execute(
        select(SignupCode).where(
            SignupCode.org_slug == org,
            SignupCode.code_hash == code_hash,
        )
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Já existe um código com este valor para esta organização.")

    sc = SignupCode(
        id=new_id(), org_slug=org, code_hash=code_hash,
        label=inp.label.strip(), source=inp.source,
        expires_at=expires_at, max_uses=inp.max_uses,
        created_at=now_ts(), created_by=admin_id,
    )
    db.add(sc)
    db.commit()

    try:
        audit(db, org, admin_id, "summit.code.created", request_id="summit", path="/api/admin/summit/codes",
              status_code=200, latency_ms=0, meta={"label": inp.label, "source": inp.source, "code_id": sc.id})
    except Exception:
        pass

    return {"ok": True, "code": plain_code, "id": sc.id, "label": sc.label, "source": sc.source, "max_uses": sc.max_uses, "expires_at": expires_at}


@app.get("/api/admin/summit/codes")
def admin_list_codes(admin=Depends(require_admin_access), db: Session = Depends(get_db)):
    """List all signup codes."""
    org = admin.get("org", default_tenant())
    rows = db.execute(select(SignupCode).where(SignupCode.org_slug == org).order_by(SignupCode.created_at.desc())).scalars().all()
    return [
        {
            "id": sc.id, "label": sc.label, "source": sc.source,
            "used_count": sc.used_count, "max_uses": sc.max_uses,
            "active": sc.active, "expires_at": sc.expires_at,
            "created_at": sc.created_at, "created_by": sc.created_by,
        }
        for sc in rows
    ]


@app.patch("/api/admin/summit/codes/{code_id}")
def admin_toggle_code(code_id: str, admin=Depends(require_admin_access), db: Session = Depends(get_db)):
    """Toggle a signup code active/inactive."""
    org = admin.get("org", default_tenant())
    sc = db.execute(select(SignupCode).where(SignupCode.id == code_id, SignupCode.org_slug == org)).scalar_one_or_none()
    if not sc:
        raise HTTPException(status_code=404, detail="Code not found")
    sc.active = not sc.active
    db.add(sc)
    db.commit()
    return {"ok": True, "id": sc.id, "active": sc.active}


# ── Feature Flags ──────────────────────────────────────────────────────

@app.get("/api/admin/flags")
def admin_list_flags(admin=Depends(require_admin_access), db: Session = Depends(get_db)):
    """List all feature flags."""
    org = admin.get("org", default_tenant())
    rows = db.execute(select(FeatureFlag).where(FeatureFlag.org_slug == org).order_by(FeatureFlag.flag_key)).scalars().all()
    return [{"id": ff.id, "flag_key": ff.flag_key, "flag_value": ff.flag_value, "updated_by": ff.updated_by, "updated_at": ff.updated_at} for ff in rows]

# ── Summit route aliases (frontend expects /api/admin/summit/*) ──────────
@app.get("/api/admin/summit/flags")
def admin_summit_list_flags(admin=Depends(require_admin_access), db: Session = Depends(get_db)):
    return admin_list_flags(admin=admin, db=db)

@app.get("/api/admin/summit/sessions")
def admin_summit_list_sessions(
    active_only: bool = True,
    admin=Depends(require_admin_access),
    db: Session = Depends(get_db),
):
    return admin_list_sessions(active_only=active_only, admin=admin, db=db)




@app.post("/api/admin/flags")
def admin_set_flag(inp: FeatureFlagIn, admin=Depends(require_admin_access), db: Session = Depends(get_db)):
    """Create or update a feature flag."""
    org = admin.get("org", default_tenant())
    admin_id = admin.get("sub", "admin_key")
    existing = db.execute(
        select(FeatureFlag).where(FeatureFlag.org_slug == org, FeatureFlag.flag_key == inp.flag_key)
    ).scalar_one_or_none()
    if existing:
        existing.flag_value = inp.flag_value
        existing.updated_by = admin_id
        existing.updated_at = now_ts()
        db.add(existing)
    else:
        db.add(FeatureFlag(
            id=new_id(), org_slug=org, flag_key=inp.flag_key,
            flag_value=inp.flag_value, updated_by=admin_id, updated_at=now_ts(),
        ))
    db.commit()
    return {"ok": True, "flag_key": inp.flag_key, "flag_value": inp.flag_value}


@app.delete("/api/admin/flags/{flag_key}")
def admin_delete_flag(flag_key: str, admin=Depends(require_admin_access), db: Session = Depends(get_db)):
    """Delete a feature flag."""
    org = admin.get("org", default_tenant())
    ff = db.execute(select(FeatureFlag).where(FeatureFlag.org_slug == org, FeatureFlag.flag_key == flag_key)).scalar_one_or_none()
    if not ff:
        raise HTTPException(status_code=404, detail="Flag not found")
    db.delete(ff)
    db.commit()
    return {"ok": True}


# ── Presence / Sessions ────────────────────────────────────────────────

@app.get("/api/admin/sessions")
def admin_list_sessions(
    active_only: bool = True,
    admin=Depends(require_admin_access),
    db: Session = Depends(get_db),
):
    """List user sessions (presence tracking)."""
    org = admin.get("org", default_tenant())
    q = select(UserSession).where(UserSession.org_slug == org)
    if active_only:
        # Sessions without logout_at and last_seen within 30 min
        cutoff = now_ts() - 1800
        q = q.where(UserSession.logout_at == None, UserSession.last_seen_at >= cutoff)
    q = q.order_by(UserSession.login_at.desc()).limit(200)
    rows = db.execute(q).scalars().all()

    # Enrich with user info
    user_ids = list(set(s.user_id for s in rows))
    users_map = {}
    if user_ids:
        users = db.execute(select(User).where(User.id.in_(user_ids))).scalars().all()
        users_map = {u.id: {"email": u.email, "name": u.name, "role": u.role} for u in users}

    return [
        {
            "id": s.id, "user_id": s.user_id,
            "user_email": users_map.get(s.user_id, {}).get("email"),
            "user_name": users_map.get(s.user_id, {}).get("name"),
            "login_at": s.login_at, "last_seen_at": s.last_seen_at,
            "logout_at": s.logout_at, "ended_reason": s.ended_reason,
            "source_code_label": s.source_code_label, "usage_tier": s.usage_tier,
            "ip_address": s.ip_address,
        }
        for s in rows
    ]


@app.post("/api/auth/heartbeat")
def auth_heartbeat(user=Depends(get_current_user), db: Session = Depends(get_db)):
    """Update last_seen_at for the user's most recent active session."""
    uid = user.get("sub")
    org = user.get("org", default_tenant())
    try:
        sess = db.execute(
            select(UserSession).where(UserSession.user_id == uid, UserSession.org_slug == org, UserSession.logout_at == None)
            .order_by(UserSession.login_at.desc()).limit(1)
        ).scalar_one_or_none()
        if sess:
            sess.last_seen_at = now_ts()
            db.add(sess)
            db.commit()
    except Exception:
        logger.exception("HEARTBEAT_FAILED")
    return {"ok": True}


@app.post("/api/auth/logout")
def auth_logout(user=Depends(get_current_user), db: Session = Depends(get_db)):
    """End the user's current session."""
    uid = user.get("sub")
    org = user.get("org") or default_tenant()
    try:
        sess = db.execute(
            select(UserSession).where(UserSession.user_id == uid, UserSession.org_slug == org, UserSession.logout_at == None)
            .order_by(UserSession.login_at.desc()).limit(1)
        ).scalar_one_or_none()
        if sess:
            sess.logout_at = now_ts()
            sess.ended_reason = "logout"
            sess.duration_seconds = int(now_ts() - sess.login_at) if sess.login_at else None
            db.add(sess)
            db.commit()
    except Exception:
        logger.exception("LOGOUT_SESSION_FAILED")
    return {"ok": True}


# ── Admin Contact Requests ─────────────────────────────────────────────

@app.get("/api/admin/contacts")
def admin_list_contacts(admin=Depends(require_admin_access), db: Session = Depends(get_db)):
    """List all contact requests."""
    rows = db.execute(select(ContactRequest).order_by(ContactRequest.created_at.desc()).limit(200)).scalars().all()
    return [
        {
            "id": cr.id, "full_name": cr.full_name, "email": cr.email,
            "whatsapp": cr.whatsapp, "subject": cr.subject, "message": cr.message,
            "privacy_request_type": cr.privacy_request_type,
            "consent_terms": cr.consent_terms, "consent_marketing": cr.consent_marketing,
            "status": cr.status, "terms_version": cr.terms_version,
            "created_at": cr.created_at,
        }
        for cr in rows
    ]


@app.patch("/api/admin/contacts/{contact_id}")
def admin_update_contact(contact_id: str, status: str = "resolved", admin=Depends(require_admin_access), db: Session = Depends(get_db)):
    """Update contact request status."""
    cr = db.execute(select(ContactRequest).where(ContactRequest.id == contact_id)).scalar_one_or_none()
    if not cr:
        raise HTTPException(status_code=404, detail="Contact request not found")
    cr.status = status
    db.add(cr)
    db.commit()
    return {"ok": True, "id": cr.id, "status": cr.status}


# ── Admin Usage Events ─────────────────────────────────────────────────

@app.get("/api/admin/usage")
def admin_list_usage(
    days: int = 7,
    admin=Depends(require_admin_access),
    db: Session = Depends(get_db),
):
    """List usage events for the last N days."""
    org = admin.get("org", default_tenant())
    cutoff = now_ts() - (days * 86400)
    rows = db.execute(
        select(UsageEvent).where(UsageEvent.org_slug == org, UsageEvent.created_at >= cutoff)
        .order_by(UsageEvent.created_at.desc()).limit(500)
    ).scalars().all()
    return [
        {
            "id": ue.id, "user_id": ue.user_id, "event_type": ue.event_type,
            "tokens_used": ue.tokens_used, "duration_seconds": ue.duration_seconds,
            "created_at": ue.created_at,
        }
        for ue in rows
    ]


# ── Summit Mode info (public) ─────────────────────────────────────────

@app.get("/api/public/summit-info")
def public_summit_info():
    """Return Summit mode status for frontend conditional rendering."""
    return {
        "summit_mode": SUMMIT_MODE,
        "summit_expires_at": SUMMIT_EXPIRES_AT,
        "turnstile_required": bool(TURNSTILE_SECRET),
        "terms_version": TERMS_VERSION,
    }


# ── Admin Users management (enhanced for Summit) ──────────────────────

@app.get("/api/admin/users")
def admin_list_users(admin=Depends(require_admin_access), db: Session = Depends(get_db)):
    """List all users with Summit fields."""
    org = admin.get("org", default_tenant())
    rows = db.execute(select(User).where(User.org_slug == org).order_by(User.created_at.desc())).scalars().all()
    return [
        {
            "id": u.id, "email": u.email, "name": u.name, "role": u.role,
            "created_at": u.created_at, "approved_at": getattr(u, "approved_at", None),
            "signup_code_label": getattr(u, "signup_code_label", None),
            "signup_source": getattr(u, "signup_source", None),
            "usage_tier": getattr(u, "usage_tier", "summit_standard"),
            "terms_accepted_at": getattr(u, "terms_accepted_at", None),
            "terms_version": getattr(u, "terms_version", None),
            "marketing_consent": getattr(u, "marketing_consent", False),
        }
        for u in rows
    ]


@app.patch("/api/admin/users/{user_id}/tier")
def admin_update_user_tier(user_id: str, tier: str = "summit_standard", admin=Depends(require_admin_access), db: Session = Depends(get_db)):
    """Update a user's usage tier."""
    org = admin.get("org", default_tenant())
    u = db.execute(select(User).where(User.id == user_id, User.org_slug == org)).scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u.usage_tier = tier
    db.add(u)
    db.commit()
    return {"ok": True, "id": u.id, "usage_tier": tier}
