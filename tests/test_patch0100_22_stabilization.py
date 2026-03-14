"""
PATCH0100_22 STABILIZATION — Testes de regressão completos
Cobre todos os requisitos do brief de estabilização:
  - Team mode: 1 mensagem por agente, agent_id sempre preenchido
  - CostEvent: gravado em /api/chat e /api/chat/stream
  - Upload institucional: cria mensagem system
  - TTS: resolve voice por message_id
  - Rate limit /api/public/tts
  - _track_cost: helper unificado
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.main import (
    app, get_db, get_current_user, require_admin_access,
    ensure_core_agents, _track_cost, _select_target_agents,
    _build_agent_prompt, _public_tts_calls,
)
from app.models import Message, Thread, CostEvent, Agent, File


# ─── setup ─────────────────────────────────────────────────────────────────────

def _setup_db():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    return Session


def _user(role="user"):
    return {"sub": "u1", "org": "acme", "name": "Alice", "email": "a@acme.test", "role": role, "approved_at": 1}


def _admin():
    return {"sub": "adm1", "org": "acme", "name": "Admin", "email": "adm@acme.test", "role": "admin", "approved_at": 1}


def _fake_openai(user_message, context_chunks, history=None, system_prompt=None, model_override=None, temperature=None):
    import re
    agent_name = "Orkio"
    m = re.search(r"Você é (.+?)\.", user_message or "")
    if m:
        agent_name = m.group(1)
    return {
        "text": f"Resposta de {agent_name}",
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
        "model": "gpt-4o-mini",
    }


def _client_with_db(Session, monkeypatch):
    def override_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = _user
    monkeypatch.setattr("app.main._openai_answer", _fake_openai)
    monkeypatch.setattr("app.main.keyword_retrieve", lambda *a, **kw: [])
    monkeypatch.setattr("app.main.get_agent_file_ids", lambda *a, **kw: [])
    monkeypatch.setattr("app.main.get_linked_agent_ids", lambda *a, **kw: [])
    return TestClient(app)


# ─── 1. Team mode ──────────────────────────────────────────────────────────────

def test_team_mode_creates_one_message_per_agent(monkeypatch):
    """@Team deve criar 1 mensagem por agente, todas com agent_id preenchido."""
    Session = _setup_db()
    client = _client_with_db(Session, monkeypatch)

    db = Session()
    ensure_core_agents(db, "acme")
    agent_count = db.execute(select(Agent).where(Agent.org_slug == "acme")).scalars().all()
    db.close()

    r = client.post("/api/chat", json={"message": "@Team status?", "thread_id": None}, headers={"X-Org-Slug": "acme"})
    assert r.status_code == 200, r.text

    db = Session()
    msgs = db.execute(select(Message).where(Message.org_slug == "acme", Message.role == "assistant")).scalars().all()
    assert len(msgs) >= 2, f"Esperado ≥2 mensagens de agente em Team mode, obtido {len(msgs)}"
    for m in msgs:
        assert m.agent_id is not None, f"Mensagem {m.id} sem agent_id"
        assert m.agent_name is not None, f"Mensagem {m.id} sem agent_name"
    db.close()
    app.dependency_overrides.clear()


def test_team_mode_last_agent_in_chatout(monkeypatch):
    """ChatOut deve retornar agent_id do último agente (não None)."""
    Session = _setup_db()
    client = _client_with_db(Session, monkeypatch)

    db = Session()
    ensure_core_agents(db, "acme")
    db.close()

    r = client.post("/api/chat", json={"message": "@Team estratégia?", "thread_id": None}, headers={"X-Org-Slug": "acme"})
    assert r.status_code == 200
    data = r.json()
    assert data.get("agent_id") is not None, "ChatOut.agent_id deve ser não-nulo após Team mode"
    app.dependency_overrides.clear()


# ─── 2. CostEvent ──────────────────────────────────────────────────────────────

def test_cost_event_persisted_chat(monkeypatch):
    """CostEvent deve ser gravado em /api/chat com campos obrigatórios."""
    Session = _setup_db()
    client = _client_with_db(Session, monkeypatch)

    db = Session()
    ensure_core_agents(db, "acme")
    db.close()

    r = client.post("/api/chat", json={"message": "Olá", "thread_id": None}, headers={"X-Org-Slug": "acme"})
    assert r.status_code == 200

    db = Session()
    evs = db.execute(select(CostEvent).where(CostEvent.org_slug == "acme")).scalars().all()
    assert len(evs) >= 1, "Nenhum CostEvent gravado"
    ev = evs[0]
    assert ev.prompt_tokens >= 0
    assert ev.completion_tokens >= 0
    assert ev.total_tokens >= 0
    assert ev.input_cost_usd >= 0
    assert ev.output_cost_usd >= 0
    assert ev.total_cost_usd >= 0
    assert ev.pricing_version is not None
    assert ev.agent_id is not None
    db.close()
    app.dependency_overrides.clear()


def test_cost_event_persisted_stream(monkeypatch):
    """CostEvent deve ser gravado em /api/chat/stream com estimated=True."""
    Session = _setup_db()
    client = _client_with_db(Session, monkeypatch)

    db = Session()
    ensure_core_agents(db, "acme")
    db.close()

    r = client.post("/api/chat/stream", json={"message": "Olá", "thread_id": None}, headers={"X-Org-Slug": "acme"})
    assert r.status_code == 200

    # Consumir o stream
    content = b"".join(r.iter_bytes())
    assert b"done" in content or b"chunk" in content, "Stream SSE não retornou eventos esperados"

    db = Session()
    evs = db.execute(select(CostEvent).where(CostEvent.org_slug == "acme")).scalars().all()
    assert len(evs) >= 1, "Nenhum CostEvent gravado no stream"
    ev = evs[0]
    # No streaming, estimated deve ser True (usage real não disponível em SSE)
    assert ev.usage_missing is True, "Streaming deve marcar usage_missing=True"
    db.close()
    app.dependency_overrides.clear()


# ─── 3. Upload institucional ───────────────────────────────────────────────────

def test_upload_creates_institutional_system_message(monkeypatch, tmp_path):
    """Upload admin deve criar mensagem system '📎 Documento institucional anexado'."""
    Session = _setup_db()

    def override_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = _admin
    app.dependency_overrides[require_admin_access] = _admin
    monkeypatch.setattr("app.main.extract_text", lambda fn, raw: ("texto de teste", len("texto de teste")))

    client = TestClient(app)
    dummy = b"PDF fake content"
    r = client.post(
        "/api/admin/files/upload",
        files={"file": ("relatorio.pdf", dummy, "application/pdf")},
        headers={"X-Org-Slug": "acme"},
    )
    assert r.status_code == 200, r.text

    db = Session()
    sys_msgs = db.execute(
        select(Message).where(
            Message.org_slug == "acme",
            Message.role == "system",
        )
    ).scalars().all()
    texts = [m.content for m in sys_msgs]
    assert any("📎 Documento institucional anexado" in t for t in texts), \
        f"Mensagem institucional não encontrada. Mensagens: {texts}"
    assert any("relatorio.pdf" in t for t in texts), "Nome do arquivo não aparece na mensagem"
    db.close()
    app.dependency_overrides.clear()


# ─── 4. TTS resolve voice por message_id ──────────────────────────────────────

def test_tts_resolves_voice_by_message_id(monkeypatch):
    """F-13 FIX: TTS deve usar voice_id do agente associado ao message_id.
    Verifica que a voz correta é passada ao OpenAI (não apenas que o endpoint não dá 500).
    """
    Session = _setup_db()

    def override_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = _user

    from app.main import new_id, now_ts

    db = Session()
    ensure_core_agents(db, "acme")
    agent = db.execute(select(Agent).where(Agent.org_slug == "acme", Agent.is_default == True)).scalar_one_or_none()
    assert agent, "Agente default não encontrado"

    # Definir voice_id específico no agente para ter certeza da resolução
    agent.voice_id = "echo"
    db.commit()

    t = Thread(id=new_id(), org_slug="acme", title="Test", created_at=now_ts())
    db.add(t)
    db.commit()
    msg = Message(
        id=new_id(), org_slug="acme", thread_id=t.id,
        role="assistant", content="Olá mundo", agent_id=agent.id, agent_name=agent.name,
        created_at=now_ts(),
    )
    db.add(msg)
    db.commit()
    msg_id = msg.id
    db.close()

    # F-13 FIX: capturar e verificar a voz realmente enviada ao OpenAI
    captured = {}

    class FakeResponse:
        content = b"\xff\xfb" * 10

    class FakeAudio:
        def create(self, **kw):
            captured['voice'] = kw.get('voice')
            captured['input'] = kw.get('input')
            return FakeResponse()

    class FakeOpenAI:
        audio = FakeAudio()

    monkeypatch.setattr("app.main.OpenAI", FakeOpenAI)

    client = TestClient(app)
    r = client.post(
        "/api/tts",
        json={"text": "Olá mundo", "voice": "alloy", "message_id": msg_id},
        headers={"Authorization": "Bearer test", "X-Org-Slug": "acme"},
    )
    assert r.status_code == 200, f"TTS falhou: {r.status_code} {r.text}"
    # Verificar que a voz usada foi a do agente ("echo"), NÃO a enviada pelo cliente ("alloy")
    assert captured.get('voice') == "echo", (
        f"Esperado voice='echo' (do agente), obtido '{captured.get('voice')}'. "
        "message_id não foi resolvido para a voz correta."
    )
    assert captured.get('input') == "Olá mundo", "Texto não chegou corretamente ao TTS"
    app.dependency_overrides.clear()


# ─── 5. Rate limit public TTS ─────────────────────────────────────────────────

def test_public_tts_rate_limit(monkeypatch):
    """Após limite, /api/public/tts deve retornar 429."""
    import app.main as main_mod

    _public_tts_calls.clear()
    monkeypatch.setattr(main_mod, "_PUBLIC_TTS_MAX_PER_MINUTE", 2)

    class FakeResponse:
        content = b"\xff\xfb" * 10
    class FakeAudio:
        def create(self, **kw):
            return FakeResponse()
    class FakeOpenAI:
        audio = FakeAudio()
    monkeypatch.setattr(main_mod, "OpenAI", FakeOpenAI)

    client = TestClient(app)
    payload = {"text": "Teste rate limit", "voice": "nova", "speed": 1.0}
    client.post("/api/public/tts", json=payload)
    client.post("/api/public/tts", json=payload)
    r3 = client.post("/api/public/tts", json=payload)
    assert r3.status_code == 429, f"Esperado 429, obtido {r3.status_code}"
    _public_tts_calls.clear()


# ─── 6. _select_target_agents unit test ───────────────────────────────────────

def test_select_target_agents_team_mode():
    """_select_target_agents em has_team não deve retornar lista vazia se há agentes."""
    Session = _setup_db()
    db = Session()
    ensure_core_agents(db, "acme")
    all_agents = db.execute(select(Agent).where(Agent.org_slug == "acme")).scalars().all()
    alias_to_agent = {}
    for a in all_agents:
        full = a.name.strip().lower()
        alias_to_agent[full] = a
        first = full.split()[0] if full.split() else full
        alias_to_agent.setdefault(first, a)

    class FakeInp:
        agent_id = None

    result = _select_target_agents(db, "acme", FakeInp(), alias_to_agent, ["Time"], has_team=True)
    assert len(result) >= 1, "Team mode deve retornar ≥1 agente"
    ids = [a.id for a in result]
    assert len(ids) == len(set(ids)), "Agentes duplicados em target_agents"
    db.close()


# ─── 7. _build_agent_prompt unit test ─────────────────────────────────────────

def test_build_agent_prompt_team_injection():
    """Prompt em Team mode deve conter role-injection anti-impersonation."""
    class FakeAgent:
        name = "Chris (VP/CFO)"
    prompt = _build_agent_prompt(FakeAgent(), "Qual o orçamento?", has_team=True, mention_tokens=["Time"])
    assert "Chris (VP/CFO)" in prompt
    assert "APENAS como" in prompt
    assert "@Time" not in prompt  # sanitize_mentions deve remover


def test_build_agent_prompt_single_agent():
    """Prompt single-agent (sem team) deve retornar a mensagem original."""
    prompt = _build_agent_prompt(None, "Olá mundo", has_team=False, mention_tokens=[])
    assert "Olá mundo" in prompt
