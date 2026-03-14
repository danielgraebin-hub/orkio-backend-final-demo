"""
PATCH0100_24 — Testes obrigatórios V2V
Cobre:
  1. chat_stream sempre emite 'done' (mesmo com LLM falhando)
  2. TTS resolve voz via message_id
  3. STT aceita audio/webm e retorna trace_id
  4. STT rejeita arquivo muito pequeno
  5. trace_id propagado no stream SSE
"""
import io
import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app, get_db, get_current_user, ensure_core_agents
from app.models import Base, Agent, Message, Thread

# ─── Fixtures ────────────────────────────────────────────────────────────────

def _setup_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)

def _user():
    return {"sub": "u1", "name": "Tester", "role": "user",
            "org": "acme", "email": "tester@acme.dev"}


# ─── TESTE 1: stream sempre emite done ───────────────────────────────────────

def test_stream_always_emits_done_on_llm_failure(monkeypatch):
    """gen() deve emitir error + done mesmo quando _openai_answer levanta exceção."""
    Session = _setup_db()

    def override_db():
        db = Session(); yield db; db.close()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = _user

    db = Session()
    ensure_core_agents(db, "acme")
    db.close()

    # Simular LLM falhando
    def broken_openai(*args, **kwargs):
        raise RuntimeError("OpenAI down for test")

    monkeypatch.setattr("app.main._openai_answer", broken_openai)

    client = TestClient(app)
    res = client.post(
        "/api/chat/stream",
        json={"message": "olá", "tenant": "acme"},
        headers={"Authorization": "Bearer test", "X-Org-Slug": "acme"},
    )
    assert res.status_code == 200, f"stream HTTP error: {res.status_code}"

    raw = res.text
    events = []
    for line in raw.split("\n"):
        line = line.strip()
        if line.startswith("event:"):
            events.append(line.split(":", 1)[1].strip())

    # REQUISITO CRÍTICO: done SEMPRE emitido
    assert "done" in events, f"'done' ausente nos eventos SSE: {events}"
    # Se LLM falhou, deve ter emitido error antes do done
    assert "error" in events, f"'error' ausente após falha do LLM: {events}"
    # done deve ser o ÚLTIMO evento
    assert events[-1] == "done", f"'done' não é o último evento: {events}"

    app.dependency_overrides.clear()


def test_stream_emits_done_on_success(monkeypatch):
    """gen() deve emitir done mesmo no caminho feliz."""
    Session = _setup_db()

    def override_db():
        db = Session(); yield db; db.close()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = _user

    db = Session()
    ensure_core_agents(db, "acme")
    db.close()

    monkeypatch.setattr("app.main._openai_answer",
                        lambda *a, **k: {"text": "Olá! Estou aqui.", "usage": {}})

    client = TestClient(app)
    res = client.post(
        "/api/chat/stream",
        json={"message": "oi", "tenant": "acme"},
        headers={"Authorization": "Bearer test", "X-Org-Slug": "acme"},
    )
    assert res.status_code == 200
    events = [l.split(":",1)[1].strip() for l in res.text.split("\n")
              if l.strip().startswith("event:")]
    assert "done" in events, f"done ausente: {events}"
    assert events[-1] == "done"


def test_stream_done_carries_trace_id(monkeypatch):
    """done global deve conter trace_id quando enviado pelo cliente."""
    Session = _setup_db()

    def override_db():
        db = Session(); yield db; db.close()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = _user

    db = Session()
    ensure_core_agents(db, "acme")
    db.close()

    monkeypatch.setattr("app.main._openai_answer",
                        lambda *a, **k: {"text": "Resposta teste", "usage": {}})

    client = TestClient(app)
    res = client.post(
        "/api/chat/stream",
        json={"message": "teste trace", "tenant": "acme", "trace_id": "trace-test-abc"},
        headers={"Authorization": "Bearer test", "X-Org-Slug": "acme"},
    )
    assert res.status_code == 200
    # Encontrar o done global e verificar trace_id
    done_data = None
    for block in res.text.split("\n\n"):
        lines = block.strip().split("\n")
        ev = next((l.split(":",1)[1].strip() for l in lines if l.startswith("event:")), None)
        raw = next((l.split(":",1)[1].strip() for l in lines if l.startswith("data:")), None)
        if ev == "done" and raw:
            try:
                d = json.loads(raw)
                if d.get("done") is True:
                    done_data = d
            except Exception:
                pass
    assert done_data is not None, "done global não encontrado"
    assert done_data.get("trace_id") == "trace-test-abc", f"trace_id errado: {done_data}"

    app.dependency_overrides.clear()


# ─── TESTE 2: TTS resolve voz via message_id ─────────────────────────────────

def test_tts_resolves_voice_by_message_id(monkeypatch):
    """TTS deve usar voice_id do agente do message_id, NÃO a voz enviada pelo cliente."""
    Session = _setup_db()

    def override_db():
        db = Session(); yield db; db.close()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = _user

    from app.main import new_id, now_ts
    db = Session()
    ensure_core_agents(db, "acme")

    agent = db.execute(
        __import__("sqlalchemy", fromlist=["select"]).select(Agent)
        .where(Agent.org_slug == "acme", Agent.is_default == True)
    ).scalar_one_or_none()
    assert agent, "Agente default não encontrado"

    # Setar voz específica no agente
    agent.voice_id = "echo"
    db.commit()

    t = Thread(id=new_id(), org_slug="acme", title="V2V Test", created_at=now_ts())
    db.add(t)
    db.commit()

    msg = Message(
        id=new_id(), org_slug="acme", thread_id=t.id,
        role="assistant", content="Olá mundo do V2V",
        agent_id=agent.id, agent_name=agent.name, created_at=now_ts(),
    )
    db.add(msg)
    db.commit()
    msg_id = msg.id
    db.close()

    # Capturar chamada ao OpenAI TTS
    captured = {}

    class FakeResponse:
        content = b"\xff\xfb" * 50  # MP3 mínimo válido

    class FakeAudio:
        def create(self, **kw):
            captured.update(kw)
            return FakeResponse()

    class FakeOpenAI:
        audio = FakeAudio()
        def __init__(self, **kw): pass

    monkeypatch.setattr("app.main.OpenAI", FakeOpenAI)

    client = TestClient(app)
    r = client.post(
        "/api/tts",
        json={"text": "Olá mundo do V2V", "voice": "alloy", "message_id": msg_id},
        headers={"Authorization": "Bearer test", "X-Org-Slug": "acme"},
    )

    assert r.status_code == 200, f"TTS falhou: {r.status_code} — {r.text[:200]}"
    # A voz deve ser "echo" (do agente), NÃO "alloy" (enviada pelo cliente)
    assert captured.get("voice") == "echo", (
        f"Voz errada: esperado 'echo' (do agente), obtido '{captured.get('voice')}'. "
        "message_id não foi resolvido para a voz correta."
    )
    assert captured.get("input") == "Olá mundo do V2V"

    # Verificar X-Trace-Id no response header
    assert "x-trace-id" in {k.lower() for k in r.headers.keys()}, \
        "Header X-Trace-Id ausente na resposta TTS"

    app.dependency_overrides.clear()


def test_tts_fallback_to_agent_id_when_no_message_id(monkeypatch):
    """TTS deve usar agent_id quando message_id não fornecido."""
    Session = _setup_db()

    def override_db():
        db = Session(); yield db; db.close()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = _user

    db = Session()
    ensure_core_agents(db, "acme")
    agent = db.execute(
        __import__("sqlalchemy", fromlist=["select"]).select(Agent)
        .where(Agent.org_slug == "acme", Agent.is_default == True)
    ).scalar_one_or_none()
    agent.voice_id = "fable"
    db.commit()
    agent_id = agent.id
    db.close()

    captured = {}

    class FakeResponse:
        content = b"\xff\xfb" * 50

    class FakeOpenAI:
        class audio:
            @staticmethod
            def create(**kw):
                captured.update(kw)
                return FakeResponse()
        def __init__(self, **kw): pass

    monkeypatch.setattr("app.main.OpenAI", FakeOpenAI)

    client = TestClient(app)
    r = client.post(
        "/api/tts",
        json={"text": "Teste fallback voz", "voice": "nova", "agent_id": agent_id},
        headers={"Authorization": "Bearer test", "X-Org-Slug": "acme"},
    )
    assert r.status_code == 200
    assert captured.get("voice") == "fable", \
        f"Esperado 'fable' (do agente via agent_id), obtido '{captured.get('voice')}'"

    app.dependency_overrides.clear()


# ─── TESTE 3: STT aceita audio/webm ──────────────────────────────────────────

def test_stt_accepts_webm_and_returns_trace_id(monkeypatch):
    """STT deve aceitar audio/webm e retornar {text, language, trace_id}."""
    Session = _setup_db()

    def override_db():
        db = Session(); yield db; db.close()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = _user

    class FakeTranscript:
        text = "olá mundo do V2V"

    class FakeTranscriptions:
        def create(self, **kw):
            return FakeTranscript()

    class FakeAudioOpenAI:
        transcriptions = FakeTranscriptions()

    class FakeOpenAI:
        audio = FakeAudioOpenAI()
        def __init__(self, **kw): pass

    monkeypatch.setattr("app.main.OpenAI", FakeOpenAI)

    # Criar blob webm mínimo (>100 bytes para passar validação)
    audio_blob = b"\x1a\x45\xdf\xa3" + b"\x00" * 200  # WebM magic bytes + padding

    client = TestClient(app)
    r = client.post(
        "/api/stt",
        files={"file": ("recording.webm", io.BytesIO(audio_blob), "audio/webm")},
        headers={"Authorization": "Bearer test", "X-Org-Slug": "acme"},
    )

    assert r.status_code == 200, f"STT falhou: {r.status_code} — {r.text}"
    body = r.json()
    assert body["text"] == "olá mundo do V2V", f"Texto errado: {body}"
    assert body["language"] == "pt"
    assert "trace_id" in body, "trace_id ausente na resposta STT"
    assert len(body["trace_id"]) > 0

    app.dependency_overrides.clear()


def test_stt_accepts_custom_trace_id(monkeypatch):
    """STT deve retornar o trace_id enviado pelo cliente via X-Trace-Id."""
    Session = _setup_db()

    def override_db():
        db = Session(); yield db; db.close()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = _user

    class FakeTranscript:
        text = "teste trace id"

    class FakeOpenAI:
        class audio:
            class transcriptions:
                @staticmethod
                def create(**kw): return FakeTranscript()
        def __init__(self, **kw): pass

    monkeypatch.setattr("app.main.OpenAI", FakeOpenAI)

    audio_blob = b"\x1a\x45\xdf\xa3" + b"\x00" * 200
    client = TestClient(app)
    r = client.post(
        "/api/stt",
        files={"file": ("audio.webm", io.BytesIO(audio_blob), "audio/webm")},
        headers={
            "Authorization": "Bearer test",
            "X-Org-Slug": "acme",
            "X-Trace-Id": "my-custom-trace-123",
        },
    )

    assert r.status_code == 200
    body = r.json()
    assert body["trace_id"] == "my-custom-trace-123", \
        f"trace_id personalizado não retornado: {body}"

    app.dependency_overrides.clear()


def test_stt_rejects_too_small_file(monkeypatch):
    """STT deve rejeitar arquivos < 100 bytes (gravação falhou)."""
    Session = _setup_db()

    def override_db():
        db = Session(); yield db; db.close()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = _user

    monkeypatch.setattr("app.main.OpenAI", lambda **kw: None)

    client = TestClient(app)
    r = client.post(
        "/api/stt",
        files={"file": ("audio.webm", io.BytesIO(b"\x00" * 50), "audio/webm")},
        headers={"Authorization": "Bearer test", "X-Org-Slug": "acme"},
    )
    assert r.status_code == 400, f"Esperado 400, obtido {r.status_code}"
    assert "too short" in r.json()["detail"].lower() or "small" in r.json()["detail"].lower()

    app.dependency_overrides.clear()


def test_stt_rejects_unsupported_format():
    """STT deve rejeitar formatos não suportados."""
    Session = _setup_db()

    def override_db():
        db = Session(); yield db; db.close()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = _user

    client = TestClient(app)
    r = client.post(
        "/api/stt",
        files={"file": ("virus.exe", io.BytesIO(b"\x4d\x5a" + b"\x00" * 200), "application/octet-stream")},
        headers={"Authorization": "Bearer test", "X-Org-Slug": "acme"},
    )
    assert r.status_code == 400
    assert "unsupported" in r.json()["detail"].lower()

    app.dependency_overrides.clear()
