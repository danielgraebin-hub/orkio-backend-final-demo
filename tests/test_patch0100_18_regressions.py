import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.main import app, get_db, get_current_user, require_admin_access
from app.main import ensure_core_agents
from app.models import Message, Thread, CostEvent


def setup_test_db():
    engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    return TestingSessionLocal


def test_team_mode_creates_one_message_per_agent(monkeypatch):
    SessionLocal = setup_test_db()

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    def override_user():
        return {"sub": "u1", "org": "acme", "name": "Alice", "email": "alice@acme.test", "role": "admin", "approved_at": 1}

    def fake_openai_answer(user_message, context_chunks, history=None, system_prompt=None, model_override=None, temperature=None):
        assert "@Chris" not in user_message
        assert "@Orkio" not in user_message
        assert "@Orion" not in user_message
        if "APENAS como" in user_message:
            who = user_message.split("APENAS como ", 1)[1].split(".", 1)[0]
        else:
            who = "Agente"
        return {"text": f"Resposta individual de {who}", "usage": None, "model": "gpt-4o-mini"}

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    monkeypatch.setattr("app.main._openai_answer", fake_openai_answer)

    with SessionLocal() as db:
        ensure_core_agents(db, "acme")

    client = TestClient(app)
    r = client.post("/api/chat", json={"message": "@Team Apresentem-se"})
    assert r.status_code == 200, r.text

    with SessionLocal() as db:
        msgs = db.execute(select(Message).where(Message.role == "assistant").order_by(Message.created_at.asc())).scalars().all()
        assert len(msgs) == 3
        assert len({m.agent_id for m in msgs}) == 3
        assert all((m.content or "").startswith("Resposta individual") for m in msgs)

        costs = db.execute(select(CostEvent)).scalars().all()
        assert len(costs) == 3

    app.dependency_overrides.clear()


def test_admin_institutional_upload_registers_chat_message():
    SessionLocal = setup_test_db()

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    def override_admin():
        return {"sub": "admin1", "org": "acme", "name": "Admin", "email": "admin@acme.test", "role": "admin"}

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[require_admin_access] = override_admin

    with SessionLocal() as db:
        ensure_core_agents(db, "public")

    client = TestClient(app)
    r = client.post(
        "/api/admin/files/upload",
        files={"file": ("manual.txt", b"conteudo institucional", "text/plain")},
    )
    assert r.status_code == 200, r.text

    with SessionLocal() as db:
        inst_thread = db.execute(select(Thread).where(Thread.title == "📚 Documentos Institucionais")).scalar_one_or_none()
        assert inst_thread is not None
        msg = db.execute(
            select(Message).where(Message.thread_id == inst_thread.id).order_by(Message.created_at.desc())
        ).scalars().first()
        assert msg is not None
        assert "📎 Documento institucional anexado: manual.txt" in (msg.content or "")

    app.dependency_overrides.clear()
