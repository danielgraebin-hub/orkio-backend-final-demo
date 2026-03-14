from __future__ import annotations

import os
import json
import logging
from typing import Iterable, Optional, List

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

try:
    from openai import OpenAI
except Exception:  # pragma: no cover
    OpenAI = None  # type: ignore

from app.db import SessionLocal
from app.models import RealtimeEvent

logger = logging.getLogger(__name__)


def _punctuate_with_openai(text: str) -> Optional[str]:
    """Return a punctuated version of the text, or None if not available."""
    key = os.getenv("OPENAI_API_KEY", "").strip()
    if not key or OpenAI is None:
        return None

    model = os.getenv("OPENAI_PUNCTUATE_MODEL", "").strip() or os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()
    client = OpenAI(api_key=key)

    system = (
        "Você é um pontuador profissional. "
        "Sua tarefa é APENAS adicionar pontuação, capitalização e quebras de linha leves quando fizer sentido. "
        "Não mude o significado, não reescreva, não adicione palavras. "
        "Retorne somente o texto pontuado, sem aspas e sem explicações."
    )

    try:
        # Use Chat Completions for broad compatibility with the existing codebase
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": text},
            ],
            temperature=0,
            max_tokens=min(2048, max(256, len(text) // 2)),
        )
        out = (resp.choices[0].message.content or "").strip()
        return out or None
    except Exception:
        logger.exception("punctuate_openai_failed")
        return None


def punctuate_realtime_events(org_slug: str, event_ids: Iterable[str]) -> None:
    """Best-effort async job.
    - Loads realtime_events by id
    - For each event with content, stores transcript_punct (OpenAI or fallback = content)
    Never raises to caller.
    """
    if SessionLocal is None:
        return

    ids: List[str] = [str(i) for i in event_ids if i]
    if not ids:
        return

    db = SessionLocal()
    try:
        rows = db.execute(
            select(RealtimeEvent).where(
                RealtimeEvent.org_slug == org_slug,
                RealtimeEvent.id.in_(ids),
            )
        ).scalars().all()

        for ev in rows:
            try:
                # Only punctuate finals; caller should filter, but keep safe here too
                if not (ev.event_type or "").endswith(".final"):
                    continue
                if not (ev.content or "").strip():
                    continue
                # Idempotent
                if getattr(ev, "transcript_punct", None):
                    continue

                punct = _punctuate_with_openai(ev.content)
                ev.transcript_punct = punct or ev.content
            except Exception:
                # Never break the batch
                logger.exception("punctuate_row_failed id=%s", getattr(ev, "id", None))

        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("punctuate_db_failed")
    except Exception:
        db.rollback()
        logger.exception("punctuate_failed")
    finally:
        try:
            db.close()
        except Exception:
            pass
