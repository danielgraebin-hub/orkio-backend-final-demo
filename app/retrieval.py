from __future__ import annotations
import re
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import select

from .models import FileChunk, File

def _terms(q: str) -> List[str]:
    raw = re.findall(r"[A-Za-zÀ-ÿ0-9]{3,}", q or "")
    # normalize
    return [t.lower() for t in raw][:12]

def keyword_retrieve(
    db: Session,
    org_slug: str,
    query: str,
    top_k: int = 6,
    file_ids: List[str] | None = None,
) -> List[Dict[str, Any]]:
    terms = _terms(query)
    if not terms:
        return []

    q = select(FileChunk).where(FileChunk.org_slug == org_slug)
    if file_ids:
        q = q.where(FileChunk.file_id.in_(list(file_ids)))
    # Pull a reasonable window of chunks; rank in Python (deterministic)
    chunks = db.execute(q.order_by(FileChunk.created_at.desc()).limit(500)).scalars().all()

    scored = []
    for c in chunks:
        text = (c.content or "").lower()
        score = sum(text.count(t) for t in terms)
        if score > 0:
            scored.append((score, c))

    scored.sort(key=lambda x: x[0], reverse=True)
    picked = [c for _, c in scored[: max(1, top_k)]]

    # Load filenames for citations
    picked_file_ids = {c.file_id for c in picked}
    files = {}
    if picked_file_ids:
        for f in db.execute(select(File).where(File.org_slug == org_slug, File.id.in_(list(picked_file_ids)))).scalars().all():
            files[f.id] = f

    out = []
    for c in picked:
        f = files.get(c.file_id)
        out.append(
            {
                "file_id": c.file_id,
                "filename": f.filename if f else None,
                "chunk_id": c.id,
                "content": c.content,
                "score": None,
            }
        )
    return out

