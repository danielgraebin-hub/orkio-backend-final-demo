from __future__ import annotations

import json
from typing import Any, Dict, Iterable

_GENERIC_MARKERS = (
    "isso depende",
    "de forma geral",
    "em resumo",
    "posso ajudar",
)

def _clean_text(value: Any) -> str:
    return " ".join(str(value or "").replace("\r", "\n").split()).strip()

def assess_realtime_session(events: Iterable[Any], meta: Dict[str, Any] | None = None) -> Dict[str, Any]:
    meta = meta or {}
    items = list(events or [])
    finals = [ev for ev in items if ((getattr(ev, "event_type", "") or "").endswith(".final")) and _clean_text(getattr(ev, "content", None))]
    user_events = [ev for ev in finals if getattr(ev, "role", None) == "user"]
    assistant_events = [ev for ev in finals if getattr(ev, "role", None) != "user"]

    first_response_ms = None
    if user_events and assistant_events:
        first_response_ms = max(0, int(getattr(assistant_events[0], "created_at", 0) or 0) - int(getattr(user_events[0], "created_at", 0) or 0))

    duplicate_count = 0
    last_assistant = None
    truncation_count = 0
    genericity_count = 0
    for ev in assistant_events:
        text = _clean_text(getattr(ev, "content", None))
        if not text:
            continue
        if text == last_assistant:
            duplicate_count += 1
        last_assistant = text
        if text.endswith("...") or len(text) < 18:
            truncation_count += 1
        low = text.lower()
        if any(marker in low for marker in _GENERIC_MARKERS):
            genericity_count += 1

    try:
        human = (meta.get("summit_review") or {}) if isinstance(meta, dict) else {}
    except Exception:
        human = {}

    return {
        "first_response_ms": first_response_ms,
        "duplicate_count": duplicate_count,
        "truncation_count": truncation_count,
        "genericity_count": genericity_count,
        "language_profile": meta.get("language_profile"),
        "mode": meta.get("mode"),
        "response_profile": meta.get("response_profile"),
        "persona_score": max(1, 5 - genericity_count),
        "naturalness_score": max(1, 5 - duplicate_count - truncation_count),
        "human_review": human,
    }

def merge_human_review(meta: Dict[str, Any] | None, review: Dict[str, Any]) -> Dict[str, Any]:
    base = dict(meta or {})
    base["summit_review"] = {k: v for k, v in (review or {}).items() if v is not None}
    return base
