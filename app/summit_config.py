from __future__ import annotations

import os
from typing import Any, Dict

_ALLOWED_MODES = {"platform", "summit"}
_ALLOWED_RESPONSE_PROFILES = {"default", "stage"}
_ALLOWED_LANGUAGES = {"auto", "pt-BR", "en"}


def normalize_mode(value: str | None) -> str:
    raw = (value or os.getenv("ORKIO_RUNTIME_MODE", "platform")).strip()
    return raw if raw in _ALLOWED_MODES else "platform"


def normalize_response_profile(value: str | None) -> str:
    raw = (value or os.getenv("SUMMIT_RESPONSE_PROFILE", "stage")).strip()
    return raw if raw in _ALLOWED_RESPONSE_PROFILES else "stage"


def normalize_language_profile(value: str | None) -> str:
    raw = (value or os.getenv("SUMMIT_LANGUAGE_PROFILE", "pt-BR")).strip()
    return raw if raw in _ALLOWED_LANGUAGES else "pt-BR"


def resolve_realtime_transcription_language(language_profile: str | None) -> str | None:
    language = normalize_language_profile(language_profile)

    if language == "auto":
        return None
    if language == "pt-BR":
        return "pt"
    return language


def get_summit_runtime_config(
    *,
    mode: str | None = None,
    response_profile: str | None = None,
    language_profile: str | None = None,
) -> Dict[str, Any]:
    runtime_mode = normalize_mode(mode)
    profile = normalize_response_profile(response_profile)
    language = normalize_language_profile(language_profile)

    transcription_language = resolve_realtime_transcription_language(language)
    short_answers = runtime_mode == "summit" and profile == "stage"

    return {
        "mode": runtime_mode,
        "response_profile": profile,
        "language_profile": language,
        "transcription_language": transcription_language,
        "max_sentences": 3 if short_answers else 6,
        "target_style": "institutional_stage" if runtime_mode == "summit" else "platform_default",
        "stage_guidance": {
            "short_answers": short_answers,
            "avoid_bullets": runtime_mode == "summit",
            "avoid_jargon": runtime_mode == "summit",
            "connect_to_vision": runtime_mode == "summit",
        },
    }
