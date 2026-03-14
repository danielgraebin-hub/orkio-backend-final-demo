"""
PATCH0100_14 — Enterprise-grade Pricing Registry (versionado, sem env vars)

Responsabilidades:
  - normalize_model_name(model) -> str
  - get_pricing(model, provider) -> dict
  - calculate_cost(model, prompt_tokens, completion_tokens, provider) -> (input_usd, output_usd, total_usd, snapshot)
"""

from __future__ import annotations

import re
import logging
from typing import Dict, Optional, Tuple, Any

logger = logging.getLogger("orkio.pricing_registry")

PRICING_VERSION = "2026-02-18"

# Preços por 1k tokens (USD)
MODEL_PRICING: Dict[str, Dict[str, float]] = {
    # OpenAI chat models
    "gpt-4o-mini": {"input_per_1k": 0.000150, "output_per_1k": 0.000600},
    # F-14 FIX: TTS models — custo por 1k caracteres de input (output é áudio, sem token count)
    # Preço do gpt-4o-mini-tts: $0.015 / 1k chars input (OpenAI pricing fev/2026)
    # Mapeado em input_per_1k para compatibilidade com calc pipeline existente
    "gpt-4o-mini-tts": {"input_per_1k": 0.015000, "output_per_1k": 0.000000},
    "tts-1": {"input_per_1k": 0.015000, "output_per_1k": 0.000000},
    "tts-1-hd": {"input_per_1k": 0.030000, "output_per_1k": 0.000000},
    "gpt-4o": {"input_per_1k": 0.005000, "output_per_1k": 0.015000},
    "gpt-4-turbo": {"input_per_1k": 0.010000, "output_per_1k": 0.030000},
    "gpt-4": {"input_per_1k": 0.030000, "output_per_1k": 0.060000},
    "gpt-3.5-turbo": {"input_per_1k": 0.000500, "output_per_1k": 0.001500},
    "gpt-4.1-mini": {"input_per_1k": 0.000400, "output_per_1k": 0.001600},
    "gpt-4.1": {"input_per_1k": 0.002000, "output_per_1k": 0.008000},
    "gpt-4.1-nano": {"input_per_1k": 0.000100, "output_per_1k": 0.000400},
    "o3-mini": {"input_per_1k": 0.001100, "output_per_1k": 0.004400},
    "o1-mini": {"input_per_1k": 0.001100, "output_per_1k": 0.004400},
    "o1": {"input_per_1k": 0.015000, "output_per_1k": 0.060000},
    # Anthropic
    "claude-3-5-sonnet": {"input_per_1k": 0.003000, "output_per_1k": 0.015000},
    "claude-3-5-haiku": {"input_per_1k": 0.000800, "output_per_1k": 0.004000},
    "claude-3-opus": {"input_per_1k": 0.015000, "output_per_1k": 0.075000},
    # Google
    "gemini-1.5-pro": {"input_per_1k": 0.003500, "output_per_1k": 0.010500},
    "gemini-1.5-flash": {"input_per_1k": 0.000350, "output_per_1k": 0.001050},
    "gemini-2.0-flash": {"input_per_1k": 0.000100, "output_per_1k": 0.000400},
    # Perplexity
    "sonar": {"input_per_1k": 0.001000, "output_per_1k": 0.001000},
}

# Aliases
_ALIASES: Dict[str, str] = {
    "gpt-5": "gpt-4o",
    "gpt-5-mini": "gpt-4o-mini",
    "gpt-5-nano": "gpt-4o-mini",
    "chatgpt-4o-latest": "gpt-4o",
}

DEFAULT_FALLBACK = "gpt-4o-mini"


def normalize_model_name(model: str) -> str:
    """Remove date suffixes, normalize separators."""
    m = (model or "").strip()
    if not m:
        return ""
    m = re.sub(r"-(20\d{2})-(\d{2})-(\d{2})$", "", m)
    m = re.sub(r"-(20\d{2})(\d{2})(\d{2})$", "", m)
    m = re.sub(r"-(20\d{2})-(\d{2})$", "", m)
    m = re.sub(r"--+", "-", m)
    return m


def get_pricing(model: str, provider: Optional[str] = None) -> Dict[str, float]:
    """Get pricing dict for a model. Falls back to gpt-4o-mini if unknown."""
    normalized = normalize_model_name(model)
    # Check direct match
    if normalized in MODEL_PRICING:
        return MODEL_PRICING[normalized]
    # Check aliases
    alias = _ALIASES.get(normalized)
    if alias and alias in MODEL_PRICING:
        return MODEL_PRICING[alias]
    # Fallback
    logger.warning("PRICING_FALLBACK model=%s normalized=%s -> using %s", model, normalized, DEFAULT_FALLBACK)
    return MODEL_PRICING[DEFAULT_FALLBACK]


def calculate_cost(
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    provider: Optional[str] = None,
) -> Tuple[float, float, float, Dict[str, Any]]:
    """
    Calculate immutable cost at generation time.

    Returns: (input_usd, output_usd, total_usd, snapshot_dict)
    """
    normalized = normalize_model_name(model)
    pricing = get_pricing(model, provider)

    input_per_1k = pricing["input_per_1k"]
    output_per_1k = pricing["output_per_1k"]

    input_usd = (int(prompt_tokens or 0) / 1000.0) * input_per_1k
    output_usd = (int(completion_tokens or 0) / 1000.0) * output_per_1k
    total_usd = input_usd + output_usd

    snapshot = {
        "model": normalized,
        "input_per_1k": input_per_1k,
        "output_per_1k": output_per_1k,
        "source": "internal_registry",
        "pricing_version": PRICING_VERSION,
    }

    return round(input_usd, 8), round(output_usd, 8), round(total_usd, 8), snapshot
