from __future__ import annotations

import os
import re
import time
import json
import logging
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


logger = logging.getLogger("orkio")


# --- Helpers

def now_ts() -> int:
    return int(time.time())


def normalize_model(model: str) -> str:
    """Normalize model names to improve pricing lookup stability.

    Examples:
      - gpt-4o-mini-2024-07-18 -> gpt-4o-mini
      - gpt-4.1-mini-2025-01-01 -> gpt-4.1-mini
      - claude-3-5-sonnet-20240620 -> claude-3-5-sonnet
    """
    m = (model or "").strip()
    if not m:
        return ""

    # Remove common date suffixes: -YYYY-MM-DD or -YYYYMMDD
    m = re.sub(r"-(20\d{2})-(\d{2})-(\d{2})$", "", m)
    m = re.sub(r"-(20\d{2})(\d{2})(\d{2})$", "", m)
    m = re.sub(r"-(20\d{2})-(\d{2})$", "", m)

    # Some providers put "latest" or "preview" suffixes; keep them if present
    # (pricing may differ), but normalize duplicated separators.
    m = re.sub(r"--+", "-", m)
    return m


def detect_provider(provider: Optional[str], model: str) -> str:
    p = (provider or "").strip().lower()
    if p:
        return p
    m = (model or "").lower()
    if "claude" in m or "anthropic" in m:
        return "anthropic"
    if "gemini" in m or m.startswith("google/"):
        return "google"
    if "sonar" in m or "perplex" in m:
        return "perplexity"
    return "openai"


@dataclass
class ModelRates:
    input_per_1m: float
    output_per_1m: float
    currency: str = "USD"
    source: str = "fallback"
    fetched_at: int = 0


class PricingRegistry:
    """In-memory pricing registry with TTL.

    Requirements:
      - Default TTL 6h (env PRICING_CACHE_TTL_HOURS)
      - Best-effort refresh (web) but NEVER break chat if refresh fails
      - Safe hardcoded fallback (at least gpt-4o-mini)
    """

    def __init__(self):
        self._ttl_s = int(float(os.getenv("PRICING_CACHE_TTL_HOURS", "6")) * 3600)
        if self._ttl_s < 300:
            self._ttl_s = 300
        self._last_refresh: int = 0
        self._rates: Dict[str, Dict[str, ModelRates]] = {}
        self._load_fallbacks()

    def _load_fallbacks(self):
        # USD / 1M tokens (official at time of patch, used as safe fallback)
        # Values can be refreshed online; these prevent USD=0 regressions.
        self._rates = {
            "openai": {
                "gpt-4o-mini": ModelRates(0.15, 0.60, source="fallback:hardcoded"),
                "gpt-4o": ModelRates(5.00, 15.00, source="fallback:hardcoded"),
                # Prepare future family (placeholders -> map to nearest known cost)
                "gpt-5": ModelRates(5.00, 15.00, source="fallback:alias"),
                "gpt-5-mini": ModelRates(0.15, 0.60, source="fallback:alias"),
                "gpt-5-nano": ModelRates(0.15, 0.60, source="fallback:alias"),
            },
            # Provider scaffolding (real pricing can be added later without refactor)
            "anthropic": {
                "claude-3-5-sonnet": ModelRates(3.00, 15.00, source="fallback:placeholder"),
                "claude-3-5-haiku": ModelRates(0.80, 4.00, source="fallback:placeholder"),
            },
            "google": {
                "gemini-1.5-pro": ModelRates(3.50, 10.50, source="fallback:placeholder"),
                "gemini-1.5-flash": ModelRates(0.35, 1.05, source="fallback:placeholder"),
            },
            "perplexity": {
                "sonar": ModelRates(1.00, 1.00, source="fallback:placeholder"),
            },
        }

    def _expired(self) -> bool:
        return (now_ts() - int(self._last_refresh or 0)) > self._ttl_s

    def _refresh_if_needed(self):
        if not self._expired():
            return
        # Best-effort refresh; keep fallbacks if anything fails
        try:
            self._refresh_openai_best_effort()
        except Exception:
            logger.exception("PRICING_REFRESH_FAILED")
        finally:
            self._last_refresh = now_ts()

    def _refresh_openai_best_effort(self):
        """Best-effort refresh from public pages. Tolerant parsing."""
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

        # Very tolerant parsing: around model name, capture $ numbers
        def find_prices(model_name: str) -> Optional[Tuple[float, float]]:
            try:
                m = re.search(re.escape(model_name) + r"(.{0,1200})", html, flags=re.IGNORECASE | re.DOTALL)
                if not m:
                    return None
                window = m.group(1)
                nums = re.findall(r"\$\s*([0-9]+(?:\.[0-9]+)?)", window)
                if len(nums) >= 2:
                    return float(nums[0]), float(nums[1])
                return None
            except Exception:
                return None

        updated = 0
        for model_name in ["gpt-4o-mini", "gpt-4o"]:
            p = find_prices(model_name)
            if not p:
                continue
            self._rates.setdefault("openai", {})[model_name] = ModelRates(
                input_per_1m=p[0],
                output_per_1m=p[1],
                source="auto:web",
                fetched_at=now_ts(),
            )
            updated += 1

        if updated:
            logger.info("PRICING_REFRESH_OK updated=%s", updated)

    def get_rates(self, provider: str, model: str) -> ModelRates:
        provider = detect_provider(provider, model)
        model_n = normalize_model(model)
        self._refresh_if_needed()

        prov = self._rates.get(provider, {})
        if model_n in prov:
            return prov[model_n]

        # If unknown, fall back to the closest safe baseline (never USD=0)
        if provider == "openai":
            return prov.get("gpt-4o-mini") or ModelRates(0.15, 0.60, source="fallback:default")
        # For other providers, use a conservative placeholder but never 0
        any_rate = next(iter(prov.values()), None)
        return any_rate or ModelRates(1.0, 1.0, source="fallback:default")

    def compute_cost_usd(self, provider: str, model: str, prompt_tokens: int, completion_tokens: int) -> Tuple[float, Dict[str, str]]:
        r = self.get_rates(provider, model)
        in_rate = float(r.input_per_1m or 0.0) / 1_000_000.0
        out_rate = float(r.output_per_1m or 0.0) / 1_000_000.0
        cost = (int(prompt_tokens or 0) * in_rate) + (int(completion_tokens or 0) * out_rate)
        meta = {
            "pricing_source": r.source,
            "model_normalized": normalize_model(model),
            "provider": detect_provider(provider, model),
        }
        return float(cost), meta


_REGISTRY: Optional[PricingRegistry] = None


def get_pricing_registry() -> PricingRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = PricingRegistry()
    return _REGISTRY
