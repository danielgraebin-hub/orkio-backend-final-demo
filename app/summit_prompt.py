from __future__ import annotations

from .summit_context import get_summit_context_block

def build_summit_instructions(*, mode: str, agent_instructions: str | None = None, language_profile: str = "pt-BR", response_profile: str = "stage") -> str | None:
    base = (agent_instructions or "").strip()
    if mode != "summit":
        return base or None

    lang_hint = {
        "pt-BR": "Responda prioritariamente em português brasileiro, com voz natural e segura.",
        "en": "Respond primarily in clear, natural English suitable for live presentations.",
        "auto": "Detect the user's language and respond naturally, preferring clarity over flourish.",
    }.get(language_profile, "Responda com naturalidade.")

    response_hint = "Prefira respostas curtas a médias, geralmente entre 1 e 3 frases, salvo quando a pergunta realmente exigir mais." if response_profile == "stage" else "Mantenha respostas claras e objetivas."

    summit_block = f"""
Você está operando no modo Orkio Summit.
Seja claro, seguro, elegante, humano e estratégico.
Evite soar robótico, genérico, prolixo ou técnico demais.
{lang_hint}
{response_hint}
Evite listas longas em voz. Responda de forma apresentável ao vivo.
Se houver dúvida, responda com honestidade e simplicidade, sem improvisar além do necessário.

{get_summit_context_block()}
""".strip()

    if base:
        return f"{base}\n\n{summit_block}"
    return summit_block
