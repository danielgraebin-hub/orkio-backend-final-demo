# Orkio API — Deploy Railway (PATCH0110_API)

## Start command
Railway reads `Procfile` automatically:

```bash
web: uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
```

## Required environment variables

### Core
- `JWT_SECRET`
- `ADMIN_API_KEY`
- `DATABASE_URL` (or `DATABASE_PUBLIC_URL` / `DATABASE_URL_PUBLIC`)

### CORS (choose one strategy)

1. Explicit regex (recommended for custom domain):

```env
CORS_ORIGIN_REGEX=https://SEU_DOMINIO
```

2. Railway dynamic subdomains:

```env
ALLOW_RAILWAY_ORIGIN_REGEX=true
```

Regex used by backend when enabled:

```text
https://[a-z0-9-]+\.up\.railway\.app
```

If `CORS_ORIGIN_REGEX` is set, it has priority.

## Optional runtime tuning
- `OPENAI_TIMEOUT`
- `LLM_TIMEOUT`
- `SSE_KEEPALIVE_SECONDS`

Timeout fallback for OpenAI calls is `45s`.

## SSE contract
Endpoint: `POST /api/chat/stream`

Headers:
- `Content-Type: text/event-stream`
- `Cache-Control: no-cache`
- `Connection: keep-alive`
- `X-Accel-Buffering: no`

Events emitted:
- `status`
- `chunk`
- `error`
- `done`

Rules:
- `done` global encerra stream.
- `agent_done` não encerra stream.

## Quick checks
```bash
python -m py_compile app/main.py
curl -N https://API_DOMAIN/api/chat/stream
```


### Nota importante (P0 CORS)
- Se `CORS_ORIGINS` estiver vazio, o backend **não** permitirá origins por lista (sem `*`).
- Use `CORS_ORIGIN_REGEX` ou `ALLOW_RAILWAY_ORIGIN_REGEX=true` para permitir origens dinâmicas.
- Opcionalmente defina `CORS_ORIGINS` com uma lista explícita de origins (separadas por vírgula) para permitir apenas domínios fixos.


## PATCH0111 tuning knobs
- `MAX_STREAM_SECONDS` (teto total do stream; 0 desativa)
- `MAX_CTX_CHARS` (teto de caracteres do contexto RAG)
- `MAX_HISTORY_CHARS` (teto de caracteres do histórico)


## PATCH0112 note
- `MAX_STREAM_SECONDS`: quando estoura, o stream emite `error(TIMEOUT)` + `done` e encerra o generator sem aguardar o LLM.

## Summit capacity (admission control)

- Limits are **per replica/instance** (in-memory counters). For predictable behavior during events, use **WEB_CONCURRENCY=1** and scale by replicas.
- Configure either:
  - `MAX_STREAMS_PER_REPLICA` (recommended name), or
  - `MAX_STREAMS_GLOBAL` (legacy alias)

Other knobs:
- `MAX_STREAMS_PER_IP`

