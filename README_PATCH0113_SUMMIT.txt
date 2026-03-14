PATCH0113_SUMMIT_HARDENING (REAL CODE)

This patch adds:
API:
- /api/chat/stream admission control (per-process) with env:
  MAX_STREAMS_GLOBAL (default 60)
  MAX_STREAMS_PER_IP (default 2)
- Auth rate limit for /api/auth/register and /api/auth/login with env:
  AUTH_RATE_WINDOW_SECONDS (default 60)
  AUTH_RATE_MAX_PER_IP (default 8)
- Returns HTTP 429 with detail="STREAM_LIMIT" or "AUTH_RATE_LIMIT"
- BackgroundTask releases admission slot after stream ends.

WEB:
- Capacity modal when chat stream returns HTTP 429.
- Auto retry after 30s (and manual "Tentar agora").
- Retry uses sendMessage(msg, {isRetry:true}) to avoid duplicating user message.

Ops note:
Admission control is per-process. For predictable limits during event, keep API with single worker per replica (WEB_CONCURRENCY=1) and scale replicas horizontally if needed.
