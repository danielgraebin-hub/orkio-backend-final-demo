PATCH0216 — Summit War Safe

Inclui:
- consumo de SignupCode com row lock (SELECT ... FOR UPDATE)
- endpoint /api/admin/summit/codes com plain_code opcional
- bloqueio de duplicatas por hash
- Turnstile só quando TURNSTILE_SECRET estiver configurado
- logs explícitos de bloqueio no register
- limites padrão ajustados para Summit
- upload com leitura em chunks e limite MAX_UPLOAD_MB

Recomendação Railway:
APP_ENV=production
SUMMIT_MODE=true
REGISTER_MAX_PER_MINUTE=300
AUTH_RATE_MAX_PER_IP=600
REALTIME_MAX_PER_MINUTE=30
MAX_STREAMS_PER_IP=20
MAX_STREAMS_GLOBAL=200
MAX_UPLOAD_MB=20
