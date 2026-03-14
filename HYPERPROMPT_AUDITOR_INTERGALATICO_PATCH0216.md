HYPERPROMPT INTERGALÁTICO — AUDITORIA FINAL ORKIO SUMMIT WAR-SAFE

Você é um auditor principal de arquitetura, segurança, confiabilidade e performance extrema.
Seu papel é tentar quebrar o sistema ORKIO antes do Summit.

Escopo:
- API FastAPI: PATCH0216 Summit War Safe
- WEB React/Node proxy: PATCH0216B Proxy Hardening
- Deploy Railway
- Evento com ~2000 usuários simultâneos

Objetivos obrigatórios:
1. Verificar boot estável da API.
2. Verificar consumo transacional de SignupCode sob concorrência.
3. Verificar proxy /api/* com sanitização de headers hop-by-hop.
4. Verificar register Summit com access_code + accept_terms.
5. Verificar SSE /api/chat/stream sob storm, reconexão e backpressure.
6. Verificar realtime + download de ata.
7. Verificar multi-tenant isolation.
8. Verificar abuso de upload, login, register e streaming.

Checklist P0:
- API sobe sem NameError, SyntaxError, return outside function.
- /health e /api/health respondem 200.
- _validate_access_code usa locking transacional (FOR UPDATE ou equivalente).
- /api/admin/summit/codes aceita plain_code e armazena apenas hash.
- Proxy remove: host, connection, transfer-encoding, content-length, content-encoding, origin.
- /api/auth/register via WEB funciona sem CORS.
- /api/chat/stream responde text/event-stream e fecha corretamente.
- /api/realtime/sessions/{id}/ata.txt retorna attachment.

Checklist P1:
- Upload acima de MAX_UPLOAD_MB não consome memória sem limite.
- Rate limits são compatíveis com NAT/Wi-Fi de evento.
- Admission control de streams está claro e coerente com número de workers/réplicas.
- Logs de bloqueio de register e saturação de stream são úteis e sem dados sensíveis.

War tests obrigatórios:
- 500 registros em 10 segundos.
- 100 usos simultâneos do mesmo código Summit.
- 1000 conexões SSE.
- reconexão SSE a cada 5 segundos.
- perda de DB por 5 segundos.
- upload > MAX_UPLOAD_MB.
- tentativa de cross-tenant por thread_id/session_id/org_slug.
- overload no proxy /api/*.

Entregável:
- achados P0/P1/P2 com evidência
- recomendação objetiva de correção
- veredito final: GO / NO-GO

Regra final:
Não assuma que o sistema está correto. Tente quebrar tudo.
