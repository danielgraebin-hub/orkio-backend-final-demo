ORKIO API — SUMMIT SUPERADMIN FINAL

Base:
- orkio-api-PATCH_STAGE_FINAL_PALCO.zip

Applied changes:
1. Structural super-admin rule:
   - any email in ADMIN_EMAILS becomes admin automatically
   - if no admin exists yet in the tenant, the first registered user becomes admin
2. Admin bypass occurs before Summit access code validation
3. Summit seed codes use explicit source mapping:
   - SOUTHSUMMIT26 -> summit_user
   - EFATA777 -> investor
4. Startup bootstrap ensures:
   - core agents for DEFAULT_TENANT
   - admin sync for ADMIN_EMAILS when matching user already exists
5. Duplicate _ensure_thread_owner call removed if present

Required backend env:
- ADMIN_EMAILS=daniel@patroai.com
- DEFAULT_TENANT=patroai
- SUMMIT_MODE=true
- OPENAI_STT_LANGUAGE=en
