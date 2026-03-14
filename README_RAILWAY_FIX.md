# PATCH0201 — Railway Procfile fix

## What changed
Railway may execute Procfile commands without a bash-compatible shell, so `${PORT:-8000}` is not expanded and uvicorn crashes.
This patch updates `Procfile` to:

`web: uvicorn app.main:app --host 0.0.0.0 --port $PORT`

Railway injects `PORT` automatically.

## Deploy note
On Railway, HTTP services are typically shown as a `web` process type. This is expected for an API service.
You can rename the Railway *service* to `api` for clarity; the Procfile process type remains `web`.

## Post-deploy check
- `/health` should return `ok`
- `uvicorn running on 0.0.0.0:<PORT>` appears in logs
