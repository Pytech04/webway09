# Deployment

## Local development

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements-dev.txt
python server.py
```

The development server binds to `127.0.0.1:5000` by default. No API token is
needed for loopback use.

## Production with Gunicorn

```bash
pip install -r requirements.txt
export WEBWAY_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
gunicorn server:app \
  --bind 0.0.0.0:${PORT:-5000} \
  --worker-class gthread \
  --threads 4 \
  --timeout 120 \
  --access-logfile - \
  --error-logfile -
```

Use a TLS-terminating reverse proxy (Caddy, nginx, or a platform load balancer)
in front of Gunicorn. Keep `WEBWAY_REVEAL_SECRETS=0` and
`WEBWAY_ALLOW_PRIVATE_HOSTS=0` unless you have a specific test requirement.

## Render

`render.yaml` and `Procfile` are included. Set `WEBWAY_API_TOKEN` in the Render
dashboard as a secret. The start command is:

```bash
gunicorn server:app --bind 0.0.0.0:$PORT --worker-class gthread --threads 4 --timeout 120
```

Render's request timeout and instance memory limits still apply. Long Wayback
scans can take time because each snapshot is fetched politely.

## Docker

```bash
docker build -t webway09 .
docker run --rm -p 5000:5000 \
  -e WEBWAY_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')" \
  webway09
```

The container runs Gunicorn and listens on `0.0.0.0:5000`.

## Vercel and serverless platforms

The Flask `app` object is WSGI-compatible, but SSE scans and long archive jobs
can exceed serverless request limits. Prefer a long-running container or VM.
If you deploy to Vercel, set `WEBWAY_API_TOKEN`; the app rejects unauthenticated
remote API access.

## Reverse-proxy notes

- Do not add wildcard CORS at the proxy. Use `WEBWAY_ALLOWED_ORIGINS` if needed.
- Configure the proxy/Gunicorn access log to omit or redact query strings for
  `/api/scan`; they can contain search keywords.
- Forward `X-Forwarded-For` only from a trusted proxy. The app treats the
  presence of `X-Forwarded-For` as remote access and will require a token.
- Add an egress firewall that blocks RFC 1918, loopback, link-local, and
  metadata ranges as defence in depth against SSRF and DNS rebinding.
