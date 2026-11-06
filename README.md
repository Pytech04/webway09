# Webway09

A Flask + Server-Sent Events tool for authorized analysis of archived and live
web content. It queries the Wayback CDX API and inspects visible text,
JavaScript, HTML comments, security headers, `robots.txt`, and same-origin
assets for keywords, endpoints, and secret-like indicators.

**This is an OSINT/content-analysis tool, not a vulnerability scanner, not a
malware detector, and not a forensic evidence system.** It does not grant
permission to test anything. Only scan systems you own or have written
authorization to test.

## What it does

- **Wayback mode**: fetches archived snapshots through the Wayback CDX API,
  extracts page text, JavaScript, and comments, and searches for user-supplied
  keywords or regular expressions.
- **Live mode**: fetches one authorized target, records a small allowlist of
  response headers, checks `OPTIONS`/`Allow`, reads `robots.txt`, collects
  comments and same-origin assets, and analyzes scripts/styles for flags,
  endpoints, and secret-like values.
- **Secret detection**: AWS keys, generic API-key assignments, bearer tokens,
  Google API keys, Firebase URLs, and Slack tokens. Values are redacted by
  default.
- **Streaming UI**: Wayback scans stream progress and matches over SSE; the
  browser uses `fetch()` streaming so the API token can be sent in a header.

## Security hardening

The original prototype trusted user URLs and exposed a public scan endpoint.
This version treats the target URL as untrusted:

- **SSRF defence**: only `http`/`https`; no embedded credentials; port
  allowlist (80/443 by default); block `localhost`, `.local`/`.internal`
  suffixes, metadata hosts, loopback, private, link-local, reserved,
  multicast, and unspecified addresses; resolve DNS and reject any non-public
  answer; validate every redirect hop.
- **Redirect and cookie safety**: redirects are followed manually (maximum 3),
  each hop is re-validated, and cookies are only sent to the original host.
- **No query-string credentials**: live-scan cookies are sent in a JSON POST
  body, not in the URL.
- **Authentication**: remote access requires `WEBWAY_API_TOKEN`; local
  loopback use is allowed without a token. `X-Forwarded-For` does not bypass
  the local-only rule. Public binding without a token is refused at startup.
- **Rate limiting**: per-process, in-memory limit (30 requests / 60 seconds by
  default) with `Retry-After`.
- **CORS**: disabled by default; only explicit `WEBWAY_ALLOWED_ORIGINS` are
  allowed. There is no wildcard.
- **Response limits**: request body, URL, cookie, robots, asset, CDX, and page
  response sizes are capped. Matches and asset counts are capped too.
- **Regex safety**: pattern length is capped and the `regex` engine is used
  with a match timeout. The code falls back to `re` only if `regex` is
  unavailable.
- **Output hygiene**: `Set-Cookie`, `Authorization`, and other sensitive
  headers are filtered out; secret-like values in findings are redacted unless
  `WEBWAY_REVEAL_SECRETS=1` is explicitly set.
- **Browser hardening**: CSP, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Permissions-Policy`, COOP/CORP, and HSTS on HTTPS.
- **Safe defaults**: debug is off, the dev server binds to `127.0.0.1`, and
  production uses Gunicorn instead of the Flask development server.

See [SECURITY.md](SECURITY.md) for the threat model and residual risks.

## Quick start

```bash
git clone https://github.com/Pytech04/webway09.git
cd webway09
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python server.py
```

Open `http://127.0.0.1:5000`.

The local dev server binds to loopback by default, so no API token is needed
for local use. For a shared or public deployment, set a token:

```bash
export WEBWAY_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export WEBWAY_HOST=0.0.0.0
python server.py
```

The application refuses to bind to a non-loopback address without a token
unless `WEBWAY_ALLOW_UNAUTHENTICATED=1` is explicitly set.

## Usage

1. Choose **Wayback Archive** to search historical snapshots.
2. Enter a domain such as `example.com`; optionally add keywords, a year, and a
   snapshot limit (maximum 200).
3. Choose **Live Site** only for a target you are authorized to test. Confirm
   the authorization checkbox. Cookies are optional and are sent in the POST
   body to the original host only.
4. If the server requires an API token, paste it into the API token field; it is
   sent as `Authorization: Bearer <token>`.

## Configuration

Copy `.env.example` and set values in your process environment. The important
ones:

| Variable | Default | Purpose |
| --- | --- | --- |
| `WEBWAY_API_TOKEN` | empty | Bearer token required for remote API access. |
| `WEBWAY_ALLOW_UNAUTHENTICATED` | `0` | Explicitly allow unauthenticated remote use. Unsafe. |
| `WEBWAY_ALLOWED_ORIGINS` | empty | Comma-separated CORS allowlist. Empty = same-origin only. |
| `WEBWAY_ALLOWED_PORTS` | `80,443` | Outbound destination ports. |
| `WEBWAY_ALLOW_PRIVATE_HOSTS` | `0` | Allow private/loopback destinations. Test only. |
| `WEBWAY_MAX_SNAPSHOTS` | `200` | Maximum Wayback snapshots per scan. |
| `WEBWAY_MAX_RESPONSE_BYTES` | `2097152` | Maximum live/archived page body. |
| `WEBWAY_RATE_LIMIT_MAX` | `30` | Requests per IP per window. |
| `WEBWAY_RATE_LIMIT_WINDOW` | `60` | Rate-limit window in seconds. |
| `WEBWAY_REGEX_TIMEOUT` | `2.0` | Per-match regex time budget (with `regex`). |
| `WEBWAY_REVEAL_SECRETS` | `0` | Return full secret values. Keep off. |
| `FLASK_DEBUG` | `0` | Flask debug mode. Keep off. |

## API

### `POST /api/live-scan`

Headers: `Content-Type: application/json`, and
`Authorization: Bearer <WEBWAY_API_TOKEN>` when a token is configured.

```json
{
  "url": "https://example.com",
  "flag_pattern": "ctf{",
  "cookies": "session=value",
  "use_regex": false,
  "authorized": true
}
```

The `authorized` field is a confirmation gate, not proof of permission.

### `GET /api/scan?domain=example.com&keyword=password&limit=25`

Returns an SSE stream. The browser client uses `fetch()` streaming so the
token can be sent in an `Authorization` header instead of a URL.

### `GET /api/health`

Returns the app name and version. It does not expose configuration or secrets.

## Verification

```bash
pip install -r requirements-dev.txt
pytest -q
```

Current suite: **27 tests pass**. The tests are offline and cover URL
validation, redirect blocking, response-size caps, auth, rate limiting, header
filtering, cookie parsing, CORS/security headers, secret redaction, and the
live-scan response path with a mocked transport. They do not make live network
requests and do not prove the scanner is correct against every target.

Additional static checks used during hardening:

```bash
python -m py_compile server.py
ruff check server.py tests
node --check static/script.js
```

## Deployment

Use Gunicorn, not `flask run` or the Flask development server:

```bash
gunicorn server:app \
  --bind 0.0.0.0:$PORT \
  --worker-class gthread \
  --threads 4 \
  --timeout 120
```

Set `WEBWAY_API_TOKEN` before exposing the service. See
[DEPLOYMENT.md](DEPLOYMENT.md) for Render, Docker, and reverse-proxy notes.
Serverless platforms that impose short request limits are a poor fit for SSE
scans.

## Limitations and residual risks

- **DNS rebinding**: the hostname is resolved and checked before each request,
  but a determined attacker could change DNS between validation and connection.
  This is a documented TOCTOU residual risk, not a complete fix.
- **Rate limiting is per process**: multiple Gunicorn workers do not share the
  in-memory counter. Use a reverse-proxy or Redis-backed limiter for a
  multi-worker public deployment.
- **Regex safety depends on `regex`**: if the optional `regex` package is
  missing, the fallback uses `re`, which has no match timeout. Keep the
  dependency installed.
- **Secret detection is heuristic**: it finds patterns, not proof of valid
  credentials, and can miss custom formats.
- **Wayback content is untrusted**: archived pages are parsed with
  BeautifulSoup/lxml; malformed or hostile markup can still be expensive.
- **No malware detection**: "suspicious patterns" are leads, not verdicts.
- **Not forensic-grade**: no chain of custody, signed evidence, or court-ready
  integrity guarantees.

## Responsible use

- Do not scan third-party systems without written authorization.
- Do not use the tool to exfiltrate credentials or personal data.
- Keep `WEBWAY_REVEAL_SECRETS=0` unless you have a lawful, scoped reason.
- Report vulnerabilities in this project privately rather than opening a public
  issue with exploit details.

## License

MIT. See [LICENSE](LICENSE).
