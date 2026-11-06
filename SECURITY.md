# Security Policy and Threat Model

## Scope

Webway09 fetches untrusted URLs and archived content. The security boundary is
the Flask process and the network destinations it can reach. The tool is
designed for authorized content analysis, not for scanning arbitrary internet
hosts or for processing sensitive evidence without additional controls.

## Threats considered

### Server-Side Request Forgery (SSRF)

An attacker submits a URL that resolves to loopback, a private network, a
link-local metadata service, or a redirect to one of those destinations.

**Controls**

- Only `http` and `https` schemes.
- No embedded credentials in URLs.
- Port allowlist, defaulting to 80 and 443.
- Hostname blocklist plus `.local`, `.internal`, `.localhost`, and
  `.home.arpa` suffixes.
- DNS resolution followed by a public-address check on every resolved address.
- Manual redirect handling with re-validation of each hop, capped at three
  redirects.
- Cookies are dropped when a redirect changes the host.

**Residual risk**: DNS rebinding can change the resolution between the check
and the actual connection. Pinning the resolved IP through a custom transport
would be the next step; it is not implemented here.

### Credential leakage through URLs or logs

The original prototype accepted cookies in a query string and could expose them
to access logs, proxies, and browser history.

**Controls**

- Live-scan cookies are accepted only in the JSON POST body.
- Cookie input is length-capped, newline-rejected, and limited to 50 pairs.
- Cookies are sent only to the original target host.
- The application does not log request bodies or cookie values. Reverse-proxy
  and Gunicorn access logs may still include the request line (including a
  query string); configure those logs to redact or omit query strings.
- `Set-Cookie`, `Authorization`, and other sensitive response headers are
  filtered from results.
- Secret-like values are redacted by default.

### Open proxy / abuse

An unauthenticated public endpoint could be used to make the server fetch
third-party content.

**Controls**

- Remote access requires `WEBWAY_API_TOKEN`.
- Local-only mode is the default; a non-loopback bind without a token is
  refused at startup.
- An `X-Forwarded-For` header does not bypass the local-only rule.
- Per-process rate limiting.
- No CORS by default; explicit origin allowlist only.
- Request, response, URL, cookie, and match caps.

**Residual risk**: rate limiting is in memory and per worker. A public
multi-worker deployment should add a reverse-proxy or shared-store limiter and
network egress filtering.

### Denial of service

Large pages, huge snapshot lists, unbounded regexes, and many assets can consume
CPU, memory, or time.

**Controls**

- Byte caps on live pages, CDX responses, robots.txt, and assets.
- Snapshot, asset, keyword, match, and total-match caps.
- Regex pattern length cap and `regex` match timeout.
- Fixed thread-pool sizes and polite delays between archive fetches.

**Residual risk**: BeautifulSoup/lxml parsing and the browser UI can still be
expensive on adversarial input. The `regex` timeout is only available when the
`regex` package is installed (it is a pinned dependency).

### Secret exposure

The scanner intentionally looks for secret-like strings.

**Controls**

- Redacted previews by default.
- Full values only with `WEBWAY_REVEAL_SECRETS=1`.
- No secret values are written to logs.

**Residual risk**: the tool may still display sensitive context in snippets or
comments. Treat findings as sensitive and follow your organization's data
handling rules.

### Browser-side issues

**Controls**

- Same-origin CORS by default.
- CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
  `Permissions-Policy`, COOP/CORP.
- API responses are `Cache-Control: no-store`.
- SSE is consumed with `fetch()` rather than `EventSource`, so the token is not
  placed in a URL.
- User-controlled strings are escaped before insertion into the results DOM.

**Residual risk**: the UI uses inline styles, so CSP allows
`style-src 'unsafe-inline'`. Script execution is restricted to same-origin
files.

## Out of scope

- Malware execution or sandboxing.
- Forensic chain of custody, signed evidence, or court admissibility.
- Vulnerability scanning, exploitation, or proof of compromise.
- Authentication bypass testing.
- Distributed rate limiting or multi-tenant isolation.

## Reporting a vulnerability

Do not open a public issue containing exploit details, tokens, or personal data.
Contact the repository owner privately and include:

- affected version/commit,
- reproduction steps with synthetic data,
- impact assessment,
- suggested fix if available.

## Deployment checklist

- [ ] `WEBWAY_API_TOKEN` set to a high-entropy value.
- [ ] `FLASK_DEBUG=0`.
- [ ] `WEBWAY_REVEAL_SECRETS=0`.
- [ ] `WEBWAY_ALLOW_PRIVATE_HOSTS=0`.
- [ ] `WEBWAY_ALLOWED_ORIGINS` restricted if cross-origin use is required.
- [ ] Gunicorn or another production WSGI server used.
- [ ] TLS terminated by a trusted reverse proxy.
- [ ] Egress firewall blocks private/link-local ranges as defence in depth.
- [ ] Access logs are configured not to retain target credentials or query strings.
