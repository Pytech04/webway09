"""Webway09 - authorized archived/live web content scanner.

This module is intentionally conservative: it treats every user-supplied URL as
untrusted, validates outbound destinations before connecting, limits response
sizes, redacts secret-like values by default, and requires an explicit
authorization confirmation for live scans.

It is an OSINT/content-analysis tool, not a vulnerability scanner and not a
forensic evidence system.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import os
import random
import re
import socket
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup, Comment
from flask import Flask, Response, jsonify, render_template, request, stream_with_context
from flask_cors import CORS

try:  # Prefer the regex engine because it supports match timeouts.
    import regex as regex_engine
except ImportError:  # pragma: no cover - exercised only when regex is absent
    regex_engine = re


APP_NAME = "Webway09"
VERSION = "1.1.0"
USER_AGENT = os.getenv(
    "WEBWAY_USER_AGENT",
    f"{APP_NAME}/{VERSION} (authorized security testing; contact repo owner)",
)
CDX_API = "https://web.archive.org/cdx/search/cdx"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        return default


MAX_RESPONSE_BYTES = env_int("WEBWAY_MAX_RESPONSE_BYTES", 2 * 1024 * 1024)
MAX_CDX_BYTES = env_int("WEBWAY_MAX_CDX_BYTES", 5 * 1024 * 1024)
MAX_ROBOTS_BYTES = env_int("WEBWAY_MAX_ROBOTS_BYTES", 128 * 1024)
MAX_ASSET_BYTES = env_int("WEBWAY_MAX_ASSET_BYTES", 1024 * 1024)
MAX_REQUEST_BYTES = env_int("WEBWAY_MAX_REQUEST_BYTES", 64 * 1024)
MAX_URL_LENGTH = env_int("WEBWAY_MAX_URL_LENGTH", 2048)
MAX_COOKIE_LENGTH = env_int("WEBWAY_MAX_COOKIE_LENGTH", 4096)
MAX_DOMAIN_LENGTH = env_int("WEBWAY_MAX_DOMAIN_LENGTH", 253)
MAX_KEYWORDS = env_int("WEBWAY_MAX_KEYWORDS", 20)
MAX_REGEX_LENGTH = env_int("WEBWAY_MAX_REGEX_LENGTH", 200)
MAX_MATCHES = env_int("WEBWAY_MAX_MATCHES", 200)
MAX_TOTAL_MATCHES = env_int("WEBWAY_MAX_TOTAL_MATCHES", 1000)
MAX_SNAPSHOTS = env_int("WEBWAY_MAX_SNAPSHOTS", 200)
MAX_ASSETS = env_int("WEBWAY_MAX_ASSETS", 20)
MAX_SNAPSHOT_WORKERS = env_int("WEBWAY_MAX_SNAPSHOT_WORKERS", 3)
MAX_ASSET_WORKERS = env_int("WEBWAY_MAX_ASSET_WORKERS", 5)
REGEX_TIMEOUT = float(os.getenv("WEBWAY_REGEX_TIMEOUT", "2.0"))
TIMEOUT = (5, 15)

ALLOWED_PORTS = {
    int(port)
    for port in os.getenv("WEBWAY_ALLOWED_PORTS", "80,443").split(",")
    if port.strip().isdigit()
}
if not ALLOWED_PORTS:
    ALLOWED_PORTS = {80, 443}

ALLOW_PRIVATE_HOSTS = env_bool("WEBWAY_ALLOW_PRIVATE_HOSTS", False)
ALLOW_UNAUTHENTICATED = env_bool("WEBWAY_ALLOW_UNAUTHENTICATED", False)
REVEAL_SECRETS = env_bool("WEBWAY_REVEAL_SECRETS", False)
API_TOKEN = os.getenv("WEBWAY_API_TOKEN", "").strip()
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("WEBWAY_ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
]
RATE_LIMIT_MAX = env_int("WEBWAY_RATE_LIMIT_MAX", 30, minimum=1)
RATE_LIMIT_WINDOW = env_int("WEBWAY_RATE_LIMIT_WINDOW", 60, minimum=1)

BLOCKED_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "metadata",
    "metadata.google.internal",
    "instance-data",
    "169.254.169.254",
    "fd00:ec2::254",
    "100.100.100.200",
}
BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")

SAFE_HEADERS = {
    "allow",
    "content-security-policy",
    "content-type",
    "content-length",
    "permissions-policy",
    "referrer-policy",
    "server",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "x-powered-by",
    "access-control-allow-origin",
}

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Generic API Key": r"(?i)(api_key|apikey|secret|token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]",
    "Bearer Token": r"Bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*",
    "Google API Key": r"AIza[0-9A-Za-z_\-]{35}",
    "Firebase URL": r"https://[a-z0-9-]+\.firebaseio\.com",
    "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
}

# ---------------------------------------------------------------------------
# Logging and app setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=os.getenv("WEBWAY_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(APP_NAME)

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static"),
    static_url_path="/static",
)
app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES

# CORS is disabled by default. When enabled, only explicit origins are allowed.
if ALLOWED_ORIGINS:
    CORS(
        app,
        origins=ALLOWED_ORIGINS,
        methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
        max_age=600,
    )

# ---------------------------------------------------------------------------
# Errors and small helpers
# ---------------------------------------------------------------------------


class OutboundRequestError(ValueError):
    """Raised when an outbound URL is unsafe or cannot be fetched safely."""


class ResponseTooLarge(OutboundRequestError):
    """Raised when a remote response exceeds the configured byte cap."""


class RegexTimeout(ValueError):
    """Raised when a user-supplied regular expression exceeds its time budget."""


@dataclass
class SafeResponse:
    status_code: int
    headers: Dict[str, str]
    content: bytes
    url: str

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")


def parse_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def clamp_int(value: object, minimum: int, maximum: int, default: int = 100) -> int:
    try:
        number = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        number = default
    return max(minimum, min(maximum, number))


def validate_regex_pattern(pattern: str) -> str:
    if not isinstance(pattern, str):
        raise ValueError("pattern must be a string")
    pattern = pattern.strip()
    if not pattern:
        raise ValueError("pattern cannot be empty")
    if len(pattern) > MAX_REGEX_LENGTH:
        raise ValueError(f"pattern exceeds {MAX_REGEX_LENGTH} characters")
    try:
        (regex_engine if regex_engine is not re else re).compile(pattern)
    except Exception as exc:
        raise ValueError("invalid regular expression") from exc
    return pattern


def _finditer(pattern: str, text: str, flags: int = 0) -> List[object]:
    if len(pattern) > MAX_REGEX_LENGTH:
        raise ValueError(f"pattern exceeds {MAX_REGEX_LENGTH} characters")
    if regex_engine is re:
        try:
            return list(re.finditer(pattern, text, flags))
        except re.error as exc:
            raise ValueError("invalid regular expression") from exc
    try:
        return list(regex_engine.finditer(pattern, text, flags=flags, timeout=REGEX_TIMEOUT))
    except TypeError:  # older regex builds do not accept timeout
        return list(regex_engine.finditer(pattern, text, flags))
    except TimeoutError as exc:
        raise RegexTimeout("regular expression timed out") from exc


def _sub(pattern: str, replacement: str, text: str, flags: int = 0) -> str:
    if len(pattern) > MAX_REGEX_LENGTH:
        raise ValueError("pattern too long")
    if regex_engine is re:
        return re.sub(pattern, replacement, text, flags=flags)
    try:
        return regex_engine.sub(pattern, replacement, text, flags=flags, timeout=REGEX_TIMEOUT)
    except TypeError:
        return regex_engine.sub(pattern, replacement, text, flags=flags)
    except TimeoutError as exc:
        raise RegexTimeout("regular expression timed out") from exc


def redact_secret(value: str) -> str:
    if REVEAL_SECRETS:
        return value
    if len(value) <= 8:
        return "[REDACTED]"
    return f"{value[:4]}…{value[-2:]}"


def redact_text(text: str) -> str:
    """Redact known secret patterns from free-form snippets/comments."""
    if REVEAL_SECRETS or not text:
        return text
    for pattern in SECRET_PATTERNS.values():
        try:
            text = _sub(pattern, "[REDACTED]", text)
        except (ValueError, RegexTimeout):
            continue
    return text


def _snippet(text: str, start: int, end: int, context: int = 30) -> str:
    start = max(0, start - context)
    end = min(len(text), end + context)
    return "..." + redact_text(text[start:end].replace("\n", " ").strip()) + "..."


def filter_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Return only non-sensitive response headers."""
    filtered: Dict[str, str] = {}
    for key, value in headers.items():
        lower = key.lower()
        if lower in SAFE_HEADERS:
            filtered[lower] = str(value)[:1000]
    return filtered


# ---------------------------------------------------------------------------
# SSRF protection
# ---------------------------------------------------------------------------


def _normalize_hostname(hostname: str) -> str:
    hostname = hostname.strip().rstrip(".").lower()
    if ":" in hostname:  # IPv6 literal; do not run it through IDNA.
        return hostname
    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise OutboundRequestError("invalid hostname") from exc


def _is_public_ip(ip: ipaddress._BaseAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return bool(
        ip.is_global
        and not ip.is_private
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_multicast
        and not ip.is_reserved
        and not ip.is_unspecified
        and not getattr(ip, "is_site_local", False)
    )


def _resolve_host(hostname: str, port: int) -> List[ipaddress._BaseAddress]:
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise OutboundRequestError("hostname did not resolve") from exc
    addresses: List[ipaddress._BaseAddress] = []
    for info in infos:
        raw = info[4][0].split("%", 1)[0]
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise OutboundRequestError("hostname did not resolve to an IP address")
    return addresses


def validate_outbound_url(url: str) -> Tuple[str, int]:
    """Validate scheme, credentials, hostname, port, and resolved IPs."""
    if not isinstance(url, str) or not url.strip():
        raise OutboundRequestError("URL is required")
    if len(url) > MAX_URL_LENGTH:
        raise OutboundRequestError("URL is too long")

    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise OutboundRequestError("only http and https URLs are allowed")
    if parsed.username or parsed.password:
        raise OutboundRequestError("URLs with embedded credentials are not allowed")
    if not parsed.hostname:
        raise OutboundRequestError("URL must include a hostname")

    hostname = _normalize_hostname(parsed.hostname)
    if hostname in BLOCKED_HOSTS or any(hostname.endswith(suffix) for suffix in BLOCKED_SUFFIXES):
        raise OutboundRequestError("host is blocked")

    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise OutboundRequestError("invalid port") from exc
    if port not in ALLOWED_PORTS:
        raise OutboundRequestError("port is not allowed")

    if not ALLOW_PRIVATE_HOSTS:
        try:
            addresses = [ipaddress.ip_address(hostname)]
        except ValueError:
            addresses = _resolve_host(hostname, port)
        if any(not _is_public_ip(address) for address in addresses):
            raise OutboundRequestError("private, loopback, link-local, or reserved address blocked")
    return hostname, port


def _read_limited(response: requests.Response, max_bytes: int) -> bytes:
    chunks: List[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=8192):
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            raise ResponseTooLarge(f"response exceeds {max_bytes} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def safe_request(
    method: str,
    url: str,
    *,
    params: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    max_bytes: int = MAX_RESPONSE_BYTES,
    timeout: Tuple[int, int] = TIMEOUT,
    max_redirects: int = 3,
    include_body: bool = True,
) -> SafeResponse:
    """Fetch a URL with SSRF validation on every redirect hop."""
    original_host = validate_outbound_url(url)[0]
    current = url
    current_params = params

    for _ in range(max_redirects + 1):
        hostname, _ = validate_outbound_url(current)
        # Cookies are only sent to the original host, never to a redirect target.
        send_cookies = cookies if hostname == original_host else None
        try:
            response = requests.request(
                method,
                current,
                params=current_params,
                headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
                cookies=send_cookies,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
                verify=True,
            )
        except requests.RequestException as exc:
            raise OutboundRequestError("outbound request failed") from exc

        try:
            if response.is_redirect:
                location = response.headers.get("Location")
                if not location:
                    raise OutboundRequestError("redirect response had no Location header")
                current = urljoin(current, location)
                current_params = None
                continue

            body = _read_limited(response, max_bytes) if include_body else b""
            return SafeResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                content=body,
                url=current,
            )
        finally:
            response.close()

    raise OutboundRequestError("too many redirects")


# ---------------------------------------------------------------------------
# Content extraction
# ---------------------------------------------------------------------------


def extract_data(
    html: str,
    keywords: Sequence[str],
    timestamp: str,
    archive_url: str,
    use_regex: bool = False,
) -> List[Dict[str, object]]:
    """Extract keyword/secret matches from archived HTML."""
    if not isinstance(html, str):
        return []
    if len(html) > MAX_RESPONSE_BYTES:
        html = html[:MAX_RESPONSE_BYTES]

    soup = BeautifulSoup(html, "lxml")
    for element in soup.select("#wm-ipp-base, #wm-ipp, #donato"):
        element.decompose()
    for script in soup.find_all("script"):
        src = script.get("src")
        if src and "archive.org" in src:
            script.decompose()

    patterns: List[str] = []
    for keyword in keywords[:MAX_KEYWORDS]:
        keyword = str(keyword).strip()
        if not keyword or len(keyword) > MAX_REGEX_LENGTH:
            continue
        try:
            patterns.append(keyword if use_regex else re.escape(keyword))
        except re.error:
            continue

    matches: List[Dict[str, object]] = []

    def add_match(match_type: str, content: str, start: int, end: int) -> None:
        if len(matches) >= MAX_MATCHES:
            return
        matches.append(
            {
                "timestamp": timestamp,
                "archiveUrl": archive_url,
                "matchType": match_type,
                "snippet": _snippet(content, start, end),
            }
        )

    def search_text(content: str, match_type: str) -> None:
        if not content or len(matches) >= MAX_MATCHES:
            return
        for pattern in patterns:
            try:
                for match in _finditer(pattern, content, flags=re.IGNORECASE):
                    add_match(match_type, content, match.start(), match.end())
                    if len(matches) >= MAX_MATCHES:
                        return
            except (ValueError, RegexTimeout):
                continue

    body = soup.find("body")
    if body:
        text_content = re.sub(r"\s+", " ", body.get_text(separator=" ", strip=True))
        search_text(text_content, "TEXT")

    for script in soup.find_all("script"):
        script_content = script.string
        if script_content:
            search_text(script_content, "JS")

    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment_text = str(comment)
        if "FILE ARCHIVED ON" in comment_text:
            continue
        search_text(comment_text, "COMMENT")

    for name, pattern in SECRET_PATTERNS.items():
        if len(matches) >= MAX_MATCHES:
            break
        try:
            for match in _finditer(pattern, html):
                secret_value = match.group(match.lastindex) if match.lastindex else match.group(0)
                if not secret_value or len(secret_value) < 8:
                    continue
                index = html.find(secret_value)
                if index < 0:
                    continue
                start = max(0, index - 20)
                end = min(len(html), index + len(secret_value) + 20)
                snippet = (
                    html[start:index]
                    + "[REDACTED]"
                    + html[index + len(secret_value) : end]
                )
                matches.append(
                    {
                        "timestamp": timestamp,
                        "archiveUrl": archive_url,
                        "matchType": "SECRET",
                        "snippet": f"[{name}] ..."
                        + redact_text(snippet.replace("\n", " ").strip())
                        + "...",
                    }
                )
                if len(matches) >= MAX_MATCHES:
                    break
        except (ValueError, RegexTimeout):
            continue

    return matches


def analyze_asset(url: str, flag_pattern: str, use_regex: bool = False) -> Optional[Dict[str, object]]:
    """Fetch and inspect a same-origin script/styles asset."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    ignored_domains = (
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "google-analytics.com",
        "googletagmanager.com",
        "doubleclick.net",
    )
    if any(domain in hostname for domain in ignored_domains):
        return None

    try:
        response = safe_request("GET", url, max_bytes=MAX_ASSET_BYTES)
    except OutboundRequestError:
        return None
    if response.status_code != 200:
        return None

    content = response.text
    if not content:
        return None

    findings: Dict[str, object] = {"url": url, "flags": [], "comments": []}

    if flag_pattern and flag_pattern.strip():
        try:
            pattern = flag_pattern if use_regex else re.escape(flag_pattern)
            values = []
            for match in _finditer(pattern, content, flags=re.IGNORECASE):
                values.append(redact_text(match.group(0)))
                if len(values) >= 50:
                    break
            if values:
                findings["flags"] = sorted(set(values))
        except (ValueError, RegexTimeout):
            pass

    found_secrets = []
    for name, pattern in SECRET_PATTERNS.items():
        try:
            for match in _finditer(pattern, content):
                secret_value = match.group(match.lastindex) if match.lastindex else match.group(0)
                if secret_value and len(secret_value) >= 8:
                    found_secrets.append(f"{name}: {redact_secret(secret_value)}")
                if len(found_secrets) >= 50:
                    break
        except (ValueError, RegexTimeout):
            continue
    if found_secrets:
        findings["secrets"] = sorted(set(found_secrets))

    endpoints: List[str] = []
    full_urls: List[str] = []
    try:
        for match in _finditer(r"['\"](\/[a-zA-Z0-9_?&=\/\-\.]+)['\"]", content):
            endpoints.append(match.group(1))
        for match in _finditer(r"https?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}[a-zA-Z0-9_?&=\/\-\.]*", content):
            full_urls.append(match.group(0))
    except (ValueError, RegexTimeout):
        pass

    ignored_endpoint_domains = (
        "w3.org",
        "github.com",
        "twitter.com",
        "facebook.com",
        "google.com",
        "adobe.ly",
        "bit.ly",
        "vuejs.org",
        "momentjs.com",
        "jquery.com",
        "cloudflare.com",
        "googleapis.com",
        "gstatic.com",
        "vimeo.com",
        "youtube.com",
    )
    ignored_extensions = (
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".css",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".ico",
        ".mp4",
        ".webm",
        ".mp3",
        ".wav",
        ".swf",
    )
    cleaned_endpoints: List[str] = []
    for endpoint in endpoints + full_urls:
        endpoint = endpoint.strip()
        if endpoint.startswith("//"):
            continue
        if any(ext in endpoint.lower() for ext in ignored_extensions):
            continue
        if any(domain in endpoint.lower() for domain in ignored_endpoint_domains):
            continue
        if len(endpoint) < 3 or len(endpoint) > 120:
            continue
        cleaned_endpoints.append(endpoint)
    if cleaned_endpoints:
        findings["endpoints"] = sorted(set(cleaned_endpoints))[:100]

    comments: List[str] = []
    try:
        for match in _finditer(r"//.*$", content, flags=re.MULTILINE):
            comments.append(match.group(0))
        for match in _finditer(r"/\*[\s\S]*?\*/", content):
            comments.append(match.group(0))
    except (ValueError, RegexTimeout):
        pass

    ignored_comments = (
        "/* latin */",
        "/* latin-ext */",
        "/* cyrillic */",
        "/* cyrillic-ext */",
        "/* greek */",
        "/* greek-ext */",
        "/* vietnamese */",
        "/* hebrew */",
        "/* math */",
        "/* symbols */",
        "sourceMappingURL=",
        "Super Modern Browsers",
        "generated by",
        "license",
        "copyright",
    )
    clean_comments: List[str] = []
    for comment in comments:
        comment = comment.strip()
        if len(comment) > 300:
            comment = comment[:300] + "..."
        if len(comment) < 5:
            continue
        lower = comment.lower()
        if comment.startswith("/**") or "* @" in comment:
            continue
        if "function(" in comment or "var " in comment or "return " in comment or "window." in comment:
            continue
        if "{" in comment and "}" in comment:
            continue
        if "copyright" in lower or "license" in lower:
            continue
        if any(ignored.lower() in lower for ignored in ignored_comments):
            continue
        if "fonts.gstatic.com" in comment:
            continue
        clean_comments.append(redact_text(comment))
    if clean_comments:
        findings["comments"] = sorted(set(clean_comments))[:50]

    if any(findings.get(key) for key in ("flags", "comments", "secrets", "endpoints")):
        return findings
    return None


# ---------------------------------------------------------------------------
# Live scanning
# ---------------------------------------------------------------------------


def normalize_target_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise OutboundRequestError("URL is required")
    if len(value) > MAX_URL_LENGTH:
        raise OutboundRequestError("URL is too long")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise OutboundRequestError("only http and https URLs are allowed")
    return value


def _parse_cookies(cookies_str: Optional[str]) -> Dict[str, str]:
    if not cookies_str:
        return {}
    if len(cookies_str) > MAX_COOKIE_LENGTH:
        raise OutboundRequestError(f"cookie header exceeds {MAX_COOKIE_LENGTH} characters")
    if "\n" in cookies_str or "\r" in cookies_str:
        raise OutboundRequestError("cookie header contains invalid characters")
    cookies: Dict[str, str] = {}
    for pair in cookies_str.split(";"):
        if "=" not in pair:
            continue
        key, value = pair.strip().split("=", 1)
        if key:
            cookies[key] = value
        if len(cookies) >= 50:
            break
    return cookies


def scan_live_site(
    url: str,
    cookies_str: Optional[str] = None,
    flag_pattern: str = "ctf{",
    use_regex: bool = False,
) -> Dict[str, object]:
    """Scan a live site for headers, comments, assets, flags, and secret indicators."""
    url = normalize_target_url(url)
    cookies = _parse_cookies(cookies_str)

    results: Dict[str, object] = {
        "url": url,
        "final_url": url,
        "status_code": None,
        "headers": {},
        "options_headers": {},
        "allow_header": "Not Found",
        "comments": [],
        "scripts": [],
        "images": [],
        "css": [],
        "flags": [],
        "deep_results": [],
        "robots_status": None,
        "error": None,
    }

    try:
        response = safe_request("GET", url, cookies=cookies, max_bytes=MAX_RESPONSE_BYTES)
        results["final_url"] = response.url
        results["status_code"] = response.status_code
        results["headers"] = filter_headers(response.headers)

        try:
            options_response = safe_request(
                "OPTIONS", url, max_bytes=0, include_body=False, timeout=(3, 5)
            )
            results["options_headers"] = filter_headers(options_response.headers)
            results["allow_header"] = options_response.headers.get("Allow", "Not Found")[:200]
        except OutboundRequestError:
            results["allow_header"] = "Failed to fetch"

        soup = BeautifulSoup(response.text, "lxml")

        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment_text = redact_text(str(comment).strip())
            if comment_text:
                results["comments"].append(comment_text)
            if len(results["comments"]) >= 100:
                break

        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                results["scripts"].append(urljoin(url, src))
            if len(results["scripts"]) >= 100:
                break

        for image in soup.find_all("img"):
            src = image.get("src")
            if src:
                results["images"].append(urljoin(url, src))
            if len(results["images"]) >= 100:
                break

        for link in soup.find_all("link", rel="stylesheet"):
            href = link.get("href")
            if href:
                results["css"].append(urljoin(url, href))
            if len(results["css"]) >= 50:
                break

        if flag_pattern and flag_pattern.strip():
            try:
                pattern = flag_pattern if use_regex else re.escape(flag_pattern)
                values = []
                for match in _finditer(pattern, response.text, flags=re.IGNORECASE):
                    values.append(redact_text(match.group(0)))
                    if len(values) >= 50:
                        break
                results["flags"] = sorted(set(values))
            except (ValueError, RegexTimeout):
                pass

        try:
            robots_url = urljoin(url, "/robots.txt")
            robots_response = safe_request("GET", robots_url, max_bytes=MAX_ROBOTS_BYTES)
            results["robots_status"] = robots_response.status_code
            if robots_response.status_code == 200:
                results["robots_txt"] = robots_response.text[:MAX_ROBOTS_BYTES]
        except OutboundRequestError as exc:
            results["robots_status"] = "Error"
            results["robots_error"] = str(exc)

        target_host = (urlparse(url).hostname or "").lower()
        assets: List[str] = []
        for asset in list(dict.fromkeys(results["scripts"] + results["css"])):
            parsed = urlparse(asset)
            asset_host = (parsed.hostname or "").lower()
            if asset_host == target_host or asset_host.endswith("." + target_host):
                assets.append(asset)
            if len(assets) >= MAX_ASSETS:
                break

        with ThreadPoolExecutor(max_workers=MAX_ASSET_WORKERS) as executor:
            futures = {
                executor.submit(analyze_asset, asset, flag_pattern, use_regex): asset
                for asset in assets
            }
            for future in as_completed(futures):
                try:
                    finding = future.result()
                except Exception:
                    logger.exception("asset analysis failed")
                    continue
                if finding:
                    results["deep_results"].append(finding)

    except (OutboundRequestError, RegexTimeout) as exc:
        results["error"] = str(exc)
    except Exception:
        logger.exception("live scan failed")
        results["error"] = "scan failed"

    return results


# ---------------------------------------------------------------------------
# Wayback CDX
# ---------------------------------------------------------------------------


def validate_domain(value: str) -> str:
    value = (value or "").strip().lower()
    if len(value) > MAX_DOMAIN_LENGTH:
        raise ValueError("domain is too long")
    if "://" in value:
        parsed = urlparse(value)
        value = (parsed.hostname or "").lower()
    value = value.strip(".")
    if not value or " " in value or "/" in value or ":" in value:
        raise ValueError("invalid domain")
    if not re.fullmatch(r"[a-z0-9.-]+", value):
        raise ValueError("invalid domain")
    if ".." in value or value.startswith("-") or value.endswith("-"):
        raise ValueError("invalid domain")
    return value


def fetch_snapshots(domain: str, year: Optional[str] = None, limit: int = 100) -> List[Dict[str, str]]:
    domain = validate_domain(domain)
    limit = clamp_int(limit, 1, MAX_SNAPSHOTS, default=100)

    params = {
        "url": domain,
        "output": "json",
        "fl": "timestamp,original",
        "filter": "statuscode:200",
        "limit": str(limit),
    }
    if year:
        if not re.fullmatch(r"\d{4}", str(year)):
            raise ValueError("year must be four digits")
        year_int = int(year)
        if not 1900 <= year_int <= 2100:
            raise ValueError("year is out of range")
        params["from"] = f"{year_int}0101"
        params["to"] = f"{year_int}1231"

    response = safe_request("GET", CDX_API, params=params, max_bytes=MAX_CDX_BYTES)
    if response.status_code != 200:
        raise OutboundRequestError(f"Wayback CDX returned status {response.status_code}")
    try:
        data = json.loads(response.text)
    except (ValueError, TypeError) as exc:
        raise OutboundRequestError("Wayback CDX returned invalid JSON") from exc
    if not isinstance(data, list) or len(data) <= 1:
        return []

    snapshots: List[Dict[str, str]] = []
    for row in data[1 : limit + 1]:
        if isinstance(row, list) and len(row) >= 2:
            timestamp, original = str(row[0]), str(row[1])
            if re.fullmatch(r"\d{14}", timestamp):
                snapshots.append({"timestamp": timestamp, "original": original})
    return snapshots


# ---------------------------------------------------------------------------
# Access control and rate limiting
# ---------------------------------------------------------------------------


def _client_ip() -> str:
    return request.remote_addr or "unknown"


def _is_loopback_address(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


_rate_lock = threading.Lock()
_rate_events: Dict[str, deque] = defaultdict(deque)


def _rate_limit_ok(key: str) -> bool:
    now = time.monotonic()
    with _rate_lock:
        if len(_rate_events) > 10000:
            _rate_events.clear()
        queue = _rate_events[key]
        while queue and now - queue[0] > RATE_LIMIT_WINDOW:
            queue.popleft()
        if len(queue) >= RATE_LIMIT_MAX:
            return False
        queue.append(now)
        return True


def require_api_access(view):
    """Require a token for remote access, with loopback-only fallback."""

    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if API_TOKEN:
            authorization = request.headers.get("Authorization", "")
            if not authorization.startswith("Bearer "):
                return jsonify(error="unauthorized"), 401
            supplied = authorization[7:].strip()
            if not hmac.compare_digest(supplied, API_TOKEN):
                return jsonify(error="unauthorized"), 401
        elif not ALLOW_UNAUTHENTICATED:
            forwarded = request.headers.get("X-Forwarded-For")
            if forwarded or not _is_loopback_address(_client_ip()):
                return jsonify(error="API token required for remote access"), 401

        if not _rate_limit_ok(_client_ip()):
            response = jsonify(error="rate limit exceeded")
            response.headers["Retry-After"] = str(RATE_LIMIT_WINDOW)
            return response, 429
        return view(*args, **kwargs)

    return wrapped


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def send_sse_event(data: Dict[str, object]) -> str:
    return f"data: {json.dumps(data)}\n\n"


@app.after_request
def add_security_headers(response: Response) -> Response:
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
    )
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'",
    )
    if request.is_secure:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(413)
def request_too_large(_error):
    if request.path.startswith("/api/"):
        return jsonify(error="request body too large"), 413
    return "Request body too large", 413


@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/"):
        return jsonify(error="not found"), 404
    return error


@app.errorhandler(405)
def method_not_allowed(error):
    if request.path.startswith("/api/"):
        response = jsonify(error="method not allowed")
        response.headers["Allow"] = "POST" if request.path == "/api/live-scan" else "GET"
        return response, 405
    return error


@app.errorhandler(500)
def internal_error(_error):
    logger.exception("unhandled server error")
    if request.path.startswith("/api/"):
        return jsonify(error="internal server error"), 500
    return "Internal server error", 500


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/health")
def health():
    return jsonify(status="ok", name=APP_NAME, version=VERSION)


@app.route("/api/scan")
@require_api_access
def scan():
    try:
        domain = validate_domain(request.args.get("domain", ""))
        year = request.args.get("year") or None
        if year and not re.fullmatch(r"\d{4}", year):
            raise ValueError("year must be four digits")
        if year and not 1900 <= int(year) <= 2100:
            raise ValueError("year is out of range")

        keyword_input = request.args.get("keyword", "")[:500]
        keywords = [item.strip() for item in keyword_input.split(",") if item.strip()]
        keywords = keywords[:MAX_KEYWORDS]
        use_regex = parse_bool(request.args.get("use_regex", "false"))
        if use_regex:
            for keyword in keywords:
                validate_regex_pattern(keyword)
        limit = clamp_int(request.args.get("limit", "100"), 1, MAX_SNAPSHOTS, default=100)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    def generate():
        total_matches = 0
        try:
            yield send_sse_event(
                {"type": "progress", "message": f"Contacting Wayback Machine for: {domain}..."}
            )
            try:
                snapshots = fetch_snapshots(domain, year, limit)
            except Exception as exc:
                logger.warning("snapshot fetch failed: %s", exc)
                yield send_sse_event({"type": "error", "error": "failed to fetch snapshots"})
                return

            if not snapshots:
                yield send_sse_event(
                    {"type": "complete", "message": "No snapshots found for this criteria."}
                )
                return

            yield send_sse_event(
                {
                    "type": "progress",
                    "message": f"Analyzing {len(snapshots)} snapshots for {len(keywords)} keywords...",
                    "currentSnapshot": 0,
                    "totalSnapshots": len(snapshots),
                }
            )

            def process_snapshot(snapshot: Dict[str, str]) -> List[Dict[str, object]]:
                timestamp = snapshot["timestamp"]
                original = snapshot["original"]
                archive_url = f"https://web.archive.org/web/{timestamp}/{original}"
                try:
                    time.sleep(random.uniform(0.5, 1.5))
                    response = safe_request(
                        "GET", archive_url, max_bytes=MAX_RESPONSE_BYTES
                    )
                    if response.status_code == 200:
                        return extract_data(
                            response.text, keywords, timestamp, archive_url, use_regex
                        )
                except Exception:
                    logger.debug("snapshot failed: %s", timestamp, exc_info=True)
                return []

            processed = 0
            with ThreadPoolExecutor(max_workers=MAX_SNAPSHOT_WORKERS) as executor:
                futures = {
                    executor.submit(process_snapshot, snapshot): snapshot
                    for snapshot in snapshots
                }
                for future in as_completed(futures):
                    processed += 1
                    try:
                        matches = future.result()
                    except Exception:
                        matches = []
                    yield send_sse_event(
                        {
                            "type": "progress",
                            "message": f"Scanned snapshot {processed}/{len(snapshots)}",
                            "currentSnapshot": processed,
                            "totalSnapshots": len(snapshots),
                        }
                    )
                    for match in matches:
                        if total_matches >= MAX_TOTAL_MATCHES:
                            break
                        total_matches += 1
                        yield send_sse_event({"type": "match", "match": match})

            yield send_sse_event({"type": "complete", "message": "Scan complete."})
        except GeneratorExit:
            return
        except Exception:
            logger.exception("scan failed")
            yield send_sse_event({"type": "error", "error": "scan failed"})

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-store",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/api/live-scan", methods=["POST"])
@require_api_access
def live_scan():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="JSON body required"), 400

    if not parse_bool(payload.get("authorized", False)):
        return jsonify(error="authorization confirmation required"), 400

    url = str(payload.get("url", "")).strip()
    cookies = str(payload.get("cookies", "") or "")
    flag_pattern = str(payload.get("flag_pattern", "ctf{") or "ctf{")
    use_regex = parse_bool(payload.get("use_regex", False))

    if not url:
        return jsonify(error="URL is required"), 400
    if len(url) > MAX_URL_LENGTH:
        return jsonify(error="URL is too long"), 400
    if len(cookies) > MAX_COOKIE_LENGTH:
        return jsonify(error="cookie header is too long"), 400
    if len(flag_pattern) > MAX_REGEX_LENGTH:
        return jsonify(error="flag pattern is too long"), 400
    if use_regex:
        try:
            validate_regex_pattern(flag_pattern)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400

    try:
        # Validate before entering the scanner so blocked destinations are a
        # clean 400 rather than a 200 response with an error field.
        normalized_url = normalize_target_url(url)
        validate_outbound_url(normalized_url)
        results = scan_live_site(normalized_url, cookies, flag_pattern, use_regex)
    except OutboundRequestError as exc:
        return jsonify(error=str(exc)), 400
    except RegexTimeout as exc:
        return jsonify(error=str(exc)), 400
    except Exception:
        logger.exception("live scan failed")
        return jsonify(error="scan failed"), 500

    return jsonify(results)


if __name__ == "__main__":
    host = os.getenv("WEBWAY_HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5000"))
    debug = env_bool("FLASK_DEBUG", False)
    if host not in {"127.0.0.1", "::1", "localhost"} and not API_TOKEN and not ALLOW_UNAUTHENTICATED:
        raise SystemExit(
            "Refusing to bind to a non-loopback interface without WEBWAY_API_TOKEN. "
            "Set WEBWAY_API_TOKEN or explicitly set WEBWAY_ALLOW_UNAUTHENTICATED=1."
        )
    app.run(host=host, port=port, debug=debug, threaded=True)
