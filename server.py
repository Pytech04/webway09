from flask import Flask, request, Response, stream_with_context, render_template, send_from_directory
from flask_cors import CORS
import requests
import re
import json
import time
import random
import os
from bs4 import BeautifulSoup, Comment
from typing import List, Dict, Optional

app = Flask(__name__, 
    template_folder=os.path.join(os.path.dirname(__file__), 'templates'),
    static_folder=os.path.join(os.path.dirname(__file__), 'static'),
    static_url_path='/static'
)
from urllib.parse import urljoin, urlparse
CORS(app)

CDX_API = "https://web.archive.org/cdx/search/cdx"
TIMEOUT = 60
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure retry strategy
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
)
adapter = HTTPAdapter(max_retries=retry_strategy)
http = requests.Session()
http.mount("https://", adapter)
http.mount("http://", adapter)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Referer": "https://web.archive.org/"
}


IMPORTANT_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-generator", "via", 
    "x-backend-server", "strict-transport-security", "content-security-policy",
    "access-control-allow-origin", "set-cookie"
]

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Generic API Key": r"(?i)(api_key|apikey|secret|token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]",
    "Bearer Token": r"Bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Firebase URL": r"https://[a-z0-9-]+\.firebaseio\.com",
    "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
    # Removed Heroku/UUID pattern as it causes too many false positives
}


import concurrent.futures
import queue

def fetch_snapshots(domain: str, year: Optional[str] = None, limit: int = 100) -> List[Dict[str, str]]:
    """Fetch snapshots from Wayback Machine CDX API"""
    params = {
        "url": domain,
        "output": "json",
        "fl": "timestamp,original",
        "filter": "statuscode:200",
        "limit": str(limit)
    }
    
    if year:
        params["from"] = f"{year}0101"
        params["to"] = f"{year}1231"
    
    try:
        response = http.get(CDX_API, params=params, headers=HEADERS, timeout=TIMEOUT)
        
        if response.status_code != 200:
            raise Exception(f"Wayback CDX API returned status {response.status_code}")
        
        data = response.json()
        
        if not isinstance(data, list) or len(data) <= 1:
            return []
        
        # Skip header row and map to snapshot objects
        snapshots = []
        for row in data[1:]:
            if len(row) >= 2:
                snapshots.append({
                    "timestamp": row[0],
                    "original": row[1]
                })
        
        return snapshots
    
    except Exception as e:
        print(f"[Wayback] CDX API Error: {e}")
        raise e


def extract_data(html: str, keywords: List[str], timestamp: str, archive_url: str, use_regex: bool = False) -> List[Dict]:
    """Extract keyword matches from HTML (text, JS, comments)"""
    matches = []
    soup = BeautifulSoup(html, 'lxml')
    
    # 1. CLEANUP: Remove Wayback Machine's injected Toolbar & Scripts
    for element in soup.select("#wm-ipp-base, #wm-ipp, #donato"):
        element.decompose()
    
    for script in soup.find_all("script"):
        src = script.get("src")
        if src and "archive.org" in src:
            script.decompose()
    
    # Compile patterns
    patterns = []
    for kw in keywords:
        kw = kw.strip()
        if not kw: continue
        
        try:
            if use_regex:
                patterns.append(re.compile(kw, re.IGNORECASE))
            else:
                patterns.append(re.compile(re.escape(kw), re.IGNORECASE))
        except re.error:
            continue # Skip invalid regex

    if not patterns:
        return []
    
    # Helper to search text
    def search_text(content, match_type):
        for pattern in patterns:
            for match in pattern.finditer(content):
                start = max(0, match.start() - 30)
                end = min(len(content), match.end() + 30)
                snippet = "..." + content[start:end].replace('\n', ' ').strip() + "..."
                
                matches.append({
                    "timestamp": timestamp,
                    "archiveUrl": archive_url,
                    "matchType": match_type,
                    "snippet": snippet
                })

    # 2. SEARCH VISIBLE TEXT
    body = soup.find("body")
    if body:
        text_content = body.get_text(separator=' ', strip=True)
        text_content = re.sub(r'\s+', ' ', text_content)
        search_text(text_content, "TEXT")
    
    # 3. SEARCH JAVASCRIPT
    for script in soup.find_all("script"):
        script_content = script.string
        if script_content:
            search_text(script_content, "JS")
    
    # 4. SEARCH COMMENTS
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    for comment in comments:
        comment_text = str(comment)
        if "FILE ARCHIVED ON" in comment_text:
            continue
        search_text(comment_text, "COMMENT")
        
    # 5. SEARCH SECRETS (Global)
    # Scan the entire HTML content for secrets
    for name, pattern in SECRET_PATTERNS.items():
        matches_found = re.findall(pattern, html)
        for m in matches_found:
            secret_val = m[1] if isinstance(m, tuple) else m
            if len(secret_val) < 8: continue
            
            # Create a snippet
            start_idx = html.find(secret_val)
            start = max(0, start_idx - 20)
            end = min(len(html), start_idx + len(secret_val) + 20)
            snippet = "..." + html[start:end].replace('\n', ' ').strip() + "..."
            
            matches.append({
                "timestamp": timestamp,
                "archiveUrl": archive_url,
                "matchType": "SECRET",
                "snippet": f"[{name}] {snippet}"
            })
    
    return matches


    return matches


def analyze_asset(url: str, flag_pattern: str, use_regex: bool = False) -> Optional[Dict]:
    """Fetch and analyze a single asset (JS/CSS) for secrets"""
    # 0. Filter Noisy Domains
    IGNORED_DOMAINS = [
        "fonts.googleapis.com", "fonts.gstatic.com", 
        "google-analytics.com", "googletagmanager.com",
        "doubleclick.net"
    ]
    for domain in IGNORED_DOMAINS:
        if domain in url:
            return None

    try:
        resp = requests.get(url, headers={"User-Agent": HEADERS["User-Agent"]}, timeout=5)
        if resp.status_code != 200:
            return None
            
        content = resp.text
        findings = {
            "url": url,
            "flags": [],
            "comments": []
        }
        
        # 1. Search Flags
        if flag_pattern and flag_pattern.strip():
            try:
                if use_regex:
                    regex_pattern = flag_pattern
                else:
                    regex_pattern = re.escape(flag_pattern)
                
                flags = re.findall(regex_pattern, content, re.IGNORECASE)
                if flags:
                    findings["flags"] = list(set(flags))
            except Exception:
                pass

        # 1.5 Search Secrets (Advanced)
        found_secrets = []
        for name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            for m in matches:
                secret_val = m[1] if isinstance(m, tuple) else m
                if len(secret_val) < 8: continue 
                found_secrets.append(f"{name}: {secret_val[:10]}...")
        
        if found_secrets:
            findings["secrets"] = list(set(found_secrets))

        # 1.6 Endpoint Discovery
        endpoints = re.findall(r"['\"](\/[a-zA-Z0-9_?&=\/\-\.]+)['\"]", content)
        full_urls = re.findall(r"https?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}[a-zA-Z0-9_?&=\/\-\.]*", content)
        
        IGNORED_ENDPOINT_DOMAINS = [
            "w3.org", "github.com", "twitter.com", "facebook.com", "google.com", 
            "adobe.ly", "bit.ly", "vuejs.org", "momentjs.com", "jquery.com",
            "cloudflare.com", "googleapis.com", "gstatic.com", "vimeo.com", "youtube.com"
        ]
        
        IGNORED_EXTENSIONS = [
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.woff', '.woff2', 
            '.ttf', '.eot', '.ico', '.mp4', '.webm', '.mp3', '.wav', '.swf'
        ]

        all_endpoints = []
        for ep in endpoints + full_urls:
            if ep.startswith("//"): continue
            
            # Filter by extension
            if any(ext in ep.lower() for ext in IGNORED_EXTENSIONS): continue
            
            # Filter by domain
            if any(d in ep.lower() for d in IGNORED_ENDPOINT_DOMAINS): continue
            
            # Filter short/noise
            if len(ep) < 3 or len(ep) > 120: continue
            
            all_endpoints.append(ep)
            
        if all_endpoints:
            findings["endpoints"] = list(set(all_endpoints))
            
        # 2. Search Comments
        single_line = re.findall(r'//.*$', content, re.MULTILINE)
        multi_line = re.findall(r'/\*[\s\S]*?\*/', content)
        
        all_comments = single_line + multi_line
        clean_comments = []
        
        IGNORED_COMMENTS = [
            "/* latin */", "/* latin-ext */", "/* cyrillic */", "/* cyrillic-ext */",
            "/* greek */", "/* greek-ext */", "/* vietnamese */", "/* hebrew */",
            "/* math */", "/* symbols */", "sourceMappingURL=", "Super Modern Browsers",
            "generated by", "license", "copyright"
        ]

        for c in all_comments:
            c = c.strip()
            if len(c) > 300: c = c[:300] + "..."
            
            if len(c) < 5: continue
            c_lower = c.lower()
            
            # Filter JSDoc and Code-like comments
            if c.startswith("/**") or "* @" in c: continue # JSDoc
            if "function(" in c or "var " in c or "return " in c or "window." in c: continue # Code
            if "{" in c and "}" in c: continue # JSON or Code
            
            if "copyright" in c_lower or "license" in c_lower: continue
            
            is_ignored = False
            for ignored in IGNORED_COMMENTS:
                if ignored.lower() in c_lower:
                    is_ignored = True
                    break
            if is_ignored: continue

            if "fonts.gstatic.com" in c: continue

            clean_comments.append(c)
            
        if clean_comments:
            findings["comments"] = list(set(clean_comments))
            
        if findings.get("flags") or findings.get("comments") or findings.get("secrets") or findings.get("endpoints"):
            return findings
            
    except Exception:
        pass
    return None


def scan_live_site(url: str, cookies_str: Optional[str] = None, flag_pattern: str = "ctf{", use_regex: bool = False) -> Dict:
    """Scan a live website for headers, comments, scripts, and flags"""
    results = {
        "headers": {},
        "comments": [],
        "scripts": [],
        "images": [],
        "css": [],
        "flags": [],
        "deep_results": [],
        "error": None
    }
    
    # Parse cookies
    cookies = {}
    if cookies_str:
        try:
            for pair in cookies_str.split(';'):
                if '=' in pair:
                    k, v = pair.strip().split('=', 1)
                    cookies[k] = v
        except Exception:
            pass

    try:
        # Make request
        resp = requests.get(url, cookies=cookies, headers={"User-Agent": HEADERS["User-Agent"]}, timeout=10)
        
        # 1. Headers (Capture ALL)
        results["headers"] = dict(resp.headers)
        
        # 1.5 OPTIONS Scan (HTTP Methods)
        try:
            options_resp = requests.options(url, headers={"User-Agent": HEADERS["User-Agent"]}, timeout=5)
            results["options_headers"] = dict(options_resp.headers)
            results["allow_header"] = options_resp.headers.get("Allow", "Not Found")
        except Exception:
            results["allow_header"] = "Failed to fetch"

        # 2. Parse HTML
        soup = BeautifulSoup(resp.text, 'lxml')
        
        # 3. Comments
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for c in comments:
            c_str = str(c).strip()
            if c_str:
                results["comments"].append(c_str)
                
        # 4. Scripts
        for s in soup.find_all("script"):
            src = s.get("src")
            if src:
                abs_url = urljoin(url, src)
                results["scripts"].append(abs_url)
                
        # 5. Images
        for img in soup.find_all("img"):
            src = img.get("src")
            if src:
                results["images"].append(urljoin(url, src))

        # 5.5 CSS
        for link in soup.find_all("link", rel="stylesheet"):
            href = link.get("href")
            if href:
                abs_url = urljoin(url, href)
                results["css"].append(abs_url)
                
        # 6. Flags (Main Page)
        if flag_pattern and flag_pattern.strip():
            try:
                if use_regex:
                    regex_pattern = flag_pattern
                else:
                    regex_pattern = re.escape(flag_pattern)
                
                flags = re.findall(regex_pattern, resp.text, re.IGNORECASE)
                results["flags"] = list(set(flags))
            except Exception as e:
                print(f"Flag regex error: {e}")

        # 6.5 Robots.txt
        results["robots_status"] = None
        try:
            robots_url = urljoin(url, "/robots.txt")
            robots_resp = requests.get(robots_url, headers={"User-Agent": HEADERS["User-Agent"]}, timeout=5)
            results["robots_status"] = robots_resp.status_code
            if robots_resp.status_code == 200:
                results["robots_txt"] = robots_resp.text
        except Exception as e:
            results["robots_status"] = f"Error: {str(e)}"

        # 7. Deep Analysis (Concurrent)
        assets_to_scan = list(set(results["scripts"] + results["css"]))
        
        # Filter: Only scan assets from the target domain (or subdomains)
        target_netloc = urlparse(url).netloc
        filtered_assets = []
        for asset in assets_to_scan:
            try:
                asset_netloc = urlparse(asset).netloc
                # Check if exact match or subdomain
                if asset_netloc == target_netloc or asset_netloc.endswith("." + target_netloc):
                    filtered_assets.append(asset)
            except Exception:
                continue
                
        # Limit to 20 assets to prevent long waits
        assets_to_scan = filtered_assets[:20]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_url = {
                executor.submit(analyze_asset, asset_url, flag_pattern, use_regex): asset_url 
                for asset_url in assets_to_scan
            }
            
            for future in concurrent.futures.as_completed(future_to_url):
                res = future.result()
                if res:
                    results["deep_results"].append(res)

    except Exception as e:
        results["error"] = str(e)
        
    return results


def send_sse_event(data: Dict) -> str:
    """Format data as SSE event"""
    return f"data: {json.dumps(data)}\n\n"


@app.route('/')
def index():
    """Serve the main HTML page"""
    return render_template('index.html')


@app.route('/api/scan')
def scan():
    """SSE endpoint for forensic scanning"""
    domain = request.args.get('domain')
    year = request.args.get('year')
    keyword_input = request.args.get('keyword')
    limit = request.args.get('limit', '100')
    use_regex = request.args.get('use_regex', 'false').lower() == 'true'
    
    # Validate required parameters
    if not domain:
        return {"error": "Missing required parameter: domain"}, 400
    
    try:
        limit = int(limit)
    except ValueError:
        limit = 100
        
    # Split keywords (if any)
    keywords = []
    if keyword_input:
        keywords = [k.strip() for k in keyword_input.split(',') if k.strip()]
    
    def generate():
        """Generator function for SSE stream"""
        try:
            # Fetch snapshots
            yield send_sse_event({
                "type": "progress",
                "message": f"Contacting Wayback Machine for: {domain}..."
            })
            
            try:
                snapshots = fetch_snapshots(domain, year, limit)
            except Exception as e:
                yield send_sse_event({
                    "type": "error",
                    "error": f"Failed to fetch snapshots: {str(e)}"
                })
                return
            
            if not snapshots:
                yield send_sse_event({
                    "type": "complete",
                    "message": "No snapshots found for this criteria."
                })
                return
            
            yield send_sse_event({
                "type": "progress",
                "message": f"Analyzing {len(snapshots)} snapshots for {len(keywords)} keywords...",
                "currentSnapshot": 0,
                "totalSnapshots": len(snapshots)
            })
            
            found_any = False
            processed_count = 0
            
            # Concurrency Setup
            # We use a Queue to collect results from threads
            result_queue = queue.Queue()
            
            def process_snapshot(snapshot_data):
                idx, snap = snapshot_data
                ts = snap["timestamp"]
                orig = snap["original"]
                arch_url = f"https://web.archive.org/web/{ts}/{orig}"
                
                try:
                    # Random delay to be polite, but parallelized
                    time.sleep(random.uniform(0.5, 1.5))
                    
                    resp = http.get(arch_url, headers=HEADERS, timeout=TIMEOUT)
                    if resp.status_code == 200:
                        found_matches = extract_data(resp.text, keywords, ts, arch_url, use_regex)
                        return (idx, found_matches)
                except Exception:
                    pass
                return (idx, [])

            # Use ThreadPoolExecutor
            # Max workers = 5 to be safe with rate limits
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                # Submit all tasks
                future_to_snap = {
                    executor.submit(process_snapshot, (i, s)): i 
                    for i, s in enumerate(snapshots)
                }
                
                for future in concurrent.futures.as_completed(future_to_snap):
                    processed_count += 1
                    idx, matches = future.result()
                    
                    # Send progress update
                    yield send_sse_event({
                        "type": "progress",
                        "message": f"Scanned snapshot {processed_count}/{len(snapshots)}",
                        "currentSnapshot": processed_count,
                        "totalSnapshots": len(snapshots)
                    })
                    
                    if matches:
                        found_any = True
                        for match in matches:
                            yield send_sse_event({
                                "type": "match",
                                "match": match
                            })

            # Send completion message
            if found_any:
                yield send_sse_event({
                    "type": "complete",
                    "message": "Scan complete."
                })
            else:
                yield send_sse_event({
                    "type": "complete",
                    "message": "Scan finished. No matches found."
                })
        
        except Exception as e:
            print(f"[Scan Error]: {e}")
            yield send_sse_event({
                "type": "error",
                "error": str(e)
            })
    
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        }
    )


@app.route('/api/live-scan')
def live_scan():
    """Endpoint for live website scanning"""
    url = request.args.get('url')
    cookies = request.args.get('cookies')
    flag_pattern = request.args.get('flag_pattern', 'ctf')
    use_regex = request.args.get('use_regex', 'false').lower() == 'true'
    
    if not url:
        return {"error": "Missing URL parameter"}, 400
        
    if not url.startswith('http'):
        url = 'https://' + url
        
    results = scan_live_site(url, cookies, flag_pattern, use_regex)
    return results


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'True') == 'True'
    app.run(host='0.0.0.0', port=port, debug=debug_mode, threaded=True)
