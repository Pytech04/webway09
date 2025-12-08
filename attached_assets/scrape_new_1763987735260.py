import httpx
import re
import time
import random
import sys
from bs4 import BeautifulSoup, Comment

# --- CONFIGURATION ---
CDX_API = "https://web.archive.org/cdx/search/cdx"
TIMEOUT = 60
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Referer": "https://web.archive.org/"
}

def fetch_snapshots(domain, year=None, limit=100):
    print(f"[*] Contacting Wayback Machine for: {domain}...")
    params = {
        "url": domain,
        "output": "json",
        "fl": "timestamp,original",
        "filter": "statuscode:200",
        "limit": limit
    }
    # If user provided a year, filter by that year
    if year:
        params["from"] = f"{year}0101"
        params["to"] = f"{year}1231"
        print(f"[*] Filtering for Year: {year}")

    try:
        r = httpx.get(CDX_API, params=params, timeout=TIMEOUT, headers=HEADERS)
        r.raise_for_status()
        data = r.json()
        if len(data) <= 1:
            return []
        return data[1:] # Skip headers
    except Exception as e:
        print(f"[!] API Error: {e}")
        return []

def extract_data(html, keyword):
    found_items = set()
    soup = BeautifulSoup(html, "html.parser")
    
    # 1. CLEANUP: Remove Wayback Machine's injected Toolbar & Scripts
    for tag in soup.find_all(id=["wm-ipp-base", "wm-ipp", "donato"]):
        tag.decompose()
    for tag in soup.find_all("script", src=re.compile(r"archive\.org")):
        tag.decompose()

    # Regex Pattern (Case Insensitive)
    pattern = re.compile(re.escape(keyword), re.IGNORECASE)

    # 2. SEARCH VISIBLE TEXT
    text_content = soup.get_text(separator=" ", strip=True)
    if pattern.search(text_content):
        match = pattern.search(text_content)
        start = max(0, match.start() - 30)
        end = min(len(text_content), match.end() + 30)
        snippet = text_content[start:end].replace("\n", " ")
        found_items.add(f"Found in TEXT: ...{snippet}...")

    # 3. SEARCH JAVASCRIPT (With Snippets)
    for script in soup.find_all("script"):
        if script.string:
            match = pattern.search(script.string)
            if match:
                start = max(0, match.start() - 30)
                end = min(len(script.string), match.end() + 30)
                snippet = script.string[start:end].replace("\n", " ").strip()
                found_items.add(f"Found in JS: ...{snippet}...")

    # 4. SEARCH COMMENTS
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        if pattern.search(comment):
            if "FILE ARCHIVED ON" in comment: continue
            found_items.add(f"Found in COMMENT: {comment.strip()}")

    return list(found_items)

def main():
    print("--- WAYBACK FORENSIC SCRAPER ---")
    
    # INPUTS
    target_site = input("Target Domain (e.g., example.com): ").strip()
    year_input = input("Target Year (Optional, e.g., 2022): ").strip()
    search_term = input("Keyword (e.g., ctf{ ): ").strip()
    
    if not target_site or not search_term:
        print("[!] URL and Keyword are required.")
        return

    # Fetch snapshots (Limit increased to 100 to catch the flag)
    snapshots = fetch_snapshots(target_site, year=year_input, limit=100) 
    
    if not snapshots:
        print("[-] No snapshots found for this criteria.")
        return

    print(f"[*] Analyzing {len(snapshots)} snapshots for '{search_term}'...")
    
    log_filename = f"forensic_report_{target_site}.txt"
    
    # USE CLIENT FOR STABILITY
    with httpx.Client(headers=HEADERS, timeout=TIMEOUT, follow_redirects=True) as client:
        with open(log_filename, "w") as f:
            f.write(f"Forensic Scan for: {target_site}\nYear: {year_input}\nKeyword: {search_term}\n\n")

            found_any = False
            for ts, original in snapshots:
                archive_url = f"https://web.archive.org/web/{ts}/{original}"
                print(f"Scanning snapshot: {ts}...", end="\r")
                
                try:
                    time.sleep(random.uniform(0.5, 1.0)) # Be polite
                    
                    r = client.get(archive_url)
                    if r.status_code == 200:
                        matches = extract_data(r.text, search_term)
                        if matches:
                            found_any = True
                            output = f"\n[+] MATCH FOUND in Snapshot {ts}:\n    URL: {archive_url}\n    Details: {matches}\n"
                            print(output)
                            f.write(output)
                except Exception:
                    continue 
            
            if not found_any:
                print("\n[-] Scan finished. No matches found.")
            else:
                print(f"\n\n[+] Scan Complete. Report saved to: {log_filename}")

if __name__ == "__main__":
    main()
