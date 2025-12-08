import requests
import os

def check_url(url, name):
    print(f"Checking {name} ({url})...")
    try:
        response = requests.get(url, timeout=10)
        print(f"  Status: {response.status_code}")
        print(f"  Success!")
    except Exception as e:
        print(f"  Failed: {e}")

print("Environment Proxy Settings:")
print(f"  HTTP_PROXY: {os.environ.get('HTTP_PROXY')}")
print(f"  HTTPS_PROXY: {os.environ.get('HTTPS_PROXY')}")

print("\nConnectivity Tests:")
check_url("https://www.google.com", "Google")
check_url("https://web.archive.org", "Wayback Machine")
check_url("https://web.archive.org/cdx/search/cdx", "CDX API")
