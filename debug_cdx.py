import requests

CDX_API = "https://web.archive.org/cdx/search/cdx"
domain = "mysupercoolctfsite.weebly.com"
params = {
    "url": domain,
    "output": "json",
    "fl": "timestamp,original",
    "filter": "statuscode:200",
    "limit": "5"
}

try:
    print(f"Checking CDX for {domain}...")
    response = requests.get(CDX_API, params=params, timeout=30)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Found {len(data)-1} snapshots.")
        print(data)
    else:
        print("Error response")
except Exception as e:
    print(f"Exception: {e}")
