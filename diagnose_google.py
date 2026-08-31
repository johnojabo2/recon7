import os
import sys
import httpx
from dotenv import load_dotenv

# Load .env
load_dotenv(r"c:\Users\John\Documents\Recon7\.env", override=True)

api_key = os.getenv("GOOGLE_SEARCH_API_KEY")
cse_id = os.getenv("GOOGLE_SEARCH_ENGINE_ID")

print("=" * 60)
print(f"Testing Google Custom Search API with key: {api_key[:10]}...{api_key[-5:] if api_key else ''}")
print(f"Search Engine ID (cx): {cse_id}")
print("=" * 60)

url = "https://www.googleapis.com/customsearch/v1"
params = {
    "key": api_key,
    "cx": cse_id,
    "q": "site:notjustevent.com",
    "num": 5
}

try:
    resp = httpx.get(url, params=params, timeout=10)
    print(f"HTTP Status: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        items = data.get("items", [])
        print(f"\n[+] SUCCESS! Retrieved {len(items)} search results from Google Search API:")
        for idx, item in enumerate(items, 1):
            print(f"\n[{idx}] {item.get('title')}")
            print(f"    URL:     {item.get('link')}")
            print(f"    Snippet: {item.get('snippet')}")
    else:
        print(f"\n[-] Error Response ({resp.status_code}):")
        print(resp.text)
except Exception as e:
    print(f"Exception: {e}")
