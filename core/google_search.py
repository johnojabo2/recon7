import hashlib
import logging
import re
import urllib.parse
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
import httpx
from bs4 import BeautifulSoup
from core.config import settings

logger = logging.getLogger(__name__)

# Runtime flags to avoid repeating failed API calls if quota/credentials fail
_QUOTA_EXHAUSTED: bool = False
_SERPAPI_EXHAUSTED: bool = False


def _hash_query(query: str) -> str:
    """Computes deterministic SHA256 hash for query normalization and caching."""
    return hashlib.sha256(query.strip().lower().encode("utf-8")).hexdigest()


def _is_expired(expires_at: Optional[datetime]) -> bool:
    """Safely checks if datetime has expired, handling SQLite naive/aware timestamps."""
    if expires_at is None:
        return False
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at < datetime.now(timezone.utc)


def _get_cached_search_results(query: str) -> Optional[List[Dict[str, Any]]]:
    """Retrieves valid cached search results from SQLite search_cache table."""
    q_hash = _hash_query(query)
    try:
        from storage.db import get_db_session, SearchCache
        with get_db_session() as db:
            cached = db.query(SearchCache).filter(SearchCache.query_hash == q_hash).first()
            if cached and not _is_expired(cached.expires_at):
                logger.info(
                    f"[core.google_search] Cache HIT for '{query[:45]}' "
                    f"(0 credits consumed, provider: {cached.provider}, items: {len(cached.results)})"
                )
                return list(cached.results)
    except Exception as e:
        logger.debug(f"[core.google_search] Cache lookup skipped/error: {e}")
    return None


def _save_cached_search_results(query: str, provider: str, results: List[Dict[str, Any]]) -> None:
    """Stores query results persistently in SQLite search_cache with configurable TTL."""
    if not results:
        return
    q_hash = _hash_query(query)
    try:
        from storage.db import get_db_session, SearchCache
        now = datetime.now(timezone.utc)
        ttl_days = getattr(settings, "SEARCH_CACHE_TTL_DAYS", 7)
        expires = now + timedelta(days=ttl_days)
        with get_db_session() as db:
            cache_entry = SearchCache(
                query_hash=q_hash,
                query=query.strip(),
                provider=provider,
                results=results,
                created_at=now,
                expires_at=expires,
            )
            db.merge(cache_entry)
            db.commit()
    except Exception as e:
        logger.debug(f"[core.google_search] Cache save skipped/error: {e}")


def is_serpapi_available() -> bool:
    """Returns True if SerpAPI key is configured and not exhausted."""
    global _SERPAPI_EXHAUSTED
    if _SERPAPI_EXHAUSTED:
        return False
    return bool(getattr(settings, "SERPAPI_API_KEY", None))


def is_google_search_available() -> bool:
    """Returns True if Google Custom Search API credentials are present and quota is not exhausted."""
    global _QUOTA_EXHAUSTED
    if _QUOTA_EXHAUSTED:
        return False
    return bool(settings.GOOGLE_SEARCH_API_KEY and settings.GOOGLE_SEARCH_ENGINE_ID)


def _query_serpapi(query: str, num: int = 10, timeout: int = 12) -> List[Dict[str, Any]]:
    """Executes search via official SerpAPI proxy for Google Search."""
    global _SERPAPI_EXHAUSTED
    api_key = settings.SERPAPI_API_KEY
    if not api_key:
        return []

    url = "https://serpapi.com/search.json"
    params = {
        "engine": "google",
        "q": query,
        "api_key": api_key,
        "num": min(max(num, 1), 10),
    }

    results: List[Dict[str, Any]] = []
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url, params=params)
            if resp.status_code == 200:
                data = resp.json()

                # 1. Parse Organic Search Results
                organic = data.get("organic_results", [])
                for item in organic:
                    title = item.get("title", "").strip()
                    link = item.get("link", "").strip()
                    snippet = item.get("snippet", "").strip()
                    if link:
                        results.append({
                            "title": title,
                            "link": link,
                            "snippet": snippet,
                        })

                # 2. Extract Google Knowledge Graph entity if present
                kg = data.get("knowledge_graph", {})
                if kg and kg.get("title"):
                    kg_title = kg.get("title", "").strip()
                    kg_type = kg.get("type", "").strip()
                    kg_desc = kg.get("description", "").strip()
                    kg_snippet = f"Entity: {kg_title} ({kg_type}). {kg_desc}".strip()
                    kg_link = kg.get("website", "") or (results[0]["link"] if results else "")
                    if kg_link:
                        results.insert(0, {
                            "title": f"[Knowledge Graph] {kg_title}",
                            "link": kg_link,
                            "snippet": kg_snippet,
                        })

                logger.info(f"[core.google_search] SerpAPI query returned {len(results)} items for '{query[:40]}'")
                return results

            elif resp.status_code in [401, 403, 429]:
                logger.warning(f"[core.google_search] SerpAPI returned {resp.status_code}. Falling back to next tier.")
                _SERPAPI_EXHAUSTED = True
            else:
                logger.debug(f"[core.google_search] SerpAPI returned status {resp.status_code}")
    except Exception as e:
        logger.debug(f"[core.google_search] SerpAPI request error: {e}. Falling back.")
    return []


def _query_google_cse(query: str, num: int = 10, timeout: int = 12) -> List[Dict[str, Any]]:
    """Executes search via Google Custom Search JSON API."""
    global _QUOTA_EXHAUSTED
    api_key = settings.GOOGLE_SEARCH_API_KEY
    cse_id = settings.GOOGLE_SEARCH_ENGINE_ID
    endpoint = "https://www.googleapis.com/customsearch/v1"
    params = {
        "key": api_key,
        "cx": cse_id,
        "q": query,
        "num": min(max(num, 1), 10),
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(endpoint, params=params)
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items", [])
                results = []
                for item in items:
                    results.append({
                        "title": item.get("title", "").strip(),
                        "link": item.get("link", "").strip(),
                        "snippet": item.get("snippet", "").strip(),
                    })
                logger.info(f"[core.google_search] Google CSE returned {len(results)} items for '{query[:40]}'")
                return results
            elif resp.status_code in [403, 429]:
                logger.warning(
                    f"[core.google_search] Google Search API quota reached or forbidden ({resp.status_code})."
                )
                _QUOTA_EXHAUSTED = True
    except Exception as e:
        logger.debug(f"[core.google_search] Google CSE request error: {e}")
    return []


def query_google_search(
    query: str,
    num: int = 10,
    timeout: int = 12,
    use_cache: bool = True,
) -> List[Dict[str, Any]]:
    """
    Unified Search Engine Interface with Persistent Caching & Tiered Fallback.
    1. Checks persistent SQLite search_cache (TTL 7 days) -> 0 credits consumed.
    2. Attempts SerpAPI if SERPAPI_API_KEY is configured in .env.
    3. Attempts Google Custom Search API if configured.
    4. Falls back to free keyless search (DuckDuckGo Lite/HTML scraper).
    5. Stores new results in cache.
    """
    # 1. Check Persistent SQLite Cache
    if use_cache:
        cached = _get_cached_search_results(query)
        if cached is not None:
            return cached

    results: List[Dict[str, Any]] = []
    provider_used = "keyless"

    # 2. Tier 1: SerpAPI (Residential Proxy & High Concurrency)
    if is_serpapi_available():
        results = _query_serpapi(query, num=num, timeout=timeout)
        if results:
            provider_used = "serpapi"

    # 3. Tier 2: Official Google Custom Search API
    if not results and is_google_search_available():
        results = _query_google_cse(query, num=num, timeout=timeout)
        if results:
            provider_used = "google_cse"

    # 4. Tier 3: Free Keyless Search Fallback (Zero Config / Free)
    if not results:
        logger.info(f"[core.google_search] Executing keyless fallback search for '{query[:40]}...'")
        results = _query_keyless_search(query, num=num, timeout=timeout)
        provider_used = "keyless"

    # 5. Persist to SQLite Cache
    if results and use_cache:
        _save_cached_search_results(query, provider_used, results)

    return results


def _query_keyless_search(query: str, num: int = 10, timeout: int = 12) -> List[Dict[str, Any]]:
    """
    Keyless search engine scraper using DuckDuckGo Lite & HTML endpoints.
    Requires no API keys, no tokens, and works completely free out of the box.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin": "https://lite.duckduckgo.com",
        "Referer": "https://lite.duckduckgo.com/",
    }

    results: List[Dict[str, Any]] = []

    # Attempt 1: DuckDuckGo Lite POST
    try:
        with httpx.Client(timeout=timeout, headers=headers, follow_redirects=True) as client:
            resp = client.post("https://lite.duckduckgo.com/lite/", data={"q": query})
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                links = soup.find_all("a", class_="result-link")
                snippets = soup.find_all("td", class_="result-snippet")

                for idx, a_tag in enumerate(links[:num]):
                    href = a_tag.get("href", "").strip()
                    if "uddg=" in href:
                        m = re.search(r"uddg=([^&]+)", href)
                        if m:
                            href = urllib.parse.unquote(m.group(1))

                    if not href or href.startswith("/") or "duckduckgo.com" in href:
                        continue

                    title = a_tag.get_text().strip()
                    snippet = snippets[idx].get_text().strip() if idx < len(snippets) else ""

                    results.append({
                        "title": title,
                        "link": href,
                        "snippet": snippet,
                    })

                if results:
                    logger.info(f"[core.google_search] Keyless search (DDG Lite) returned {len(results)} items for '{query[:40]}...'")
                    return results

    except Exception as e:
        logger.debug(f"[core.google_search] DDG Lite scraper error: {e}")

    # Attempt 2: DuckDuckGo HTML GET Fallback
    try:
        with httpx.Client(timeout=timeout, headers=headers, follow_redirects=True) as client:
            resp = client.get("https://html.duckduckgo.com/html/", params={"q": query})
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                for result_div in soup.find_all("div", class_=re.compile(r"result__body|web-result")):
                    a_tag = result_div.find("a", class_=re.compile(r"result__url|result__snippet|result__a"))
                    if not a_tag:
                        a_tag = result_div.find("a", href=True)
                    if not a_tag:
                        continue

                    href = a_tag.get("href", "").strip()
                    if "uddg=" in href:
                        m = re.search(r"uddg=([^&]+)", href)
                        if m:
                            href = urllib.parse.unquote(m.group(1))

                    if not href or href.startswith("/") or "duckduckgo.com" in href:
                        continue

                    title = a_tag.get_text().strip()
                    snip_elem = result_div.find(class_=re.compile(r"snippet"))
                    snippet = snip_elem.get_text().strip() if snip_elem else ""

                    results.append({
                        "title": title,
                        "link": href,
                        "snippet": snippet,
                    })
                    if len(results) >= num:
                        break

                if results:
                    logger.info(f"[core.google_search] Keyless search (DDG HTML) returned {len(results)} items for '{query[:40]}...'")
                    return results

    except Exception as e:
        logger.debug(f"[core.google_search] DDG HTML scraper error: {e}")

    return results

