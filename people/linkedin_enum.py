import logging
import re
import urllib.parse
from typing import List, Dict, Any, Set, Optional
import httpx
from bs4 import BeautifulSoup
from core.scope import extract_root_domain

logger = logging.getLogger(__name__)

LINKEDIN_CLEAN_PATTERNS = [
    r"\s*-\s*LinkedIn$",
    r"\s*\|\s*LinkedIn$",
    r"\s*-\s*Professional Profile\s*-\s*LinkedIn$",
    r"\s*-\s*United States\s*\|\s*Professional Profile\s*-\s*LinkedIn$",
    r"\s*on LinkedIn:.*$",
]

INVALID_WORDS = {
    # Technical & Navigation Noise
    "network", "transactions", "deliver", "booking", "developer",
    "repositories", "packages", "event", "planning", "terms",
    "privacy", "cookie", "support", "services", "solutions",
    "management", "overview", "story", "vision", "mission",
    "values", "about", "contact", "pricing", "login", "register",
    "signup", "dashboard", "features", "benefits", "reviews",
    "venues", "they", "we", "you", "our", "the", "how", "what",
    "where", "why", "join", "get", "book", "hire", "fit", "true",
    "analyzed", "ip", "being", "post", "posts", "update", "hiring",
    "jobs", "job", "vacancy", "internship", "feed", "activity",
    "united", "states", "nigeria", "india", "london", "canada",
    # Web UI & Call-to-Action Phrases (blocks "Visit Us", "Contact Us", etc.)
    "visit", "us", "read", "more", "learn", "click", "here",
    "follow", "share", "like", "subscribe", "see", "all", "view",
    "show", "home", "back", "next", "press", "release", "news",
    "blog", "events", "admin", "administrator", "official",
    # Corporate & Institutional Suffixes (blocks "NotJustEvent, Inc.", "Acme LLC")
    "inc", "llc", "ltd", "corp", "corporation", "co", "company",
    "technologies", "tech", "group", "studios", "holdings", "solutions",
    "enterprises", "hq", "international", "global",
    # Institutional / Academic Organization words
    "university", "institute", "center", "centre", "faculty",
    "department", "college", "school", "portal", "foundation", "association",
}


def clean_human_name(name: str, org_name: str = "") -> str:
    """Extracts and formats a clean human First & Last name; returns empty string if not a human."""
    if not name or len(name.strip()) < 3:
        return ""
    
    clean = re.sub(r"\(.*?\)", "", name)
    clean = re.sub(r"\s*\|\s*.*$", "", clean)
    clean = re.sub(r"\s*[-–]\s*.*$", "", clean)
    clean = clean.strip()
    
    # Strip trailing corporate abbreviations separated by comma (e.g. "NotJustEvent, Inc.")
    if "," in clean:
        parts = clean.split(",")
        if len(parts) >= 2 and parts[1].strip().lower().replace(".", "") in {"inc", "llc", "ltd", "corp", "co"}:
            return ""  # It's an incorporated company, not a human!
        clean = parts[0].strip()
    
    words = clean.split()
    if not (2 <= len(words) <= 4):
        return ""
        
    org_lower = org_name.lower().replace(" ", "").replace("_", "").replace("-", "") if org_name else ""
    
    formatted_words = []
    for w in words:
        w_clean = re.sub(r"[^a-zA-Z]", "", w).lower()
        # Reject empty or single-letter names (e.g. "FULafia V" -> last name "v")
        if not w_clean or len(w_clean) < 2:
            return ""
        if org_lower and len(org_lower) > 3 and org_lower in w_clean:
            return ""
        if w_clean in INVALID_WORDS:
            return ""
        formatted_words.append(w_clean.capitalize())
        
    if len(formatted_words) < 2:
        return ""

    return " ".join(formatted_words)


def is_valid_human_name(name: str, org_name: str = "") -> bool:
    return bool(clean_human_name(name, org_name))


def enumerate_linkedin_profiles(domain: str, org_name: Optional[str] = None, timeout: int = 15) -> List[Dict[str, Any]]:
    """
    Submodule 7: Dedicated Multi-Engine Public LinkedIn OSINT Enumerator.
    Harvests verified human employee profiles, leadership, and roles from public LinkedIn index.
    """
    root_domain = extract_root_domain(domain)
    domain_stem = root_domain.split(".")[0].capitalize()
    
    clean_org = domain_stem
    if org_name and org_name.lower().strip() not in ["cloudflarenet", "unknown", "none", "amazon", "google", "microsoft"]:
        clean_org = org_name.strip()

    logger.info(f"[people.linkedin] Harvesting human LinkedIn profiles for '{domain}' (Org: '{clean_org}')")

    results: List[Dict[str, Any]] = []
    seen_urls: Set[str] = set()
    seen_names: Set[str] = set()

    # Dork queries specifically crafted for human employee profiles
    queries = [
        f'"{clean_org}" site:linkedin.com/in/',
        f'"{clean_org}" linkedin.com/in',
        f'"{clean_org}" "at {clean_org}" linkedin.com',
        f'"{clean_org}" "Product" OR "Design" OR "UI" OR "UX" linkedin.com/in',
        f'"{clean_org}" "Founder" OR "CEO" OR "CTO" OR "Lead" OR "Head" linkedin.com/in',
        f'"{clean_org}" "Developer" OR "Engineer" OR "Manager" linkedin.com/in',
        f'"{clean_org}" "Writer" OR "Researcher" OR "Specialist" OR "Operations" linkedin.com/in',
        f'"{clean_org}" "Teacher" OR "Student" OR "Intern" OR "Associate" linkedin.com/in',
        f'"{clean_org}" linkedin.com/company',
    ]

    # 1. High-Yield LinkedIn Search (Budgeted 2 queries: Leadership & Technical Staff)
    high_yield_linkedin_queries = [
        f'site:linkedin.com/in/ "{clean_org}" ("CEO" OR "Founder" OR "CTO" OR "VP" OR "Director" OR "Head of" OR "Partner")',
        f'site:linkedin.com/in/ "{clean_org}" ("Engineer" OR "Security" OR "DevOps" OR "Lead" OR "Manager" OR "Architect")',
    ]
    try:
        from core.google_search import query_google_search
        for l_query in high_yield_linkedin_queries:
            g_items = query_google_search(l_query, num=10, timeout=10)
            for item in g_items:
                href = item.get("link", "").strip()
                raw_title = item.get("title", "").strip()
                if not href or href in seen_urls or "linkedin.com/in/" not in href.lower():
                    continue
                seen_urls.add(href)
            
            clean_title = raw_title
            for pat in LINKEDIN_CLEAN_PATTERNS:
                clean_title = re.sub(pat, "", clean_title, flags=re.IGNORECASE).strip()
                
            name = ""
            role = f"Staff at {clean_org}"
            if "-" in clean_title or "–" in clean_title or "|" in clean_title:
                parts = re.split(r"[-–|]", clean_title)
                name_cand = clean_human_name(parts[0], clean_org)
                if name_cand:
                    name = name_cand
                    role = parts[1].strip() if len(parts) > 1 else role
            else:
                name_cand = clean_human_name(clean_title, clean_org)
                if name_cand:
                    name = name_cand
                    
            if not name:
                slug_match = re.search(r"linkedin\.com/in/([a-zA-Z0-9-]+)", href)
                if slug_match:
                    slug_parts = [p.capitalize() for p in slug_match.group(1).split("-") if p.isalpha()]
                    if 2 <= len(slug_parts) <= 3:
                        candidate_from_slug = clean_human_name(" ".join(slug_parts), clean_org)
                        if candidate_from_slug:
                            name = candidate_from_slug
                            
            if name and name.lower() not in seen_names:
                seen_names.add(name.lower())
                results.append({
                    "name": name,
                    "email": "",
                    "title": role if role else f"Professional at {clean_org}",
                    "profile_url": href,
                    "platform": "LinkedIn",
                    "confidence": 98,
                    "is_human": True,
                    "source": "google_search:linkedin",
                })
    except Exception as e:
        logger.debug(f"Google LinkedIn search failed: {e}")

    # 2. Multi-Engine Scrapers (DDG Lite queries)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Origin": "https://lite.duckduckgo.com",
        "Referer": "https://lite.duckduckgo.com/",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    with httpx.Client(timeout=timeout, headers=headers, follow_redirects=True) as client:
        for q in queries:
            try:
                resp = client.post("https://lite.duckduckgo.com/lite/", data={"q": q})
                if resp.status_code == 200:
                    _parse_ddg_linkedin_html(
                        resp.text,
                        clean_org=clean_org,
                        root_domain=root_domain,
                        results=results,
                        seen_urls=seen_urls,
                        seen_names=seen_names,
                    )
            except Exception as e:
                logger.debug(f"LinkedIn query error for '{q}': {e}")

    logger.info(f"[people.linkedin] Discovered {len(results)} verified LinkedIn human profiles and company directory records")
    return results


def _parse_ddg_linkedin_html(
    html: str,
    clean_org: str,
    root_domain: str,
    results: List[Dict[str, Any]],
    seen_urls: Set[str],
    seen_names: Set[str],
):
    """Parses search response HTML specifically for real human employee profiles."""
    soup = BeautifulSoup(html, "html.parser")

    for a in soup.find_all("a"):
        href = a.get("href", "").strip()
        if not href or href.startswith("/") or "duckduckgo.com" in href:
            continue

        raw_title = a.get_text().strip()
        if not raw_title or "linkedin.com" not in href.lower() or href in seen_urls:
            continue

        seen_urls.add(href)
        href_lower = href.lower()

        # Clean title text
        clean_title = raw_title
        for pat in LINKEDIN_CLEAN_PATTERNS:
            clean_title = re.sub(pat, "", clean_title, flags=re.IGNORECASE).strip()

        # 1. Individual Employee Profile (/in/) - TOP PRIORITY HUMAN TARGET
        if "/in/" in href_lower:
            name = ""
            role = f"Staff at {clean_org}"

            # Extract role
            if "-" in clean_title or "–" in clean_title or "|" in clean_title:
                parts = re.split(r"[-–|]", clean_title)
                name_cand = clean_human_name(parts[0], clean_org)
                if name_cand:
                    name = name_cand
                    role = parts[1].strip() if len(parts) > 1 else role
                elif len(parts) > 1:
                    name_cand2 = clean_human_name(parts[1], clean_org)
                    if name_cand2:
                        name = name_cand2
                        role = parts[0].strip()
            else:
                name_cand = clean_human_name(clean_title, clean_org)
                if name_cand:
                    name = name_cand

            # Fallback: extract from LinkedIn profile slug
            if not name:
                slug_match = re.search(r"linkedin\.com/in/([a-zA-Z0-9-]+)", href)
                if slug_match:
                    slug_parts = [p.capitalize() for p in slug_match.group(1).split("-") if p.isalpha()]
                    if 2 <= len(slug_parts) <= 3:
                        candidate_from_slug = clean_human_name(" ".join(slug_parts), clean_org)
                        if candidate_from_slug:
                            name = candidate_from_slug

            if name and name.lower() not in seen_names:
                seen_names.add(name.lower())
                results.append({
                    "name": name,
                    "email": "",
                    "title": role if role else f"Professional at {clean_org}",
                    "profile_url": href,
                    "platform": "LinkedIn",
                    "confidence": 95,
                    "is_human": True,
                    "source": "linkedin:profile",
                })

        # 2. Company Directory Page (/company/)
        elif "/company/" in href_lower and not any(p in href_lower for p in ["/jobs", "/posts", "/life"]):
            results.append({
                "name": f"{clean_org}, Inc.",
                "email": "",
                "title": "Official Corporate LinkedIn Directory",
                "profile_url": href,
                "platform": "LinkedIn",
                "confidence": 95,
                "is_human": False,
                "source": "linkedin:company",
            })
