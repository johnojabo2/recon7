import html
import logging
import re
import urllib.parse
from typing import List, Dict, Any, Set, Optional, Tuple
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

# Comprehensive Job Role, Corporate Title & Department Keywords (Never a human's First/Last Name)
JOB_ROLE_WORDS = {
    # Engineering, IT, Software & Tech
    "engineer", "engineering", "developer", "devops", "architect", "programmer", "coder",
    "admin", "administrator", "sysadmin", "specialist", "technician", "lead", "leader",
    "qa", "tester", "sre", "consultant", "analyst", "scientist", "researcher", "security",
    "infrastructure", "network", "cybersecurity", "frontend", "backend", "fullstack",
    "stack", "cloud", "data", "database", "ai", "ml", "hardware", "software",
    
    # Executive & Corporate Leadership
    "ceo", "cto", "cfo", "coo", "ciso", "cio", "cpo", "cmo", "cro", "eo", "president",
    "vice", "vp", "director", "manager", "management", "head", "founder", "cofounder",
    "co-founder", "chief", "executive", "officer", "principal", "partner", "investor",
    "board", "advisor", "advisory", "fellow", "trustee", "owner", "chair", "chairman",
    "chairperson",
    
    # Product, Design, Media & Content
    "product", "designer", "design", "ui", "ux", "media", "content", "creator", "editor",
    "writer", "copywriter", "author", "journalist", "reporter", "host", "producer",
    "animator", "artist", "illustrator", "creative", "brand", "branding",
    
    # Business, Sales, Marketing, HR, People & Operations
    "sales", "marketing", "operations", "recruiter", "talent", "recruiting", "people",
    "culture", "hr", "human", "resources", "finance", "accounting", "accountant",
    "auditor", "legal", "counsel", "attorney", "lawyer", "advocate", "strategist",
    "strategy", "coordinator", "supervisor", "associate", "intern", "trainee",
    "representative", "rep", "agent", "assistant", "clerk", "support", "success",
    "customer", "client", "relations", "communications", "public", "pr", "growth",
    "revenue", "procurement", "logistics", "supply", "chain",
    
    # Academic, Educational & General
    "professor", "prof", "lecturer", "instructor", "teacher", "student", "alumni", "graduate",
    "member", "staff", "personnel", "team", "scholar",
}

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
    "blog", "events", "official",
    # Corporate & Institutional Suffixes (blocks "NotJustEvent, Inc.", "Acme LLC")
    "inc", "llc", "ltd", "corp", "corporation", "co", "company",
    "technologies", "tech", "group", "studios", "holdings", "solutions",
    "enterprises", "hq", "international", "global",
    # Institutional / Academic Organization words
    "university", "institute", "center", "centre", "faculty",
    "department", "college", "school", "portal", "foundation", "association",
}


def clean_human_name(name: str, org_name: str = "") -> str:
    """Extracts and formats a clean human First & Last name; returns empty string if not a human or is a role."""
    if not name or len(name.strip()) < 3:
        return ""
    
    # Unescape HTML entities (e.g. &amp; -> &)
    clean = html.unescape(name)
    clean = re.sub(r"\(.*?\)", "", clean)
    clean = re.sub(r"\s*\|\s*.*$", "", clean)
    clean = re.sub(r"\s*[-–—]\s*.*$", "", clean)
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
    clean_no_space = "".join(re.sub(r"[^a-zA-Z]", "", w).lower() for w in words)
    
    # Reject if candidate is literally just the organization name itself (e.g. "NotJustEvent" or "Ojabo")
    if org_lower and len(org_lower) >= 3 and clean_no_space == org_lower:
        return ""

    formatted_words = []
    for w in words:
        w_clean = re.sub(r"[^a-zA-Z]", "", w).lower()
        # Reject empty or single-letter names (e.g. "FULafia V" -> last name "v")
        if not w_clean or len(w_clean) < 2:
            return ""
        if w_clean in INVALID_WORDS or w_clean in JOB_ROLE_WORDS:
            return ""
        formatted_words.append(w_clean.capitalize())
        
    if len(formatted_words) < 2:
        return ""

    return " ".join(formatted_words)


def is_valid_human_name(name: str, org_name: str = "") -> bool:
    return bool(clean_human_name(name, org_name))


def _parse_linkedin_title_and_slug(raw_title: str, href: str, clean_org: str) -> Tuple[str, str]:
    """
    Accurately extracts genuine Human Name and Role/Title from a LinkedIn search result.
    Resolves reversed formats (e.g. 'Devops Engineer - John Ojabo | LinkedIn' vs 'John Ojabo - Devops Engineer').
    Uses LinkedIn profile URL slug as authoritative ground-truth disambiguation anchor.
    """
    title = html.unescape(raw_title)
    for pat in LINKEDIN_CLEAN_PATTERNS:
        title = re.sub(pat, "", title, flags=re.IGNORECASE).strip()

    # 1. Extract ground-truth slug candidate name (e.g. /in/john-ojabo-12345/ -> "John Ojabo")
    slug_name = ""
    slug_match = re.search(r"linkedin\.com/in/([a-zA-Z0-9-]+)", href, re.IGNORECASE)
    if slug_match:
        raw_slug = slug_match.group(1)
        # Filter out random trailing hex, numbers or noise tokens
        slug_tokens = [t.capitalize() for t in raw_slug.split("-") if t.isalpha() and len(t) >= 2]
        if 2 <= len(slug_tokens) <= 3:
            cand_slug_name = " ".join(slug_tokens)
            if is_valid_human_name(cand_slug_name, clean_org):
                slug_name = cand_slug_name

    parts = [p.strip() for p in re.split(r"\s*[-–—|:]\s*", title) if p.strip()]

    if len(parts) >= 2:
        p0 = parts[0]
        p1 = parts[1]

        # If slug name matches part 1, then part 0 is role and part 1 is name!
        if slug_name:
            if slug_name.lower() in p1.lower() or p1.lower() in slug_name.lower():
                return slug_name, p0
            elif slug_name.lower() in p0.lower() or p0.lower() in slug_name.lower():
                return slug_name, p1

        # Check which part is a valid human name vs job role
        name_cand_0 = clean_human_name(p0, clean_org)
        name_cand_1 = clean_human_name(p1, clean_org)

        if name_cand_0 and not name_cand_1:
            return name_cand_0, p1
        elif name_cand_1 and not name_cand_0:
            return name_cand_1, p0
        elif name_cand_0 and name_cand_1:
            p0_has_role = any(w.lower() in JOB_ROLE_WORDS for w in p0.split())
            p1_has_role = any(w.lower() in JOB_ROLE_WORDS for w in p1.split())
            if p0_has_role and not p1_has_role:
                return name_cand_1, p0
            elif p1_has_role and not p0_has_role:
                return name_cand_0, p1
            return name_cand_0, p1

    # Fallback with single part
    if parts:
        single_name = clean_human_name(parts[0], clean_org)
        if single_name:
            return single_name, f"Staff at {clean_org}"

    # Fallback to slug if title couldn't be parsed
    if slug_name:
        role = parts[0] if parts else f"Staff at {clean_org}"
        return slug_name, role

    return "", ""


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
            
                name, role = _parse_linkedin_title_and_slug(raw_title, href, clean_org)
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

        # 1. Individual Employee Profile (/in/) - TOP PRIORITY HUMAN TARGET
        if "/in/" in href_lower:
            name, role = _parse_linkedin_title_and_slug(raw_title, href, clean_org)

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
