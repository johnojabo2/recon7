import logging
import re
from typing import List, Dict, Any, Set, Optional, Tuple
import httpx
from bs4 import BeautifulSoup
from core.scope import extract_root_domain
from people.linkedin_enum import is_valid_human_name

logger = logging.getLogger(__name__)

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

CDN_ISP_NAMES = {
    "cloudflarenet", "cloudflare", "amazon", "amazon-aes", "amazon-02",
    "google", "google-cloud", "microsoft", "microsoft-corp", "digitalocean",
    "linode", "hetzner", "ovh", "akamai", "fastly", "unknown", "none"
}


def search_dork_snippets(domain: str, org_name: Optional[str] = None, seed_ceo: Optional[str] = None, timeout: int = 15) -> List[Dict[str, Any]]:
    """
    Submodule 5: Multi-Platform Public OSINT Search Engine Dorker.
    Harvests verified public employee profiles, roles, and profile URLs across:
      - GitHub (contributors, commit authors, members)
      - Twitter/X, Instagram, Facebook primary handles
      - Direct corporate email mentions & PDF doc metadata
      - Targeted Executive / Worker Pivot queries
    """
    root_domain = extract_root_domain(domain)
    domain_stem = root_domain.split(".")[0].capitalize()
    
    clean_org = domain_stem
    if org_name and org_name.lower().strip() not in CDN_ISP_NAMES:
        clean_org = org_name.strip()

    logger.info(f"[people.search_dork] Executing multi-platform OSINT dorks for '{domain}' (Org: {clean_org})")
    
    results: List[Dict[str, Any]] = []
    seen_emails: Set[str] = set()
    seen_profiles: Set[str] = set()
    seen_names: Set[str] = set()

    queries = [
        # 1. Leadership, Founders & Executives
        f'"{clean_org}" ("CEO" OR "CTO" OR "CFO" OR "Founder" OR "Director" OR "Head of" OR "President" OR "Manager")',
        
        # 2. Direct Corporate Emails, Phone Numbers & Contact Leaks
        f'"{clean_org}" ("@{root_domain}" OR "email" OR "contact us" OR "phone" OR "tel")',
        f'"@{root_domain}"',
        
        # 3. Public Document Leaks & Personnel Rosters
        f'"{clean_org}" ("@{root_domain}" OR "confidential" OR "internal" OR "staff roster") filetype:pdf OR filetype:docx',
        
        # 4. Verified Professional Profiles
        f'site:linkedin.com/in/ "{clean_org}"',
        f'site:github.com "{root_domain}" OR "{clean_org}"',
    ]

    # If seed CEO / Executive name was provided, prioritize precision pivot dorks
    if seed_ceo and len(seed_ceo.strip()) > 2:
        c_name = seed_ceo.strip()
        queries.insert(0, f'"{c_name}" site:linkedin.com/in/')
        queries.insert(1, f'"{clean_org}" "{c_name}"')
        queries.insert(2, f'"{c_name}" ("@{root_domain}" OR "email" OR "contact")')
        queries.insert(3, f'"{c_name}" filetype:pdf OR filetype:docx')

    # 1. Budgeted High-Yield Email Footprint Dork (1 query)
    email_query = f'"{clean_org}" ("@{root_domain}" OR "email" OR "contact") -site:{root_domain}'
    try:
        from core.google_search import query_google_search
        g_items = query_google_search(email_query, num=10, timeout=timeout)
        for item in g_items:
                snippet = item.get("snippet", "").strip()
                title = item.get("title", "").strip()
                link = item.get("link", "").strip()
                full_text = f"{title} {snippet}"

                # 1a. Extract all emails from title & snippet
                for m in EMAIL_REGEX.findall(full_text):
                    m_clean = m.lower().strip().rstrip(".")
                    if not any(m_clean.endswith(ext) for ext in [".png", ".jpg", ".svg", ".css", ".js"]):
                        if m_clean not in seen_emails:
                            seen_emails.add(m_clean)
                            results.append({
                                "name": "",
                                "email": m_clean,
                                "title": f"Contact Mention ({title[:40]})",
                                "profile_url": link,
                                "platform": "Search Engine Snippet",
                                "confidence": 95 if root_domain in m_clean else 85,
                                "is_human": False,
                                "source": "google_search:snippet",
                            })

                # 1b. Parse LinkedIn or Executive Profiles from Title
                # Format e.g.: "John Doe - Chief Technology Officer - Acme Corp | LinkedIn"
                name_cand, role_cand = _extract_name_and_role_from_text(title, clean_org)
                if not name_cand:
                    name_cand, role_cand = _extract_name_and_role_from_text(snippet, clean_org)

                if name_cand and name_cand not in seen_names:
                    seen_names.add(name_cand)
                    platform = "LinkedIn" if "linkedin.com" in link else "Public Profile"
                    results.append({
                        "name": name_cand,
                        "email": "",
                        "title": role_cand or "Staff / Leadership",
                        "profile_url": link,
                        "platform": platform,
                        "confidence": 90,
                        "is_human": True,
                        "source": "google_search:profile",
                    })
    except Exception as e:
        logger.debug(f"[people.search_dork] Google dork query error: {e}")

    # 2. Multi-Engine Scrapers (DDG Lite Fallback)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Origin": "https://lite.duckduckgo.com",
        "Referer": "https://lite.duckduckgo.com/",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    with httpx.Client(timeout=timeout, headers=headers, follow_redirects=True) as client:
        for q in queries[:3]:  # Run top 3 on DDG Lite to remain fast
            try:
                resp = client.post("https://lite.duckduckgo.com/lite/", data={"q": q})
                if resp.status_code == 200:
                    _parse_ddg_lite_html(
                        resp.text,
                        domain=domain,
                        root_domain=root_domain,
                        clean_org=clean_org,
                        results=results,
                        seen_emails=seen_emails,
                        seen_profiles=seen_profiles,
                        seen_names=seen_names,
                    )
            except Exception as e:
                logger.debug(f"DDG Lite query error for '{q}': {e}")

    logger.info(f"[people.search_dork] Discovered {len(results)} candidate people, emails, and profile records from search dorks")
    return results



def _parse_ddg_lite_html(
    html: str,
    domain: str,
    root_domain: str,
    clean_org: str,
    results: List[Dict[str, Any]],
    seen_emails: Set[str],
    seen_profiles: Set[str],
    seen_names: Set[str],
):
    """Parses DDG Lite search response HTML, filtering out noise, posts, and reels."""
    soup = BeautifulSoup(html, "html.parser")
    
    # 1. Regex check for emails in all snippets
    for snip in soup.find_all("td", class_="result-snippet"):
        text = snip.get_text()
        for m in EMAIL_REGEX.findall(text):
            m_clean = m.lower().strip().rstrip(".")
            if (root_domain in m_clean or domain in m_clean) and m_clean not in seen_emails:
                if not any(m_clean.endswith(ext) for ext in [".png", ".jpg", ".svg", ".css", ".js"]):
                    seen_emails.add(m_clean)
                    results.append({
                        "name": "",
                        "email": m_clean,
                        "title": "Corporate Email Leak",
                        "profile_url": "",
                        "platform": "Email Leak",
                        "confidence": 90,
                        "is_human": False,
                        "source": "search_dork:email_leak",
                    })

    # 2. Parse result links
    for a in soup.find_all("a"):
        href = a.get("href", "").strip()
        if not href or href.startswith("/") or "duckduckgo.com" in href:
            continue

        raw_title = a.get_text().strip()
        if not raw_title or href in seen_profiles:
            continue

        href_lower = href.lower()

        # Filter out noisy subpaths (posts, reels, videos, status tweets, hashtags, packages)
        if any(noise in href_lower for noise in [
            "/reel/", "/posts/", "/videos/", "/status/", "/hashtag/",
            "/packages", "/blob/", "/commit/", "/tree/", "/issues/",
            "/pull/", "/share", "/intent/"
        ]):
            continue

        seen_profiles.add(href)

        # A. GitHub Profiles / Contributors
        if "github.com/" in href_lower:
            name = ""
            match = re.search(r"\((.*?)\)", raw_title)
            if match and is_valid_human_name(match.group(1).strip(), clean_org):
                name = match.group(1).strip()
            elif is_valid_human_name(raw_title, clean_org):
                name = raw_title

            is_human = bool(name)
            results.append({
                "name": name,
                "email": "",
                "title": "GitHub Contributor" if is_human else "GitHub Organization Repository",
                "profile_url": href,
                "platform": "GitHub",
                "confidence": 85 if is_human else 70,
                "is_human": is_human,
                "source": "search_dork:github",
            })

        # B. Twitter / X Profiles
        elif "twitter.com/" in href_lower or "x.com/" in href_lower:
            name = raw_title.split("(@")[0].strip() if "(@" in raw_title else ""
            if not is_valid_human_name(name, clean_org):
                name = ""
            results.append({
                "name": name,
                "email": "",
                "title": "Official Public Handle",
                "profile_url": href,
                "platform": "X/Twitter",
                "confidence": 80,
                "is_human": bool(name),
                "source": "search_dork:twitter",
            })

        # C. Instagram & Facebook Pages
        elif "instagram.com/" in href_lower or "facebook.com/" in href_lower:
            plat = "Instagram" if "instagram" in href_lower else "Facebook"
            results.append({
                "name": "",
                "email": "",
                "title": "Official Public Handle",
                "profile_url": href,
                "platform": plat,
                "confidence": 80,
                "is_human": False,
                "source": f"search_dork:{plat.lower()}",
            })


def _extract_name_and_role_from_text(text: str, clean_org: str) -> Tuple[str, str]:
    """
    Extracts a candidate human name and professional role from search result text/title.
    e.g. "John Doe - Chief Technology Officer - Acme Corp | LinkedIn"
    e.g. "Devops Engineer - John Doe | LinkedIn"
    e.g. "Jane Smith (Founder & CEO) - Acme Corp"
    """
    if not text:
        return "", ""

    # Strip common platform tails
    cleaned = re.sub(
        r"\s*[-–—|]\s*(?:LinkedIn|GitHub|Twitter|X|Facebook|Instagram|YouTube).*$",
        "",
        text,
        flags=re.IGNORECASE,
    ).strip()

    # Check "Name - Role" or "Role - Name" pattern
    parts = [p.strip() for p in re.split(r"\s*[-–—|:]\s*", cleaned) if p.strip()]
    if len(parts) >= 2:
        cand0 = parts[0]
        cand1 = parts[1]
        valid0 = is_valid_human_name(cand0, clean_org)
        valid1 = is_valid_human_name(cand1, clean_org)

        if valid0 and not valid1:
            cand_role = parts[2] if cand1.lower() == clean_org.lower() and len(parts) > 2 else cand1
            return cand0, cand_role
        elif valid1 and not valid0:
            return cand1, cand0
        elif valid0 and valid1:
            return cand0, cand1

    # Check "Name (Role)" pattern
    paren_match = re.search(
        r"^([A-Z][a-zA-Z'\-]+(?:\s+[A-Z][a-zA-Z'\-]+){1,2})\s*\((.*?)\)",
        cleaned,
    )
    if paren_match:
        cand_name = paren_match.group(1).strip()
        cand_role = paren_match.group(2).strip()
        if is_valid_human_name(cand_name, clean_org):
            return cand_name, cand_role

    return "", ""

