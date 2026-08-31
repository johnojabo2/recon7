import json
import logging
import re
from collections import deque
from typing import List, Dict, Any, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse
import httpx
from bs4 import BeautifulSoup
from core.scope import extract_root_domain
from people.linkedin_enum import is_valid_human_name

logger = logging.getLogger(__name__)

COMMON_TEAM_PATHS = [
    "/about",
    "/about-us",
    "/team",
    "/our-team",
    "/leadership",
    "/contact",
    "/contact-us",
    "/people",
    "/management",
    "/board",
    "/directory",
    "/faculty",
    "/staff",
]

HIGH_VALUE_KEYWORDS = [
    "team", "about", "contact", "people", "leadership",
    "management", "board", "directory", "faculty", "staff",
    "bio", "author", "executives", "founders", "roster",
    "career", "jobs"
]

NOISE_SUBPATHS = [
    "/reel/", "/posts/", "/videos/", "/status/", "/hashtag/",
    "/share", "/intent/", "/cart/", "/checkout/", "/login",
    "/signup", "/register", "/wp-json/", "/feed/", "/tag/",
    "/category/", "/page/"
]

MEDIA_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".css", ".js", ".map", ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z", ".mp3", ".mp4",
    ".avi", ".mov", ".wmv", ".exe", ".dmg", ".iso"
)

EMAIL_REGEX_PATTERN = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
PHONE_REGEX = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}")

PLATFORM_DOMAINS = {
    "linkedin.com": "LinkedIn",
    "github.com": "GitHub",
    "twitter.com": "X/Twitter",
    "x.com": "X/Twitter",
    "instagram.com": "Instagram",
    "facebook.com": "Facebook",
}


def decode_cloudflare_email(cf_hex: str) -> str:
    """Decodes Cloudflare's XOR-encrypted email strings."""
    if not cf_hex or len(cf_hex) < 4:
        return ""
    try:
        key = int(cf_hex[:2], 16)
        email = "".join([
            chr(int(cf_hex[i:i + 2], 16) ^ key)
            for i in range(2, len(cf_hex), 2)
        ])
        return email.strip().lower()
    except Exception:
        return ""


def extract_json_ld_entities(soup: BeautifulSoup, page_url: str) -> List[Dict[str, Any]]:
    """Parses Schema.org JSON-LD for Person & Organization contact records."""
    entities: List[Dict[str, Any]] = []
    for script in soup.find_all("script", type="application/ld+json"):
        if not script.string:
            continue
        try:
            data = json.loads(script.string)
            items = data if isinstance(data, list) else [data]
            if isinstance(data, dict) and "@graph" in data and isinstance(data["@graph"], list):
                items.extend(data["@graph"])

            for item in items:
                if not isinstance(item, dict):
                    continue
                item_type = item.get("@type")
                if item_type in ["Person", "Employee"]:
                    name = (item.get("name") or "").strip()
                    email = (item.get("email") or "").strip().lower()
                    phone = (item.get("telephone") or "").strip()
                    title = (item.get("jobTitle") or item.get("roleName") or "Team Member").strip()
                    url = (item.get("url") or page_url).strip()
                    if name or email or phone:
                        entities.append({
                            "name": name,
                            "email": email,
                            "phone": phone,
                            "title": title,
                            "profile_url": url,
                            "platform": "Corporate Website (JSON-LD)",
                            "confidence": 96,
                            "is_human": bool(name),
                            "source": "site_crawler:json_ld",
                        })
                elif item_type in ["Organization", "Corporation"]:
                    email = (item.get("email") or "").strip().lower()
                    phone = (item.get("telephone") or "").strip()
                    if email:
                        entities.append({
                            "name": "",
                            "email": email,
                            "phone": "",
                            "title": "Corporate Contact",
                            "profile_url": page_url,
                            "platform": "Corporate Website (JSON-LD)",
                            "confidence": 95,
                            "is_human": False,
                            "source": "site_crawler:json_ld_org",
                        })
                    if phone:
                        entities.append({
                            "name": "",
                            "email": "",
                            "phone": phone,
                            "title": "Corporate Telephone",
                            "profile_url": page_url,
                            "platform": "Corporate Website (JSON-LD)",
                            "confidence": 95,
                            "is_human": False,
                            "source": "site_crawler:json_ld_org_phone",
                        })
        except Exception:
            continue
    return entities


def probe_sitemap_and_robots(client: httpx.Client, base_url: str, root_domain: str) -> List[str]:
    """Discovers high-priority in-scope URLs from sitemap.xml and robots.txt."""
    discovered_urls: List[str] = []
    
    # 1. Sitemap.xml
    try:
        sitemap_url = urljoin(base_url, "/sitemap.xml")
        resp = client.get(sitemap_url, timeout=3.0)
        if resp.status_code == 200 and ("<urlset" in resp.text.lower() or "<sitemapindex" in resp.text.lower()):
            soup = BeautifulSoup(resp.text, "xml") if "xml" in resp.headers.get("content-type", "") else BeautifulSoup(resp.text, "html.parser")
            for loc in soup.find_all("loc"):
                u = loc.get_text().strip()
                if u and extract_root_domain(urlparse(u).netloc) == root_domain:
                    if any(kw in u.lower() for kw in HIGH_VALUE_KEYWORDS):
                        discovered_urls.append(u)
    except Exception:
        pass

    # 2. Robots.txt
    try:
        robots_url = urljoin(base_url, "/robots.txt")
        resp = client.get(robots_url, timeout=3.0)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        path = parts[1].strip()
                        if any(kw in path.lower() for kw in HIGH_VALUE_KEYWORDS):
                            discovered_urls.append(urljoin(base_url, path))
    except Exception:
        pass

    return discovered_urls


def crawl_site_for_people(
    domain: str,
    subdomains: Optional[List[str]] = None,
    max_pages: int = 40,
    max_depth: int = 2,
    timeout: int = 15,
) -> List[Dict[str, Any]]:
    """
    Submodule 2: In-Scope Breadth-First Deep Crawler for People & Contact OSINT.
    Extracts employee names, verified emails (with Cloudflare de-obfuscation),
    telephone numbers, JSON-LD Schema records, and verified social profile URLs.
    Strictly constrained to the in-scope root domain.
    """
    root_domain = extract_root_domain(domain)
    org_guess = root_domain.split(".")[0].capitalize()

    logger.info(f"[people.site_crawler] Starting deep in-scope crawl for '{domain}' (Root: '{root_domain}')")
    results: List[Dict[str, Any]] = []
    seen_emails: Set[str] = set()
    seen_phones: Set[str] = set()
    seen_profiles: Set[str] = set()
    seen_names: Set[str] = set()
    visited_urls: Set[str] = set()

    # 1. Build initial seed list (Apex, WWW, and relevant subdomains)
    seed_hosts = [domain]
    if not domain.startswith("www."):
        seed_hosts.append(f"www.{domain}")

    if subdomains:
        # Prioritize subdomains with high-value keywords
        for sub in subdomains:
            if not sub or sub in seed_hosts:
                continue
            sub_clean = sub.strip().lower()
            if extract_root_domain(sub_clean) != root_domain:
                continue
            if any(kw in sub_clean for kw in ["career", "team", "about", "staff", "people", "blog", "help", "support", "contact"]):
                seed_hosts.insert(0, sub_clean)
            elif len(seed_hosts) < 6:
                seed_hosts.append(sub_clean)

    queue: deque = deque()

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) R7-DeepCrawler/2.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    with httpx.Client(
        timeout=timeout,
        verify=False,
        follow_redirects=True,
        headers=headers,
    ) as client:
        # Resolve active base URLs for primary seeds
        for host in seed_hosts[:4]:
            base_url = None
            for scheme in ["https://", "http://"]:
                cand_url = f"{scheme}{host}"
                try:
                    r = client.get(cand_url, timeout=3.0)
                    if r.status_code < 400:
                        base_url = str(r.url).rstrip("/")
                        break
                except Exception:
                    continue

            if not base_url:
                continue

            # Queue initial base URL
            queue.append((base_url, 0))

            # Queue team paths for base host
            for path in COMMON_TEAM_PATHS:
                queue.append((f"{base_url}{path}", 1))

            # Pull sitemap & robots links
            sitemap_links = probe_sitemap_and_robots(client, base_url, root_domain)
            for link in sitemap_links:
                queue.append((link, 1))

        # 2. BFS Crawl Loop
        while queue and len(visited_urls) < max_pages:
            target_url, depth = queue.popleft()
            clean_url = target_url.split("#")[0].rstrip("/")
            if clean_url in visited_urls or depth > max_depth:
                continue
            visited_urls.add(clean_url)

            try:
                # Stream check content-type & size
                with client.stream("GET", clean_url) as resp:
                    if resp.status_code != 200:
                        continue
                    ct = resp.headers.get("content-type", "").lower()
                    if "text/html" not in ct and "application/xhtml" not in ct:
                        continue
                    cl = resp.headers.get("content-length")
                    if cl and int(cl) > 1_500_000:
                        continue
                    html_content = resp.read().decode("utf-8", errors="ignore")

                soup = BeautifulSoup(html_content, "html.parser")

                # A. Cloudflare Email Protection De-obfuscation
                # Check data-cfemail on tags
                for cf_elem in soup.find_all(attrs={"data-cfemail": True}):
                    cf_hex = cf_elem["data-cfemail"].strip()
                    dec_email = decode_cloudflare_email(cf_hex)
                    if dec_email and dec_email not in seen_emails:
                        seen_emails.add(dec_email)
                        results.append({
                            "name": "",
                            "email": dec_email,
                            "phone": "",
                            "title": "Cloudflare Protected Contact",
                            "profile_url": clean_url,
                            "platform": "Corporate Website",
                            "confidence": 98,
                            "is_human": False,
                            "source": f"site_crawler:cloudflare:{urlparse(clean_url).path or '/'}",
                        })

                # Check /cdn-cgi/l/email-protection# links
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"].strip()
                    if "/cdn-cgi/l/email-protection#" in href:
                        cf_hex = href.split("#")[-1].strip()
                        dec_email = decode_cloudflare_email(cf_hex)
                        if dec_email and dec_email not in seen_emails:
                            seen_emails.add(dec_email)
                            results.append({
                                "name": a_tag.get_text().strip() if is_valid_human_name(a_tag.get_text().strip(), org_guess) else "",
                                "email": dec_email,
                                "phone": "",
                                "title": "Direct Contact / Inbox",
                                "profile_url": clean_url,
                                "platform": "Corporate Website",
                                "confidence": 98,
                                "is_human": bool(is_valid_human_name(a_tag.get_text().strip(), org_guess)),
                                "source": f"site_crawler:cloudflare:{urlparse(clean_url).path or '/'}",
                            })

                # B. Schema.org JSON-LD Extraction
                json_ld_entities = extract_json_ld_entities(soup, clean_url)
                for ent in json_ld_entities:
                    em = ent.get("email")
                    ph = ent.get("phone")
                    nm = ent.get("name")
                    if em and em not in seen_emails:
                        seen_emails.add(em)
                        results.append(ent)
                    elif ph and ph not in seen_phones:
                        seen_phones.add(ph)
                        results.append(ent)
                    elif nm and nm.lower() not in seen_names:
                        seen_names.add(nm.lower())
                        results.append(ent)

                # C. Direct mailto: and tel: links extraction
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"].strip()
                    if href.lower().startswith("mailto:"):
                        raw_email = href.split(":", 1)[1].split("?")[0].strip().lower().rstrip(".")
                        if raw_email and raw_email not in seen_emails:
                            seen_emails.add(raw_email)
                            link_text = a_tag.get_text().strip()
                            results.append({
                                "name": link_text if is_valid_human_name(link_text, org_guess) else "",
                                "email": raw_email,
                                "phone": "",
                                "title": "Direct Contact / Inbox",
                                "profile_url": clean_url,
                                "platform": "Corporate Website",
                                "confidence": 98,
                                "is_human": bool(is_valid_human_name(link_text, org_guess)),
                                "source": f"site_crawler:mailto:{urlparse(clean_url).path or '/'}",
                            })
                    elif href.lower().startswith("tel:"):
                        raw_phone = href.split(":", 1)[1].split("?")[0].strip()
                        if raw_phone and raw_phone not in seen_phones:
                            seen_phones.add(raw_phone)
                            results.append({
                                "name": "",
                                "email": "",
                                "phone": raw_phone,
                                "title": "Corporate Telephone",
                                "profile_url": clean_url,
                                "platform": "Corporate Website",
                                "confidence": 95,
                                "is_human": False,
                                "source": f"site_crawler:tel:{urlparse(clean_url).path or '/'}",
                            })

                # D. Regex search for emails and phone numbers across page text
                emails = re.findall(EMAIL_REGEX_PATTERN, html_content)
                for email in emails:
                    email_clean = email.strip().lower().rstrip(".")
                    if (root_domain in email_clean or "contact" in email_clean or "support" in email_clean or "info" in email_clean) and email_clean not in seen_emails:
                        if not any(email_clean.endswith(ext) for ext in MEDIA_EXTENSIONS):
                            seen_emails.add(email_clean)
                            results.append({
                                "name": "",
                                "email": email_clean,
                                "phone": "",
                                "title": "Corporate Contact",
                                "profile_url": clean_url,
                                "platform": "Website",
                                "confidence": 95 if root_domain in email_clean else 85,
                                "is_human": False,
                                "source": f"site_crawler:{urlparse(clean_url).path or '/'}",
                            })

                # E. Extract primary social links (LinkedIn /in/, etc.)
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"].strip()
                    if not href.startswith("http"):
                        href = urljoin(clean_url, href)

                    for plat_dom, plat_name in PLATFORM_DOMAINS.items():
                        if plat_dom in href.lower():
                            if any(noise in href.lower() for noise in ["/reel/", "/posts/", "/videos/", "/status/", "/hashtag/", "/share", "/intent/"]):
                                continue

                            if href not in seen_profiles:
                                seen_profiles.add(href)
                                is_person_profile = "/in/" in href.lower()
                                results.append({
                                    "name": "",
                                    "email": "",
                                    "phone": "",
                                    "title": "Verified Profile" if is_person_profile else "Official Corporate Profile",
                                    "profile_url": href,
                                    "platform": plat_name,
                                    "confidence": 90,
                                    "is_human": is_person_profile,
                                    "source": f"site_crawler:{plat_name.lower()}",
                                })

                # F. Extract employee names and titles from verified team containers
                for container in soup.find_all(class_=re.compile(r"team|staff|member|leader|profile|bio|author|director", re.IGNORECASE)):
                    name_tag = container.find(["h2", "h3", "h4", "h5", "strong"])
                    if name_tag:
                        name_text = name_tag.get_text().strip()
                        if is_valid_human_name(name_text, org_guess) and name_text.lower() not in seen_names:
                            seen_names.add(name_text.lower())
                            role_text = "Team Member"
                            role_tag = container.find(["p", "span", "div"], class_=re.compile(r"role|title|position|job", re.IGNORECASE))
                            if role_tag:
                                role_text = role_tag.get_text().strip() or role_text
                            elif name_tag.find_next_sibling(["p", "span"]):
                                sib_text = name_tag.find_next_sibling(["p", "span"]).get_text().strip()
                                if sib_text and len(sib_text) < 50:
                                    role_text = sib_text

                            card_profile = ""
                            card_a = container.find("a", href=re.compile(r"linkedin\.com/in/|twitter\.com/|x\.com/"))
                            if card_a and card_a.get("href"):
                                card_profile = card_a["href"].strip()

                            results.append({
                                "name": name_text,
                                "email": "",
                                "phone": "",
                                "title": role_text,
                                "profile_url": card_profile or clean_url,
                                "platform": "Corporate Website",
                                "confidence": 90,
                                "is_human": True,
                                "source": f"site_crawler:{urlparse(clean_url).path or '/'}",
                            })

                # G. Enqueue new in-scope links for BFS crawling (if depth < max_depth)
                if depth < max_depth:
                    for a_tag in soup.find_all("a", href=True):
                        raw_href = a_tag["href"].strip()
                        if not raw_href or raw_href.startswith(("#", "javascript:", "mailto:", "tel:")):
                            continue
                        next_url = urljoin(clean_url, raw_href).split("#")[0].rstrip("/")
                        parsed = urlparse(next_url)

                        # Scope check: Must match root_domain exactly
                        if not parsed.netloc or extract_root_domain(parsed.netloc) != root_domain:
                            continue

                        # Exclude media and noisy paths
                        if any(next_url.lower().endswith(ext) for ext in MEDIA_EXTENSIONS):
                            continue
                        if any(noise in next_url.lower() for noise in NOISE_SUBPATHS):
                            continue

                        if next_url not in visited_urls:
                            # Prioritize high-value URLs to front of queue
                            if any(kw in next_url.lower() for kw in HIGH_VALUE_KEYWORDS):
                                queue.appendleft((next_url, depth + 1))
                            else:
                                queue.append((next_url, depth + 1))

            except Exception as e:
                logger.debug(f"Error deep crawling {clean_url}: {e}")

    logger.info(
        f"[people.site_crawler] Deep crawl completed: visited {len(visited_urls)} pages across '{root_domain}', "
        f"harvested {len(results)} personnel/contact records"
    )

    return results
