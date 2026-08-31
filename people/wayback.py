import logging
import re
from typing import List, Dict, Any, Set
import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

TEAM_KEYWORDS = ["team", "about", "contact", "leadership", "people", "staff", "board", "management"]


def extract_wayback_people(domain: str, timeout: int = 15) -> List[Dict[str, Any]]:
    """
    Submodule 6: Wayback Machine Historical Team & Contact Archive Harvester.
    Queries Wayback Machine CDX index for archived snapshots of team/contact pages.
    Extracts historical employee profiles and emails that may have been removed from the live site.
    """
    logger.info(f"[people.wayback] Probing Wayback Machine historical archives for '{domain}'")
    results: List[Dict[str, Any]] = []
    seen_emails: Set[str] = set()
    seen_names: Set[str] = set()

    cdx_url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url={domain}/*&output=json&fl=original,timestamp,statuscode,mimetype"
        f"&filter=statuscode:200&filter=mimetype:text/html&collapse=urlkey&limit=50"
    )

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) R7-OSINT/1.0",
        "Accept": "application/json",
    }

    try:
        with httpx.Client(timeout=timeout, headers=headers, follow_redirects=True) as client:
            resp = client.get(cdx_url)
            if resp.status_code != 200:
                return []

            rows = resp.json()
            if not rows or len(rows) <= 1:
                return []

            # Filter relevant historical snapshot URLs
            relevant_snapshots = []
            for row in rows[1:]:
                if len(row) >= 2:
                    orig_url, timestamp = row[0], row[1]
                    if any(kw in orig_url.lower() for kw in TEAM_KEYWORDS):
                        relevant_snapshots.append((orig_url, timestamp))

            logger.info(f"[people.wayback] Found {len(relevant_snapshots)} historical team snapshot candidate URLs")

            # Fetch top 5 historical snapshots
            for orig_url, timestamp in relevant_snapshots[:5]:
                raw_snap_url = f"https://web.archive.org/web/{timestamp}id_/{orig_url}"
                try:
                    snap_resp = client.get(raw_snap_url)
                    if snap_resp.status_code == 200:
                        html = snap_resp.text
                        soup = BeautifulSoup(html, "html.parser")

                        # 1. Extract historical emails
                        for m in EMAIL_REGEX.findall(html):
                            m_clean = m.lower().strip()
                            if domain.lower() in m_clean and m_clean not in seen_emails:
                                if not any(m_clean.endswith(ext) for ext in [".png", ".jpg", ".svg", ".css", ".js"]):
                                    seen_emails.add(m_clean)
                                    results.append({
                                        "name": "",
                                        "email": m_clean,
                                        "title": "Historical Staff Contact",
                                        "profile_url": raw_snap_url,
                                        "platform": "Wayback Archive",
                                        "confidence": 85,
                                        "source": "wayback_archive",
                                    })

                        # 2. Extract historical names
                        for tag in soup.find_all(["h2", "h3", "h4", "strong"]):
                            text = tag.get_text().strip()
                            words = text.split()
                            if 2 <= len(words) <= 3 and all(w.isalpha() and w[0].isupper() for w in words):
                                if text.lower() not in seen_names and len(text) > 4:
                                    seen_names.add(text.lower())
                                    results.append({
                                        "name": text,
                                        "email": "",
                                        "title": "Historical Team Member",
                                        "profile_url": raw_snap_url,
                                        "platform": "Wayback Archive",
                                        "confidence": 80,
                                        "source": "wayback_archive",
                                    })
                except Exception as e:
                    logger.debug(f"Wayback snapshot fetch failed for {raw_snap_url}: {e}")

    except Exception as e:
        logger.debug(f"Wayback CDX API query failed for {domain}: {e}")

    logger.info(f"[people.wayback] Discovered {len(results)} historical people findings from Wayback Machine")
    return results


def extract_wayback_documents(domain: str, timeout: int = 15) -> List[Dict[str, Any]]:
    """
    Submodule 6B: Wayback Machine Historical Document & File Archive Harvester.
    Queries the Wayback Machine CDX index for archived PDFs, DOCX, XLSX, PPTX, and sensitive files.
    Returns list of discovered historical document URLs with timestamps and MIME types.
    """
    logger.info(f"[people.wayback] Probing Wayback CDX for historical documents on '{domain}'")
    documents: List[Dict[str, Any]] = []
    seen_urls: Set[str] = set()

    cdx_doc_url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url={domain}/*&output=json&fl=original,timestamp,statuscode,mimetype"
        f"&filter=statuscode:200&collapse=urlkey&limit=80"
    )

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) R7-OSINT/1.0",
        "Accept": "application/json",
    }

    DOC_EXTENSIONS = (".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".csv", ".txt")

    try:
        with httpx.Client(timeout=timeout, headers=headers, follow_redirects=True) as client:
            resp = client.get(cdx_doc_url)
            if resp.status_code != 200:
                return []

            rows = resp.json()
            if not rows or len(rows) <= 1:
                return []

            for row in rows[1:]:
                if len(row) >= 4:
                    orig_url, timestamp, status_code, mimetype = row[0], row[1], row[2], row[3]
                    lower_url = orig_url.lower().split("?")[0]
                    if any(lower_url.endswith(ext) for ext in DOC_EXTENSIONS) or "pdf" in mimetype or "msword" in mimetype or "officedocument" in mimetype:
                        if orig_url not in seen_urls:
                            seen_urls.add(orig_url)
                            archive_snap_url = f"https://web.archive.org/web/{timestamp}id_/{orig_url}"
                            ext = lower_url.split(".")[-1] if "." in lower_url else "pdf"
                            documents.append({
                                "original_url": orig_url,
                                "archive_url": archive_snap_url,
                                "timestamp": timestamp,
                                "filetype": ext.upper(),
                                "mimetype": mimetype,
                                "source": "wayback_archive",
                            })

    except Exception as e:
        logger.debug(f"Wayback document CDX query failed for {domain}: {e}")

    logger.info(f"[people.wayback] Discovered {len(documents)} archived document candidate URLs")
    return documents
