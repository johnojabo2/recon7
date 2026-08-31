import io
import logging
import os
import re
import zipfile
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Set, Tuple, Optional
import httpx
from pypdf import PdfReader
from core.config import settings
from core.scope import extract_root_domain
from people.wayback import extract_wayback_documents

logger = logging.getLogger(__name__)

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
PHONE_REGEX = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}")

# Forensics regex extractors
AD_USER_REGEX = re.compile(r"(?:[a-zA-Z0-9_-]{2,15}\\[a-zA-Z0-9._-]+|[a-zA-Z0-9._-]+_adm\b|[a-zA-Z0-9._-]+\.sa\b)", re.IGNORECASE)
UNC_PATH_REGEX = re.compile(r"(\\\\[a-zA-Z0-9._-]+\\[a-zA-Z0-9._$\-\\]+|(?:[A-Z]):\\Users\\[a-zA-Z0-9._-]+\\[a-zA-Z0-9._$\-\\]+|/home/[a-zA-Z0-9._-]+/[a-zA-Z0-9._\-/]+)", re.IGNORECASE)

# Direct signature / author patterns in document text
SIGNATURE_PATTERNS = [
    re.compile(r"(?:prepared by|author|authored by|contact|signed by|presented by|speaker|director|manager|lead|coordinator):\s*([A-Z][a-zA-Z'\-]+(?:\s+[A-Z][a-zA-Z'\-]+){1,3})", re.IGNORECASE),
    re.compile(r"([A-Z][a-zA-Z'\-]+(?:\s+[A-Z][a-zA-Z'\-]+){1,2})\s*[-–—|]\s*(?:CEO|CTO|CFO|COO|Director|Founder|Manager|Lead|Partner|President|Vice President|Head of [A-Za-z]+)", re.IGNORECASE),
]

IGNORED_AUTHORS = {
    "adobe", "microsoft", "canva", "latex", "word", "excel", "powerpoint",
    "pdf creator", "print to pdf", "acrobat", "writer", "user", "admin",
    "administrator", "author", "unknown", "untitled", "hp", "canon", "epson",
    "root", "guest", "default", "null", "none"
}


def _extract_pdf_forensics(content: bytes, max_pages: int = 15) -> Tuple[str, Dict[str, Any]]:
    """Extracts raw text body and forensic metadata from PDF bytes."""
    meta_dict: Dict[str, Any] = {}
    text_chunks: List[str] = []
    try:
        reader = PdfReader(io.BytesIO(content))
        if reader.metadata:
            for k, v in reader.metadata.items():
                if v and isinstance(v, str):
                    clean_k = k.lstrip("/").lower()
                    meta_dict[clean_k] = v.strip()

        for page in reader.pages[:max_pages]:
            try:
                page_text = page.extract_text()
                if page_text:
                    text_chunks.append(page_text)
            except Exception:
                continue
    except Exception as e:
        logger.debug(f"[doc_metadata] PDF parse error: {e}")
    return "\n".join(text_chunks), meta_dict


def _extract_openxml_forensics(content: bytes) -> Tuple[str, Dict[str, Any]]:
    """
    Extracts text body, author, last modified by, and software application from OpenXML files (.docx, .xlsx, .pptx).
    """
    text_chunks: List[str] = []
    meta_dict: Dict[str, Any] = {}

    try:
        with zipfile.ZipFile(io.BytesIO(content)) as z:
            namelist = z.namelist()

            # 1. Extract core properties (dc:creator, cp:lastModifiedBy, created, modified)
            if "docProps/core.xml" in namelist:
                try:
                    core_xml = z.read("docProps/core.xml")
                    root = ET.fromstring(core_xml)
                    for elem in root.iter():
                        tag = elem.tag.split("}")[-1].lower()
                        text = (elem.text or "").strip()
                        if text:
                            if tag == "creator":
                                meta_dict["author"] = text
                            elif tag == "lastmodifiedby":
                                meta_dict["last_modified_by"] = text
                            elif tag == "created":
                                meta_dict["creation_date"] = text
                            elif tag == "modified":
                                meta_dict["modification_date"] = text
                except Exception as e:
                    logger.debug(f"Error parsing core.xml: {e}")

            # 2. Extract app properties (Application, AppVersion, Company)
            if "docProps/app.xml" in namelist:
                try:
                    app_xml = z.read("docProps/app.xml")
                    root = ET.fromstring(app_xml)
                    for elem in root.iter():
                        tag = elem.tag.split("}")[-1].lower()
                        text = (elem.text or "").strip()
                        if text:
                            if tag == "application":
                                meta_dict["creator_software"] = text
                            elif tag == "appversion":
                                meta_dict["software_version"] = text
                            elif tag == "company":
                                meta_dict["company"] = text
                except Exception as e:
                    logger.debug(f"Error parsing app.xml: {e}")

            # 3. Extract text from Word document.xml
            if "word/document.xml" in namelist:
                try:
                    doc_xml = z.read("word/document.xml")
                    root = ET.fromstring(doc_xml)
                    for elem in root.iter():
                        if elem.tag.endswith("}t") and elem.text:
                            text_chunks.append(elem.text)
                except Exception:
                    pass

            # 4. Extract text from Excel sharedStrings.xml
            if "xl/sharedStrings.xml" in namelist:
                try:
                    xl_xml = z.read("xl/sharedStrings.xml")
                    root = ET.fromstring(xl_xml)
                    for elem in root.iter():
                        if elem.tag.endswith("}t") and elem.text:
                            text_chunks.append(elem.text)
                except Exception:
                    pass

    except Exception as e:
        logger.debug(f"[doc_metadata] OpenXML parse error: {e}")

    return " ".join(text_chunks), meta_dict


def _extract_text_file(content: bytes) -> str:
    """Decodes plain text / CSV / TSV bytes."""
    for enc in ["utf-8", "latin-1", "cp1252"]:
        try:
            return content.decode(enc, errors="ignore")
        except Exception:
            continue
    return ""


def _extract_signatures_from_text(text: str) -> List[str]:
    """Finds named individuals cited in signature, credit, or contact lines."""
    names: List[str] = []
    for pat in SIGNATURE_PATTERNS:
        for match in pat.findall(text):
            cand = match.strip()
            words = cand.split()
            if 2 <= len(words) <= 4 and not any(w.lower() in IGNORED_AUTHORS for w in words):
                names.append(cand)
    return names


def extract_public_doc_metadata(
    domain: str,
    org_name: Optional[str] = None,
    seed_ceo: Optional[str] = None,
    timeout: int = 15,
) -> Dict[str, Any]:
    """
    Submodule 3: Full-Text Document Ingestion & Defensive Forensics Harvester.
    Mines both live search dorks AND Wayback CDX historical document archives for
    publicly exposed files (PDF, DOCX, XLSX, PPTX, CSV, TXT).
    Extracts:
      - Forensic identities: Active Directory accounts, authors, last modified users.
      - Internal technical leaks: UNC file share paths, internal network storage, software builds.
      - Corporate contacts: Email addresses, phone numbers, executive signatures.
    """
    root_domain = extract_root_domain(domain)
    domain_stem = root_domain.split(".")[0].capitalize()
    clean_org = org_name.strip() if (org_name and len(org_name.strip()) > 2) else domain_stem

    logger.info(f"[people.doc_metadata] Probing public documents for '{domain}' (Org: '{clean_org}')")
    entities: List[Dict[str, Any]] = []
    document_exposures: List[Dict[str, Any]] = []

    seen_emails: Set[str] = set()
    seen_names: Set[str] = set()
    seen_urls: Set[str] = set()
    seen_ad_users: Set[str] = set()
    seen_unc_paths: Set[str] = set()

    discovered_docs: List[Dict[str, str]] = []

    # 1. Discover documents from Google/Serp Search Dorks
    doc_q1 = f'site:{root_domain} (filetype:pdf OR filetype:docx OR filetype:xlsx OR filetype:pptx OR filetype:csv)'
    if seed_ceo and len(seed_ceo.strip()) > 2:
        doc_q2 = f'"{clean_org}" "{seed_ceo.strip()}" (filetype:pdf OR filetype:docx OR filetype:xlsx)'
    else:
        doc_q2 = f'"{clean_org}" ("confidential" OR "internal" OR "staff roster" OR "credentials") (filetype:pdf OR filetype:xlsx OR filetype:txt)'

    try:
        from core.google_search import query_google_search
        for q in [doc_q1, doc_q2]:
            items = query_google_search(q, num=10, timeout=timeout)
            for item in items:
                link = item.get("link", "").strip()
                title = item.get("title", "").strip()
                snippet = item.get("snippet", "").strip()
                if link and link not in seen_urls:
                    seen_urls.add(link)
                    discovered_docs.append({
                        "link": link,
                        "title": title,
                        "snippet": snippet,
                        "source": "search_dork",
                    })

                    # Immediate Snippet Harvesting (Zero-Download Guarantee)
                    full_snippet = f"{title} {snippet}"
                    for em in EMAIL_REGEX.findall(full_snippet):
                        em_clean = em.lower().strip().rstrip(".")
                        if not any(em_clean.endswith(ext) for ext in [".png", ".jpg", ".svg", ".css", ".js"]):
                            if em_clean not in seen_emails:
                                seen_emails.add(em_clean)
                                entities.append({
                                    "name": "",
                                    "email": em_clean,
                                    "title": f"Contact in Document Excerpt ({title[:40]})",
                                    "profile_url": link,
                                    "platform": "Document Snippet",
                                    "confidence": 90,
                                    "is_human": False,
                                    "source": f"doc_snippet:{link.split('/')[-1]}",
                                })
    except Exception as e:
        logger.debug(f"[doc_metadata] Search query error: {e}")

    # 2. Discover historical documents from Wayback Machine CDX API
    try:
        wayback_docs = extract_wayback_documents(root_domain, timeout=timeout)
        for w_doc in wayback_docs[:10]:
            orig_url = w_doc["original_url"]
            if orig_url not in seen_urls:
                seen_urls.add(orig_url)
                discovered_docs.append({
                    "link": w_doc.get("archive_url") or orig_url,
                    "title": orig_url.split("/")[-1],
                    "snippet": f"Archived {w_doc['filetype']} file from Wayback snapshot ({w_doc.get('timestamp')})",
                    "source": "wayback_archive",
                })
    except Exception as e:
        logger.debug(f"[doc_metadata] Wayback doc harvesting error: {e}")

    # 3. Stream & Extract Forensic Metadata from Discovered Documents
    with httpx.Client(
        timeout=timeout,
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) R7-DocExtractor/2.0"},
    ) as client:
        for doc_item in discovered_docs[:12]:  # Process top 12 discovered documents
            doc_url = doc_item["link"]
            doc_title = doc_item["title"]
            lower_url = doc_url.lower()

            try:
                # Stream download with size limit (max 5MB)
                with client.stream("GET", doc_url) as resp:
                    if resp.status_code != 200:
                        continue
                    content_length = resp.headers.get("content-length")
                    if content_length and int(content_length) > 5 * 1024 * 1024:
                        continue
                    body = resp.read()

                body_text = ""
                meta_dict: Dict[str, Any] = {}

                if lower_url.endswith(".pdf") or b"%PDF-" in body[:10]:
                    body_text, meta_dict = _extract_pdf_forensics(body)
                elif any(lower_url.endswith(ext) for ext in [".docx", ".xlsx", ".pptx"]) or b"PK\x03\x04" in body[:4]:
                    body_text, meta_dict = _extract_openxml_forensics(body)
                elif any(lower_url.endswith(ext) for ext in [".txt", ".csv", ".tsv"]):
                    body_text = _extract_text_file(body)

                if not body_text and not meta_dict:
                    continue

                # Forensic field extraction
                doc_authors: List[str] = []
                author = meta_dict.get("author") or meta_dict.get("creator")
                if author and isinstance(author, str):
                    clean_author = author.strip()
                    if (
                        clean_author not in seen_names
                        and len(clean_author) >= 3
                        and not any(k in clean_author.lower() for k in IGNORED_AUTHORS)
                    ):
                        seen_names.add(clean_author)
                        doc_authors.append(clean_author)
                        entities.append({
                            "name": clean_author,
                            "email": "",
                            "title": f"Document Author ({doc_title[:40]})",
                            "profile_url": doc_url,
                            "platform": "Document Metadata",
                            "confidence": 85,
                            "is_human": True,
                            "source": f"doc_metadata:{doc_url.split('/')[-1]}",
                        })

                last_mod = meta_dict.get("last_modified_by")
                if last_mod and isinstance(last_mod, str):
                    clean_last = last_mod.strip()
                    if clean_last not in seen_names and len(clean_last) >= 3 and not any(k in clean_last.lower() for k in IGNORED_AUTHORS):
                        seen_names.add(clean_last)
                        doc_authors.append(clean_last)
                        entities.append({
                            "name": clean_last,
                            "email": "",
                            "title": f"Document Editor / Contributor ({doc_title[:40]})",
                            "profile_url": doc_url,
                            "platform": "Document Metadata",
                            "confidence": 80,
                            "is_human": True,
                            "source": f"doc_metadata:{doc_url.split('/')[-1]}",
                        })

                # Check for Active Directory user accounts in metadata and text
                combined_content = f"{body_text} {' '.join(str(v) for v in meta_dict.values())}"
                doc_ad_users = []
                for match in AD_USER_REGEX.finditer(combined_content):
                    user_cand = match.group(0).strip()
                    if user_cand not in seen_ad_users and len(user_cand) > 3:
                        seen_ad_users.add(user_cand)
                        doc_ad_users.append(user_cand)

                # Check for internal UNC file shares and directory paths
                doc_unc_paths = []
                for match in UNC_PATH_REGEX.finditer(combined_content):
                    path_cand = match.group(0).strip()
                    if path_cand not in seen_unc_paths and len(path_cand) > 5:
                        seen_unc_paths.add(path_cand)
                        doc_unc_paths.append(path_cand)

                # Extract Emails from body text
                found_emails = EMAIL_REGEX.findall(body_text)
                doc_emails = []
                for em in found_emails:
                    em_clean = em.lower().strip().rstrip(".")
                    if not any(em_clean.endswith(ext) for ext in [".png", ".jpg", ".svg", ".css", ".js"]):
                        if em_clean not in seen_emails:
                            seen_emails.add(em_clean)
                            doc_emails.append(em_clean)
                            entities.append({
                                "name": "",
                                "email": em_clean,
                                "title": f"Cited in Document ({doc_title[:40]})",
                                "profile_url": doc_url,
                                "platform": "Public Document",
                                "confidence": 95 if root_domain in em_clean else 85,
                                "is_human": False,
                                "source": f"doc_body:{doc_url.split('/')[-1]}",
                            })

                # Extract Signatures from body text
                signatures = _extract_signatures_from_text(body_text)
                for sig in signatures:
                    if sig not in seen_names:
                        seen_names.add(sig)
                        doc_authors.append(sig)
                        entities.append({
                            "name": sig,
                            "email": "",
                            "title": f"Document Signatory ({doc_title[:40]})",
                            "profile_url": doc_url,
                            "platform": "Public Document",
                            "confidence": 88,
                            "is_human": True,
                            "source": f"doc_signature:{doc_url.split('/')[-1]}",
                        })

                # Compile structured Document Exposure Record
                software_signature = meta_dict.get("creator_software") or meta_dict.get("producer") or meta_dict.get("creator") or "Standard Document Format"
                creation_dt = meta_dict.get("creation_date") or meta_dict.get("created")
                
                document_exposures.append({
                    "url": doc_url,
                    "filename": doc_url.split("/")[-1].split("?")[0] or doc_title,
                    "title": doc_title,
                    "source": doc_item.get("source", "search_dork"),
                    "software": software_signature,
                    "authors": doc_authors,
                    "ad_usernames": doc_ad_users,
                    "internal_paths": doc_unc_paths,
                    "emails_discovered": doc_emails,
                    "creation_date": creation_dt,
                    "has_sensitive_leaks": bool(doc_ad_users or doc_unc_paths),
                })

            except Exception as e:
                logger.debug(f"[doc_metadata] Failed processing doc '{doc_url}': {e}")
                continue

    logger.info(f"[people.doc_metadata] Discovered {len(entities)} entities and {len(document_exposures)} forensic document exposures.")
    return {
        "entities": entities,
        "document_exposures": document_exposures,
        "ad_usernames": list(seen_ad_users),
        "internal_paths": list(seen_unc_paths),
    }

