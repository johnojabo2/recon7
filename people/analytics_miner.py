import logging
import re
from typing import Dict, Any, Set, List, Tuple, Optional
import httpx

logger = logging.getLogger(__name__)

# Regular expressions for high-fidelity web tracking tokens
GTM_REGEX = re.compile(r"GTM-[A-Z0-9]{4,9}")
GA4_REGEX = re.compile(r"G-[A-Z0-9]{8,12}")
UA_REGEX = re.compile(r"UA-\d{4,10}-\d{1,4}")
ADSENSE_REGEX = re.compile(r"pub-\d{16}")
META_PIXEL_REGEX = re.compile(r"fbq\(['\"]init['\"],\s*['\"](\d{12,18})['\"]\)")
HOTJAR_REGEX = re.compile(r"hjid:\s*(\d{5,10})")


def extract_analytics_ids(html_content: str) -> Dict[str, Set[str]]:
    """
    Native SpiderFoot-inspired Web Analytics & Tracking Tag Extractor (sfp_analytics / sfp_spyonweb).
    Extracts marketing infrastructure and tracking tokens across HTML source:
      - Google Tag Manager (GTM)
      - Google Analytics 4 (GA4)
      - Universal Analytics (UA)
      - Google AdSense (pub-)
      - Meta / Facebook Pixel
      - Hotjar ID
    """
    if not html_content or len(html_content) < 20:
        return {}

    tokens: Dict[str, Set[str]] = {
        "gtm": set(GTM_REGEX.findall(html_content)),
        "ga4": set(GA4_REGEX.findall(html_content)),
        "ua": set(UA_REGEX.findall(html_content)),
        "adsense": set(ADSENSE_REGEX.findall(html_content)),
        "meta_pixel": set(META_PIXEL_REGEX.findall(html_content)),
        "hotjar": set(HOTJAR_REGEX.findall(html_content)),
    }

    # Clean out empty sets
    return {k: v for k, v in tokens.items() if v}


def correlate_shared_analytics(
    parent_tokens: Dict[str, Set[str]],
    candidate_tokens: Dict[str, Set[str]],
) -> Tuple[bool, int, List[Dict[str, Any]]]:
    """
    Correlates tracking tokens between a parent organization domain and a candidate subsidiary domain.
    Returns (has_shared_infrastructure, confidence_boost, list_of_anchors).
    """
    anchors: List[Dict[str, Any]] = []
    total_boost = 0

    if not parent_tokens or not candidate_tokens:
        return False, 0, []

    for tag_type, p_set in parent_tokens.items():
        c_set = candidate_tokens.get(tag_type, set())
        shared = p_set.intersection(c_set)
        if shared:
            tag_name = {
                "gtm": "Google Tag Manager (GTM)",
                "ga4": "Google Analytics 4 (GA4)",
                "ua": "Universal Analytics (UA)",
                "adsense": "Google AdSense (pub-)",
                "meta_pixel": "Meta Pixel",
                "hotjar": "Hotjar Site ID",
            }.get(tag_type, tag_type.upper())

            # GTM and AdSense are authoritative shared infrastructure (+45% confidence)
            weight = 45 if tag_type in ["gtm", "adsense"] else 35
            total_boost += weight

            anchors.append({
                "anchor": f"SHARED_{tag_type.upper()}_TRACKING_INFRASTRUCTURE",
                "description": f"Shared {tag_name} container ID ({', '.join(list(shared)[:2])}) with parent organization",
                "weight": weight,
                "shared_ids": list(shared),
            })

    has_shared = len(anchors) > 0
    return has_shared, min(50, total_boost), anchors


def fetch_and_extract_analytics_ids(url_or_domain: str, timeout: int = 6) -> Dict[str, Set[str]]:
    """Fetches home page of domain and extracts analytics tokens."""
    url = url_or_domain if url_or_domain.startswith("http") else f"https://{url_or_domain}"
    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
            resp = client.get(url, headers={"User-Agent": "Mozilla/5.0 Recon7-AnalyticsMiner/1.0"})
            if resp.status_code == 200 and resp.text:
                return extract_analytics_ids(resp.text)
    except Exception:
        pass
    return {}
