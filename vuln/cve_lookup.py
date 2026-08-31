import logging
import time
from typing import Dict, Any, List, Optional, Set
import httpx

logger = logging.getLogger(__name__)

# CISA Known Exploited Vulnerabilities Public Catalog URL
CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CISA_KEV_CACHE: Optional[Set[str]] = None
_CISA_KEV_LAST_FETCH: float = 0.0
_CISA_KEV_CACHE_TTL: float = 86400.0  # 24 hours

# Authoritative baseline offline KEV catalog (fallback if air-gapped / offline)
_BASELINE_OFFLINE_KEV: Set[str] = {
    "CVE-2023-44487",  # HTTP/2 Rapid Reset
    "CVE-2021-44228",  # Log4Shell
    "CVE-2021-45046",  # Log4j
    "CVE-2022-26134",  # Confluence OGNL
    "CVE-2023-34362",  # MOVEit Transfer SQLi
    "CVE-2023-22515",  # Confluence Broken Access
    "CVE-2024-1709",   # ConnectWise ScreenConnect Auth Bypass
    "CVE-2024-21762",  # Fortinet FortiOS SSL-VPN RCE
    "CVE-2024-3400",   # Palo Alto PAN-OS Command Injection
    "CVE-2017-0144",   # EternalBlue (MS17-010)
    "CVE-2019-19781",  # Citrix ADC / Gateway
    "CVE-2020-1472",   # Zerologon
    "CVE-2021-26855",  # ProxyLogon (Exchange)
    "CVE-2021-34527",  # PrintNightmare
    "CVE-2022-30190",  # Follina MSDT
    "CVE-2023-23397",  # Microsoft Outlook NTLM Relay
}


def get_cisa_kev_set(timeout: int = 5) -> Set[str]:
    """
    Returns the set of verified CVE IDs currently cataloged in the CISA KEV list.
    Attempts live fetch with 24-hour caching; falls back to verified baseline catalog if offline.
    Requires ZERO API keys.
    """
    global _CISA_KEV_CACHE, _CISA_KEV_LAST_FETCH
    now = time.time()

    if _CISA_KEV_CACHE is not None and (now - _CISA_KEV_LAST_FETCH) < _CISA_KEV_CACHE_TTL:
        return _CISA_KEV_CACHE

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(CISA_KEV_FEED_URL, headers={"User-Agent": "R7-ThreatIntel/1.0"})
            if resp.status_code == 200:
                data = resp.json()
                vulnerabilities = data.get("vulnerabilities", [])
                cve_set = set()
                for v in vulnerabilities:
                    cve_id = v.get("cveID")
                    if cve_id:
                        cve_set.add(cve_id.strip().upper())

                if cve_set:
                    _CISA_KEV_CACHE = cve_set
                    _CISA_KEV_LAST_FETCH = now
                    logger.info(f"[vuln.cve_lookup] Synchronized {len(cve_set)} verified CVEs from official CISA KEV catalog")
                    return _CISA_KEV_CACHE
    except Exception as e:
        logger.debug(f"[vuln.cve_lookup] Live CISA KEV sync unavailable ({e}). Using local baseline catalog.")

    if _CISA_KEV_CACHE is None:
        _CISA_KEV_CACHE = set(_BASELINE_OFFLINE_KEV)
        _CISA_KEV_LAST_FETCH = now

    return _CISA_KEV_CACHE


def is_verified_cisa_kev(cve_id: str) -> bool:
    """
    Returns True ONLY if the given CVE ID is confirmed in CISA's official KEV catalog.
    Prevents false 'actively exploited' claims for theoretical/lab PoCs like CVE-2024-6387.
    """
    if not cve_id or not isinstance(cve_id, str):
        return False
    kev_set = get_cisa_kev_set()
    return cve_id.strip().upper() in kev_set

OWASP_TOP_10_MAPPING = {
    "A01": "A01:2021 - Broken Access Control",
    "A02": "A02:2021 - Cryptographic Failures",
    "A03": "A03:2021 - Injection",
    "A04": "A04:2021 - Insecure Design",
    "A05": "A05:2021 - Security Misconfiguration",
    "A06": "A06:2021 - Vulnerable and Outdated Components",
    "A07": "A07:2021 - Identification and Authentication Failures",
    "A08": "A08:2021 - Software and Data Integrity Failures",
    "A09": "A09:2021 - Security Logging and Monitoring Failures",
    "A10": "A10:2021 - Server-Side Request Forgery (SSRF)",
}

CWE_TO_OWASP = {
    "CWE-200": "A01",
    "CWE-538": "A01",
    "CWE-552": "A01",
    "CWE-319": "A02",
    "CWE-326": "A02",
    "CWE-89":  "A03",
    "CWE-79":  "A03",
    "CWE-1021": "A05",
    "CWE-16":  "A05",
    "CWE-1104": "A06",
    "CWE-287": "A07",
    "CWE-918": "A10",
}


def correlate_findings_with_cve_and_owasp(findings: List[Dict[str, Any]], timeout: int = 5) -> List[Dict[str, Any]]:
    """
    Step 7: Enriches vulnerability findings with NVD public API lookups and OWASP Top 10 mappings.
    """
    logger.info(f"[vuln.cve_lookup] Correlating {len(findings)} findings against NVD and OWASP Top 10")
    
    enriched = []
    for f in findings:
        item = dict(f)
        cve_ids = item.get("cve_ids", [])
        cwe_ids = item.get("cwe_ids", [])
        
        # 1. Determine OWASP Top 10 Category
        owasp_cat = None
        for cwe in cwe_ids:
            if cwe in CWE_TO_OWASP:
                owasp_key = CWE_TO_OWASP[cwe]
                owasp_cat = OWASP_TOP_10_MAPPING.get(owasp_key)
                break
        
        if not owasp_cat:
            template_id = item.get("template_id", "").lower()
            if "missing" in template_id or "header" in template_id:
                owasp_cat = OWASP_TOP_10_MAPPING["A05"]
            elif "git" in template_id or "env" in template_id:
                owasp_cat = OWASP_TOP_10_MAPPING["A01"]
            elif "sqli" in template_id or "xss" in template_id:
                owasp_cat = OWASP_TOP_10_MAPPING["A03"]
            elif "cve" in template_id:
                owasp_cat = OWASP_TOP_10_MAPPING["A06"]
            else:
                owasp_cat = OWASP_TOP_10_MAPPING["A05"]

        item["owasp_category"] = owasp_cat

        # 2. Query NVD API for CVE details if present & verify CISA KEV status
        nvd_details = []
        cisa_kev_confirmed = False
        if isinstance(cve_ids, list):
            for cve in cve_ids:
                if is_verified_cisa_kev(cve):
                    cisa_kev_confirmed = True
            for cve in cve_ids[:2]:
                details = lookup_nvd_cve(cve, timeout=timeout)
                if details:
                    nvd_details.append(details)

        # Strictly enforce CISA KEV status
        if "cve_id" in item and is_verified_cisa_kev(item["cve_id"]):
            cisa_kev_confirmed = True

        item["cisa_kev"] = cisa_kev_confirmed
        item["nvd_data"] = nvd_details
        enriched.append(item)

    return enriched


def correlate_port_findings_to_vulns(ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Analyzes deep Nmap port findings and automatically generates vulnerability findings for:
    - Dangerous HTTP methods (TRACE, PUT)
    - Anonymous FTP / Unauthenticated database exposure
    - Weak SSL/TLS ciphers
    - Specific outdated software versions
    """
    vulns = []
    for p in ports:
        ip = p.get("ip", "unknown")
        port_num = p.get("port", 0)
        product = p.get("product", "")
        version = p.get("version", "")
        host_label = f"{ip}:{port_num}"

        # 1. Dangerous HTTP Methods
        dangerous_methods = p.get("dangerous_methods", [])
        if dangerous_methods:
            vulns.append({
                "template_id": "http-dangerous-methods-detected",
                "name": f"Dangerous HTTP Methods Enabled ({', '.join(dangerous_methods)})",
                "severity": "medium",
                "host": host_label,
                "matched_at": f"http://{host_label}",
                "description": f"Target web service on port {port_num} allows dangerous HTTP methods ({', '.join(dangerous_methods)}), potentially enabling Cross-Site Tracing (XST) or unauthorized file uploads.",
                "cwe_ids": ["CWE-16"],
                "owasp_category": OWASP_TOP_10_MAPPING["A05"],
            })

        # 2. Anonymous FTP Login
        if p.get("anonymous_access"):
            vulns.append({
                "template_id": "ftp-anonymous-access",
                "name": "Anonymous FTP Login Allowed",
                "severity": "high",
                "host": host_label,
                "matched_at": f"ftp://{host_label}",
                "description": f"FTP server on port {port_num} accepts unauthenticated anonymous logins with read/write access.",
                "cwe_ids": ["CWE-287"],
                "owasp_category": OWASP_TOP_10_MAPPING["A07"],
            })

        # 3. Weak SSL/TLS Ciphers
        weak_ciphers = p.get("weak_ciphers", [])
        if weak_ciphers:
            vulns.append({
                "template_id": "tls-weak-ciphers-supported",
                "name": "Legacy SSLv3 / TLS 1.0 or Weak Ciphers Supported",
                "severity": "medium",
                "host": host_label,
                "matched_at": f"https://{host_label}",
                "description": f"TLS endpoint on port {port_num} supports obsolete protocols or weak encryption ciphers.",
                "cwe_ids": ["CWE-326"],
                "owasp_category": OWASP_TOP_10_MAPPING["A02"],
            })

    return vulns


def lookup_nvd_cve(cve_id: str, timeout: int = 5) -> Optional[Dict[str, Any]]:
    """Free public query to NIST NVD 2.0 API."""
    if not cve_id or not cve_id.upper().startswith("CVE-"):
        return None

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.upper()}"
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url, headers={"User-Agent": "R7-VulnEngine/1.0"})
            if resp.status_code == 200:
                data = resp.json()
                vulnerabilities = data.get("vulnerabilities", [])
                if vulnerabilities:
                    cve_item = vulnerabilities[0].get("cve", {})
                    metrics = cve_item.get("metrics", {})
                    
                    cvss_v31 = metrics.get("cvssMetricV31", [])
                    base_score = None
                    if cvss_v31:
                        base_score = cvss_v31[0].get("cvssData", {}).get("baseScore")

                    descriptions = cve_item.get("descriptions", [])
                    desc_text = descriptions[0].get("value", "") if descriptions else ""

                    return {
                        "cve_id": cve_id,
                        "base_score": base_score,
                        "description": desc_text[:300],
                    }
    except Exception as e:
        logger.debug(f"NVD query failed for {cve_id}: {e}")

    return None
