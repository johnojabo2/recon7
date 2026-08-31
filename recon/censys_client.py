import os
import logging
import re
from typing import List, Dict, Any, Set, Optional, Tuple
import httpx
from core.config import settings

logger = logging.getLogger(__name__)

CENSYS_SEARCH_BASE = "https://search.censys.io/api/v2"
CENSYS_PLATFORM_BASE = "https://api.platform.censys.io/v3"


def get_censys_credentials(
    api_id: Optional[str] = None,
    api_secret: Optional[str] = None,
    org_id: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Retrieves Censys credentials (API ID, Secret, and optional Org ID)."""
    cid = (api_id or getattr(settings, "CENSYS_API_ID", None) or os.getenv("CENSYS_API_ID") or "").strip()
    sec = (api_secret or getattr(settings, "CENSYS_API_SECRET", None) or os.getenv("CENSYS_API_SECRET") or "").strip()
    oid = (org_id or getattr(settings, "CENSYS_ORG_ID", None) or os.getenv("CENSYS_ORG_ID") or "").strip()

    if cid or sec:
        return cid or None, sec or None, oid or None
    return None, None, None


def _get_auth_and_headers(
    api_id: Optional[str] = None,
    api_secret: Optional[str] = None,
    org_id: Optional[str] = None,
):
    cid, sec, oid = get_censys_credentials(api_id, api_secret, org_id)
    headers = {"User-Agent": "R7-ReconEngine/1.0"}
    auth = None

    if oid:
        headers["X-Organization-ID"] = oid

    # Check if either field contains a Personal Access Token (starts with censys_)
    if cid and cid.startswith("censys_"):
        headers["Authorization"] = f"Bearer {cid}"
    elif sec and sec.startswith("censys_"):
        headers["Authorization"] = f"Bearer {sec}"
    elif cid and sec:
        # Both ID and Secret -> HTTP Basic Auth (v2)
        auth = (cid, sec)
    elif cid or sec:
        # Single Token -> Bearer PAT (v3 Platform API)
        token = cid or sec
        headers["Authorization"] = f"Bearer {token}"

    return auth, headers


def query_censys_subdomains(
    domain: str,
    api_id: Optional[str] = None,
    api_secret: Optional[str] = None,
    org_id: Optional[str] = None,
    timeout: int = 15,
) -> List[str]:
    """
    Queries Censys Certificates index for hostnames & SANs matching target domain.
    Supports both v2 Basic Auth and v3 Bearer PAT authentication.
    """
    auth, headers = _get_auth_and_headers(api_id, api_secret, org_id)
    if not auth and "Authorization" not in headers:
        logger.debug("[recon.censys] Censys credentials not configured. Skipping Censys certificate search.")
        return []

    clean_domain = domain.strip().lower().lstrip("*.")
    logger.info(f"[recon.censys] Querying Censys Certificate index for '{clean_domain}'")
    discovered_subs: Set[str] = set()

    url = f"{CENSYS_SEARCH_BASE}/certificates/search"
    params = {
        "q": f"names: {clean_domain}",
        "per_page": 100,
    }

    auth_mode = f"Bearer Token ({headers['Authorization'][:15]}...)" if "Authorization" in headers else f"Basic Auth (ID: {auth[0] if auth else 'none'})"

    try:
        with httpx.Client(timeout=timeout, auth=auth, headers=headers) as client:
            resp = client.get(url, params=params)

            if resp.status_code == 200:
                data = resp.json()
                hits = data.get("result", {}).get("hits", [])
                for hit in hits:
                    names = hit.get("names", [])
                    for name in names:
                        n_clean = name.strip().lower().lstrip("*.")
                        if n_clean and (n_clean == clean_domain or n_clean.endswith(f".{clean_domain}")):
                            if re.match(r"^[a-zA-Z0-9.-]+$", n_clean):
                                discovered_subs.add(n_clean)
                logger.info(f"[recon.censys] Discovered {len(discovered_subs)} subdomains from Censys certificate telemetry")
            else:
                logger.warning(
                    f"[recon.censys] Certificate search failed | Mode: {auth_mode} | URL: {resp.url} | Status: {resp.status_code} | Response: {resp.text[:400]}"
                )
    except Exception as e:
        logger.warning(f"[recon.censys] Certificate search network exception: {e}")

    return sorted(list(discovered_subs))


def query_censys_hosts(
    domain: str,
    api_id: Optional[str] = None,
    api_secret: Optional[str] = None,
    org_id: Optional[str] = None,
    timeout: int = 15,
) -> List[Dict[str, Any]]:
    """
    Queries Censys Hosts index to uncover live IPv4/IPv6 origin servers,
    open ports, and service banners presenting the target's TLS certificates.
    """
    auth, headers = _get_auth_and_headers(api_id, api_secret, org_id)
    if not auth and "Authorization" not in headers:
        logger.debug("[recon.censys] Censys credentials not configured. Skipping Censys host search.")
        return []

    clean_domain = domain.strip().lower().lstrip("*.")
    logger.info(f"[recon.censys] Querying Censys Hosts index for servers presenting '{clean_domain}'")
    hosts_result: List[Dict[str, Any]] = []

    url = f"{CENSYS_SEARCH_BASE}/hosts/search"
    params = {
        "q": f"services.tls.certificates.leaf_data.names: {clean_domain}",
        "per_page": 50,
    }
    auth_mode = f"Bearer Token ({headers['Authorization'][:15]}...)" if "Authorization" in headers else f"Basic Auth (ID: {auth[0] if auth else 'none'})"

    try:
        with httpx.Client(timeout=timeout, auth=auth, headers=headers) as client:
            resp = client.get(url, params=params)

            if resp.status_code == 200:
                data = resp.json()
                hits = data.get("result", {}).get("hits", [])
                for hit in hits:
                    ip = hit.get("ip")
                    if not ip:
                        continue
                    services = hit.get("services", [])
                    ports = []
                    for svc in services:
                        port_num = svc.get("port")
                        service_name = svc.get("service_name") or "unknown"
                        if port_num:
                            ports.append({"port": port_num, "service": service_name})

                    location = hit.get("location", {})
                    autonomous_system = hit.get("autonomous_system", {})

                    hosts_result.append({
                        "ip": ip,
                        "ports": ports,
                        "asn": autonomous_system.get("asn"),
                        "asn_name": autonomous_system.get("name"),
                        "country": location.get("country"),
                        "source": "censys_hosts",
                    })
                logger.info(f"[recon.censys] Discovered {len(hosts_result)} live internet hosts from Censys telemetry")
            else:
                logger.warning(
                    f"[recon.censys] Hosts query failed | Mode: {auth_mode} | URL: {resp.url} | Status: {resp.status_code} | Response: {resp.text[:400]}"
                )
    except Exception as e:
        logger.warning(f"[recon.censys] Host query network exception: {e}")

    return hosts_result
