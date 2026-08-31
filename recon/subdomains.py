import json
import logging
import re
import shutil
import subprocess
import ipaddress
from typing import List, Set, Dict, Any, Optional
import httpx
from core.config import settings
from core.scope import normalize_domain

logger = logging.getLogger(__name__)


def enumerate_subdomains(domain: str, timeout: int = 60) -> List[Dict[str, Any]]:
    """
    Step 2: Enumerate subdomains for target domain using free CT logs and CLI tools.
    Returns a list of structured findings: [{subdomain: str, sources: [str]}].
    """
    clean_domain = normalize_domain(domain)
    
    # 0. Fast-Path: If target is a direct IP address, return it immediately without CT/DNS scraping
    try:
        ipaddress.ip_address(clean_domain)
        logger.info(f"[recon.subdomains] Target '{clean_domain}' is a direct IP address. Returning seed IP host.")
        return [{"subdomain": clean_domain, "sources": ["seed_ip"]}]
    except ValueError:
        pass

    logger.info(f"[recon.subdomains] Starting subdomain discovery for '{clean_domain}'")
    
    discovered: Dict[str, Set[str]] = {}

    def _add(sub: str, source: str):
        sub_clean = sub.strip().lower().lstrip("*.")
        if sub_clean and (sub_clean == clean_domain or sub_clean.endswith(f".{clean_domain}")):
            # basic sanity check for valid hostname
            if re.match(r"^[a-zA-Z0-9.-]+$", sub_clean):
                if sub_clean not in discovered:
                    discovered[sub_clean] = set()
                discovered[sub_clean].add(source)

    # 1. crt.sh (Certificate Transparency)
    try:
        crt_subs = _query_crt_sh(clean_domain, timeout=min(timeout, 20))
        for s in crt_subs:
            _add(s, "crt.sh")
    except Exception as e:
        logger.warning(f"crt.sh enumeration failed for {clean_domain}: {e}")

    # 2. HackerTarget Hostsearch (Free Passive DNS)
    try:
        ht_subs = _query_hackertarget(clean_domain, timeout=min(timeout, 15))
        for s in ht_subs:
            _add(s, "hackertarget")
    except Exception as e:
        logger.debug(f"HackerTarget enumeration failed for {clean_domain}: {e}")

    # 3. Certspotter CT Log API (Free Tier)
    try:
        cs_subs = _query_certspotter(clean_domain, timeout=min(timeout, 15))
        for s in cs_subs:
            _add(s, "certspotter")
    except Exception as e:
        logger.debug(f"Certspotter enumeration failed for {clean_domain}: {e}")

    # 3. Subfinder Subprocess (if binary available)
    subfinder_bin = shutil.which(settings.SUBFINDER_BIN) or shutil.which("subfinder")
    if subfinder_bin:
        try:
            sf_subs = _run_subfinder_cli(subfinder_bin, clean_domain, timeout=timeout)
            for s in sf_subs:
                _add(s, "subfinder")
        except Exception as e:
            logger.warning(f"subfinder execution failed for {clean_domain}: {e}")
    else:
        logger.debug("subfinder binary not detected in PATH; using direct CT log sources")

    # 4. Google Custom Search (1 budgeted query if available)
    try:
        from core.google_search import query_google_search
        import urllib.parse
        g_results = query_google_search(f"site:*.{clean_domain} -www", num=10, timeout=10)
        for gr in g_results:
            link = gr.get("link", "")
            parsed_host = urllib.parse.urlparse(link).hostname
            if parsed_host:
                _add(parsed_host, "google_search")
    except Exception as e:
        logger.debug(f"Google search subdomain enumeration failed: {e}")

    # 5. Censys Certificate Search (if configured)
    try:
        from recon.censys_client import query_censys_subdomains
        censys_subs = query_censys_subdomains(clean_domain, timeout=min(timeout, 15))
        for s in censys_subs:
            _add(s, "censys")
    except Exception as e:
        logger.debug(f"Censys subdomain query failed: {e}")

    # Always ensure root domain is included
    _add(clean_domain, "root_domain")

    results = [
        {"subdomain": sub, "sources": sorted(list(sources))}
        for sub, sources in sorted(discovered.items())
    ]
    logger.info(f"[recon.subdomains] Discovered {len(results)} unique subdomains for '{clean_domain}'")
    return results


def _query_crt_sh(domain: str, timeout: int = 20) -> List[str]:
    """Queries crt.sh JSON endpoint directly via HTTP."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) R7/1.0"}
    subdomains = []
    
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                for raw_sub in name_value.split("\n"):
                    subdomains.append(raw_sub.strip())
    return subdomains


def _query_certspotter(domain: str, timeout: int = 15) -> List[str]:
    """Queries Certspotter free public API."""
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    headers = {"User-Agent": "R7/1.0"}
    subdomains = []
    
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            for item in data:
                dns_names = item.get("dns_names", [])
                subdomains.extend(dns_names)
    return subdomains


def _query_hackertarget(domain: str, timeout: int = 15) -> List[str]:
    """Queries HackerTarget free hostsearch API for passive DNS records."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) R7/1.0"}
    subdomains = []
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 200 and not resp.text.startswith("error"):
                for line in resp.text.splitlines():
                    if "," in line:
                        host = line.split(",")[0].strip()
                        if host:
                            subdomains.append(host)
    except Exception as e:
        logger.debug(f"HackerTarget request error: {e}")
    return subdomains


def _run_subfinder_cli(binary_path: str, domain: str, timeout: int = 60) -> List[str]:
    """Runs subfinder CLI tool in JSON output mode."""
    cmd = [binary_path, "-d", domain, "-silent", "-json"]
    subdomains = []
    
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
    )
    if proc.returncode == 0 and proc.stdout:
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host")
                if host:
                    subdomains.append(host)
            except json.JSONDecodeError:
                subdomains.append(line)
    return subdomains
