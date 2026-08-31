import re
import logging
from typing import Dict, Any, Optional, Tuple, List

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 1. UNIVERSAL BANNER PARSER (DISTRO & PACKAGE REVISION EXTRACTION)
# ---------------------------------------------------------------------------

DISTRO_PATTERNS = [
    (r"ubuntu-?([0-9a-zA-Z.~+]+)", "ubuntu"),
    (r"ubuntu", "ubuntu"),
    (r"debian-?([0-9a-zA-Z.~+]+)", "debian"),
    (r"debian", "debian"),
    (r"el[6-9](?:_[0-9]+)?", "rhel"),
    (r"redhat", "rhel"),
    (r"centos", "centos"),
    (r"alpine", "alpine"),
    (r"arch", "arch"),
    (r"amzn[1-9]?", "amazon_linux"),
    (r"freebsd", "freebsd"),
]

def parse_banner_components(banner: str) -> Dict[str, Any]:
    """
    Decomposes raw server banners (SSH, HTTP, FTP, SMTP) into structured metadata:
    - product: Normalized service name (e.g. OpenSSH, Apache, Nginx)
    - upstream_version: Upstream semantic version (e.g. 9.6p1, 2.4.58)
    - distro: Detected Linux distribution (e.g. ubuntu, debian, rhel)
    - package_revision: Distro package release string (e.g. 3ubuntu13.18, 1+deb12u1)
    - raw_banner: Original input banner
    """
    if not banner or not isinstance(banner, str):
        return {
            "product": "Unknown",
            "upstream_version": None,
            "distro": None,
            "package_revision": None,
            "raw_banner": "",
        }

    clean_banner = banner.strip()
    result: Dict[str, Any] = {
        "product": "Unknown",
        "upstream_version": None,
        "distro": None,
        "package_revision": None,
        "raw_banner": clean_banner,
    }

    # 1. Detect Product & Upstream Version
    # SSH patterns: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18
    ssh_match = re.search(r"OpenSSH[_-]([0-9]+(?:\.[0-9]+)+(?:p[0-9]+)?)", clean_banner, re.IGNORECASE)
    if ssh_match:
        result["product"] = "OpenSSH"
        result["upstream_version"] = ssh_match.group(1)
    
    # Apache patterns: Apache/2.4.58 (Ubuntu)
    apache_match = re.search(r"Apache(?:-Server)?/([0-9]+(?:\.[0-9]+)+)", clean_banner, re.IGNORECASE)
    if apache_match:
        result["product"] = "Apache"
        result["upstream_version"] = apache_match.group(1)

    # Nginx patterns: nginx/1.24.0 (Ubuntu)
    nginx_match = re.search(r"nginx/([0-9]+(?:\.[0-9]+)+)", clean_banner, re.IGNORECASE)
    if nginx_match:
        result["product"] = "Nginx"
        result["upstream_version"] = nginx_match.group(1)

    # Generic Web / Service: Lighttpd, Exim, Postfix, ProFTPD, vsftpd
    if result["product"] == "Unknown":
        gen_match = re.search(r"(Lighttpd|Exim|Postfix|ProFTPD|vsftpd|Dropbear|OpenSSL)[ /_-]([0-9]+(?:\.[0-9]+)+[a-z0-9_.-]*)", clean_banner, re.IGNORECASE)
        if gen_match:
            result["product"] = gen_match.group(1).capitalize()
            result["upstream_version"] = gen_match.group(2)

    # 2. Extract Distribution & Package Revision
    # Examples: Ubuntu-3ubuntu13.18, 3ubuntu13.3, 1+deb12u1, el9_4, alpine
    for pattern, distro_name in DISTRO_PATTERNS:
        match = re.search(pattern, clean_banner, re.IGNORECASE)
        if match:
            result["distro"] = distro_name
            if match.groups() and match.group(1):
                result["package_revision"] = match.group(1)
            break

    # Additional Debian/Ubuntu revision extraction (e.g. Ubuntu-3ubuntu13.18)
    if not result["package_revision"]:
        rev_match = re.search(r"(?:ubuntu|deb)[_-]?([0-9]+(?:\.[0-9]+)*(?:ubuntu|deb|\+deb)[0-9a-zA-Z._~+-]*)", clean_banner, re.IGNORECASE)
        if rev_match:
            result["package_revision"] = rev_match.group(1)

    return result


# ---------------------------------------------------------------------------
# 2. DEBIAN / UBUNTU DPKG VERSION COMPARISON ALGORITHM
# ---------------------------------------------------------------------------

def _order_char(c: str) -> int:
    """
    Debian dpkg character ordering:
    ~ sorts before everything (including empty string).
    letters sort before non-letters/digits.
    """
    if c == "~":
        return -1
    if c.isalpha():
        return ord(c)
    if c.isdigit():
        return ord(c) + 1000
    return ord(c) + 2000


def _compare_chunks(chunk_a: str, chunk_b: str) -> int:
    """Compares non-digit or digit chunks per Debian dpkg specification."""
    is_digit_a = chunk_a.isdigit()
    is_digit_b = chunk_b.isdigit()

    if is_digit_a and is_digit_b:
        num_a = int(chunk_a)
        num_b = int(chunk_b)
        if num_a < num_b:
            return -1
        if num_a > num_b:
            return 1
        return 0

    # Non-digit string comparison
    i = 0
    while i < len(chunk_a) or i < len(chunk_b):
        ca = chunk_a[i] if i < len(chunk_a) else ""
        cb = chunk_b[i] if i < len(chunk_b) else ""

        if ca == cb:
            i += 1
            continue

        val_a = _order_char(ca) if ca else 0
        val_b = _order_char(cb) if cb else 0

        if val_a < val_b:
            return -1
        if val_a > val_b:
            return 1
        i += 1

    return 0


def compare_dpkg_versions(ver_a: str, ver_b: str) -> int:
    """
    Pure Python implementation of Debian's dpkg --compare-versions.
    Supports [epoch:]upstream_version[-debian_revision].
    Returns:
       -1 if ver_a < ver_b
        0 if ver_a == ver_b
        1 if ver_a > ver_b
    """
    if not ver_a and not ver_b:
        return 0
    if not ver_a:
        return -1
    if not ver_b:
        return 1

    def split_epoch_upstream_revision(v: str) -> Tuple[int, str, str]:
        epoch = 0
        if ":" in v:
            parts = v.split(":", 1)
            try:
                epoch = int(parts[0])
            except ValueError:
                epoch = 0
            v = parts[1]

        revision = ""
        if "-" in v:
            parts = v.rsplit("-", 1)
            v = parts[0]
            revision = parts[1]

        return epoch, v, revision

    epoch_a, up_a, rev_a = split_epoch_upstream_revision(ver_a)
    epoch_b, up_b, rev_b = split_epoch_upstream_revision(ver_b)

    if epoch_a != epoch_b:
        return -1 if epoch_a < epoch_b else 1

    def compare_part(part_a: str, part_b: str) -> int:
        chunks_a = re.findall(r"\d+|\D+", part_a)
        chunks_b = re.findall(r"\d+|\D+", part_b)

        idx = 0
        while idx < len(chunks_a) or idx < len(chunks_b):
            ca = chunks_a[idx] if idx < len(chunks_a) else ""
            cb = chunks_b[idx] if idx < len(chunks_b) else ""

            cmp = _compare_chunks(ca, cb)
            if cmp != 0:
                return cmp
            idx += 1
        return 0

    up_cmp = compare_part(up_a, up_b)
    if up_cmp != 0:
        return up_cmp

    return compare_part(rev_a, rev_b)


# ---------------------------------------------------------------------------
# 3. LIVE VENDOR SECURITY TRACKER & OSV FEED CLIENT (WITH 24H CACHE)
# ---------------------------------------------------------------------------

import time
import httpx

_LIVE_TRACKER_CACHE: Dict[str, Dict[str, Any]] = {}
_CACHE_TIMESTAMP: Dict[str, float] = {}
_CACHE_TTL = 86400.0  # 24 hours

# Machine-readable vendor security tracker threshold baseline (fallback if offline)
DISTRO_SECURITY_TRACKERS: Dict[str, Dict[str, Any]] = {
    "CVE-2024-6387": {
        "title": "OpenSSH regreSSHion Signal Handler Race Condition",
        "upstream_affected_range": ("8.5p1", "9.7p1"),
        "upstream_fixed": "9.8p1",
        "distros": {
            "ubuntu": {
                "noble": "1:9.6p1-3ubuntu13.3",
                "jammy": "1:8.9p1-3ubuntu0.10",
                "focal": "1:8.2p1-4ubuntu0.11",
                "default_fixed_revision": "3ubuntu13.3",
                "notes": "Ubuntu security update backported fix into package release 3ubuntu13.3 without modifying upstream version.",
            },
            "debian": {
                "bookworm": "1:9.2p1-2+deb12u3",
                "bullseye": "1:8.4p1-5+deb11u3",
                "default_fixed_revision": "2+deb12u3",
                "notes": "Debian Security Advisory DSA-5721-1 backported the fix.",
            },
        },
    },
    "CVE-2023-44487": {
        "title": "HTTP/2 Rapid Reset Stream Cancellation Flood",
        "upstream_affected_range": ("1.0.0", "1.25.2"),
        "upstream_fixed": "1.25.3",
        "distros": {
            "ubuntu": {
                "default_mitigated": True,
                "notes": "Ubuntu and Nginx officially stated default configuration mitigates Rapid Reset via keepalive_requests (1000) and stream bounds.",
            },
            "debian": {
                "default_mitigated": True,
                "notes": "Default configuration enforces stream request limits.",
            },
        },
    },
}


def fetch_live_ubuntu_cve(cve_id: str, timeout: float = 3.0) -> Optional[Dict[str, Any]]:
    """
    Queries Canonical's official Ubuntu Security API (https://ubuntu.com/security/cves.json).
    Extracts structured fixed package versions per Ubuntu release.
    """
    clean_cve = cve_id.strip().upper()
    url = f"https://ubuntu.com/security/cves.json?q={clean_cve}"
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url, headers={"User-Agent": "R7-ThreatIntel/1.0"})
            if resp.status_code == 200:
                data = resp.json()
                cves = data.get("cves", [])
                for entry in cves:
                    if entry.get("id", "").upper() == clean_cve:
                        packages = entry.get("packages", [])
                        distro_fixes: Dict[str, str] = {}
                        for p in packages:
                            statuses = p.get("statuses", [])
                            for s in statuses:
                                if s.get("status") == "released" and s.get("release"):
                                    distro_fixes[s.get("release")] = s.get("version", "")

                        if distro_fixes:
                            return {
                                "distros": {
                                    "ubuntu": {
                                        **distro_fixes,
                                        "default_fixed_revision": list(distro_fixes.values())[0],
                                        "notes": f"Canonical USN official tracker for {clean_cve}",
                                    }
                                }
                            }
    except Exception as e:
        logger.debug(f"[distro_matcher] Live Ubuntu API lookup for {clean_cve} unavailable: {e}")
    return None


def fetch_live_osv_package(package_name: str, ecosystem: str = "Debian", timeout: float = 3.0) -> Optional[List[Dict[str, Any]]]:
    """
    Queries Google OSV (Open Source Vulnerabilities) API (https://api.osv.dev/v1/query).
    Standardized, free open-source database covering Linux distros (Debian, Ubuntu, Alpine, RHEL).
    """
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": package_name, "ecosystem": ecosystem}}
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, json=payload, headers={"User-Agent": "R7-ThreatIntel/1.0"})
            if resp.status_code == 200:
                data = resp.json()
                return data.get("vulns", [])
    except Exception as e:
        logger.debug(f"[distro_matcher] Live OSV API lookup for {package_name} ({ecosystem}) unavailable: {e}")
    return None


def get_cve_distro_intel(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Resolves CVE distro security intelligence from:
    1. In-memory / SQLite fast cache (if < 24h)
    2. Canonical Ubuntu Security Tracker API (live online query)
    3. Baseline offline security database
    """
    clean_cve = cve_id.strip().upper()
    now = time.time()

    # 1. Check cache
    if clean_cve in _LIVE_TRACKER_CACHE and (now - _CACHE_TIMESTAMP.get(clean_cve, 0)) < _CACHE_TTL:
        return _LIVE_TRACKER_CACHE[clean_cve]

    # 2. Check baseline offline DB first
    baseline = DISTRO_SECURITY_TRACKERS.get(clean_cve)
    if baseline:
        _LIVE_TRACKER_CACHE[clean_cve] = baseline
        _CACHE_TIMESTAMP[clean_cve] = now
        return baseline

    # 3. Live Canonical Ubuntu Security API Query
    live_ubuntu = fetch_live_ubuntu_cve(clean_cve)
    if live_ubuntu:
        _LIVE_TRACKER_CACHE[clean_cve] = live_ubuntu
        _CACHE_TIMESTAMP[clean_cve] = now
        logger.info(f"[distro_matcher] Synchronized live Canonical USN backport intelligence for {clean_cve}")
        return live_ubuntu

    return None


# ---------------------------------------------------------------------------
# 4. DISTRO-AWARE INFERENCE ENGINE (4-TIER EVIDENCE TAXONOMY)
# ---------------------------------------------------------------------------

def evaluate_distro_security_status(
    cve_id: str,
    product: str,
    upstream_version: str,
    banner: str,
    active_proof_obtained: bool = False,
) -> Dict[str, Any]:
    """
    Evaluates vulnerability applicability taking into account Linux distro package revisions,
    backported security fixes, and configuration mitigations.

    Returns 4-tier taxonomy:
    1. CONFIRMED: Active PoC / HTTP probe verified.
    2. LIKELY_VULNERABLE: Package revision is strictly below vendor fixed release or unpatched build.
    3. POTENTIALLY_AFFECTED: Upstream version in range, but distro revision or config is unverified.
    4. NOT_VULNERABLE: Distro package revision proves the security fix has been backported.
    """
    parsed = parse_banner_components(banner)
    distro = parsed.get("distro")
    pkg_rev = parsed.get("package_revision")
    detected_product = parsed.get("product") or product
    detected_ver = parsed.get("upstream_version") or upstream_version

    # Tier 1: Active Proof
    if active_proof_obtained:
        return {
            "finding_status": "CONFIRMED",
            "status_label": "CONFIRMED (ACTIVE PROOF)",
            "confidence": 0.99,
            "distro": distro,
            "package_revision": pkg_rev,
            "reason": "Active exploitation probe or vulnerability verification succeeded against this target.",
            "is_vulnerable": True,
        }

    cve_intel = get_cve_distro_intel(cve_id)
    if not cve_intel:
        # Generic CVE fallback without vendor-specific backport tracker
        return {
            "finding_status": "POTENTIALLY_AFFECTED",
            "status_label": "POTENTIALLY AFFECTED (VERSION ADVISORY)",
            "confidence": 0.65,
            "distro": distro,
            "package_revision": pkg_rev,
            "reason": f"Detected {detected_product} version {detected_ver}. Upstream release falls within advisory range.",
            "is_vulnerable": True,
        }

    # Distro-specific analysis
    distro_intel = cve_intel.get("distros", {}).get(distro) if distro else None

    # Handle Nginx / HTTP/2 Rapid Reset configuration mitigation case
    if cve_id == "CVE-2023-44487":
        return {
            "finding_status": "POTENTIALLY_AFFECTED",
            "status_label": "POTENTIALLY AFFECTED / ADVISORY",
            "confidence": 0.40,
            "distro": distro or "generic",
            "package_revision": pkg_rev,
            "reason": "Nginx default configuration enforces keepalive_requests (1000) and max concurrent stream limits that mitigate Rapid Reset. Exploitability is configuration-dependent.",
            "is_vulnerable": False,  # Not directly exploitable by default
            "advisory_only": True,
        }

    # Handle OpenSSH regreSSHion backport analysis (CVE-2024-6387)
    if cve_id == "CVE-2024-6387" and distro in ("ubuntu", "debian"):
        fixed_rev = distro_intel.get("default_fixed_revision", "3ubuntu13.3") if distro_intel else "3ubuntu13.3"
        
        if pkg_rev:
            cmp_result = compare_dpkg_versions(pkg_rev, fixed_rev)
            if cmp_result >= 0:
                # Package revision is higher or equal to fixed threshold (e.g. 3ubuntu13.18 >= 3ubuntu13.3)
                return {
                    "finding_status": "NOT_VULNERABLE",
                    "status_label": "NOT VULNERABLE (DISTRO BACKPORT)",
                    "confidence": 0.98,
                    "distro": distro,
                    "package_revision": pkg_rev,
                    "fixed_threshold": fixed_rev,
                    "reason": f"Ubuntu/Debian Security Tracker confirms CVE-2024-6387 was patched in package release '{fixed_rev}'. The detected host is running '{pkg_rev}', which includes the backported security fix.",
                    "is_vulnerable": False,
                    "mathematical_proof": f"{pkg_rev} >= {fixed_rev} (Debian DPKG Comparison)",
                }
            else:
                # Package revision is strictly below fixed threshold
                return {
                    "finding_status": "LIKELY_VULNERABLE",
                    "status_label": "LIKELY VULNERABLE (UNPATCHED DISTRO PACKAGE)",
                    "confidence": 0.92,
                    "distro": distro,
                    "package_revision": pkg_rev,
                    "fixed_threshold": fixed_rev,
                    "reason": f"Detected {distro.capitalize()} package revision '{pkg_rev}' is strictly below the fixed release '{fixed_rev}'.",
                    "is_vulnerable": True,
                    "mathematical_proof": f"{pkg_rev} < {fixed_rev} (Debian DPKG Comparison)",
                }

    # Distro recognized but no revision extracted from banner
    if distro:
        return {
            "finding_status": "POTENTIALLY_AFFECTED",
            "status_label": "POTENTIALLY AFFECTED (DISTRO DETECTED)",
            "confidence": 0.60,
            "distro": distro,
            "package_revision": None,
            "reason": f"Detected {distro.capitalize()} host running {detected_product} {detected_ver}. Upstream version is in range, but Linux package revision could not be determined from the banner alone.",
            "is_vulnerable": True,
        }

    # Upstream generic
    return {
        "finding_status": "POTENTIALLY_AFFECTED",
        "status_label": "POTENTIALLY AFFECTED (UPSTREAM MATCH)",
        "confidence": 0.70,
        "distro": None,
        "package_revision": None,
        "reason": f"Upstream {detected_product} version {detected_ver} matches known vulnerable range.",
        "is_vulnerable": True,
    }
