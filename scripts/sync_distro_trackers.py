#!/usr/bin/env python3
"""
Recon7 Threat Intel - Distro Security Tracker & Vendor CVE Synchronizer.
Fetches and caches live security notices and fixed package releases from:
1. Canonical Ubuntu Security Tracker API (https://ubuntu.com/security/cves.json)
2. Debian Security Bug Tracker JSON
3. Google OSV (Open Source Vulnerabilities) API
4. CISA KEV Catalog Feed

Usage:
  python scripts/sync_distro_trackers.py
"""

import os
import sys
import logging
from pathlib import Path
from typing import List

# Ensure Recon7 project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from vuln.cve_lookup import get_cisa_kev_set
from vuln.distro_matcher import fetch_live_ubuntu_cve, get_cve_distro_intel, fetch_live_osv_package

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sync_distro_trackers")

PRIORITY_CVES_TO_SYNC: List[str] = [
    "CVE-2024-6387",  # OpenSSH regreSSHion
    "CVE-2023-44487", # HTTP/2 Rapid Reset
    "CVE-2021-41773", # Apache 2.4.49 Path Traversal
    "CVE-2021-42013", # Apache 2.4.50 Path Traversal
    "CVE-2022-22720", # Apache Request Smuggling
    "CVE-2021-23017", # Nginx DNS Resolver
    "CVE-2023-48795", # OpenSSH Terrapin
    "CVE-2024-4577",  # PHP CGI Argument Injection
    "CVE-2022-22965", # Spring4Shell RCE
]

def main():
    logger.info("Starting Threat Intelligence & Vendor Security Tracker Sync...")

    # 1. Sync Official CISA KEV Catalog
    logger.info("[1/3] Synchronizing CISA Known Exploited Vulnerabilities catalog...")
    kev_set = get_cisa_kev_set()
    logger.info(f"==> Cached {len(kev_set)} verified active exploitation CVEs from CISA KEV.")

    # 2. Sync Canonical Ubuntu Security API & Distro Backports
    logger.info("[2/3] Querying Canonical Ubuntu & Debian Security Trackers...")
    synced_cves = 0
    for cve in PRIORITY_CVES_TO_SYNC:
        intel = get_cve_distro_intel(cve)
        if intel:
            synced_cves += 1
            logger.info(f"  ✓ Synced {cve} distro backport tracking")

    logger.info(f"==> Successfully synced {synced_cves}/{len(PRIORITY_CVES_TO_SYNC)} priority CVE advisories.")

    # 3. Test OSV.dev Integration
    logger.info("[3/3] Testing Google OSV Universal Vulnerability Feed...")
    osv_res = fetch_live_osv_package("openssh-server", ecosystem="Debian")
    if osv_res:
        logger.info(f"==> OSV.dev connected successfully: {len(osv_res)} package advisories indexed.")
    else:
        logger.info("==> OSV.dev returned standard response.")

    logger.info("Threat Intelligence & Distro Tracker Synchronization Complete!")

if __name__ == "__main__":
    main()
